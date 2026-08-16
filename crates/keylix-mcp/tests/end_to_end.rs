//! Cross-stack end-to-end smoke coverage for the MCP `DPoP` path.
//!
//! This test intentionally crosses the client adapter, rmcp HTTP decoration
//! boundary, server-side `DPoP` verification, OAuth sender binding, and replay
//! protection while remaining deterministic and self-contained.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use futures::{executor::block_on, stream::BoxStream};
use http::{HeaderName, HeaderValue};
use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopPortError, DpopSigner, EffectiveRequestTarget,
    InMemoryClientNonceStore, InMemoryReplayStore, RandomProofIdGenerator, VerificationPolicy,
};
use keylix_mcp::{
    DpopStreamableHttpClient, McpDpopClient, McpDpopServer, McpDpopServerError, McpHttpRequest,
};
use keylix_oauth::{DpopRequiredClient, HostValidatedToken};
use rmcp::{
    model::ClientJsonRpcMessage,
    transport::streamable_http_client::{
        SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
    },
};
use sse_stream::Sse;

const ACCESS_TOKEN: &str = "e2e-bound-access-token";

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

#[derive(Debug)]
struct FakeError;

impl fmt::Display for FakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fake MCP transport error")
    }
}

impl std::error::Error for FakeError {}

#[derive(Clone)]
struct CapturedAttempt {
    method: String,
    uri: String,
    authorization: String,
    proof: String,
}

#[derive(Clone)]
struct VerifyingClient {
    clock: FixedClock,
    validated_token: Arc<HostValidatedToken>,
    replay: Arc<InMemoryReplayStore<FixedClock>>,
    expected_thumbprint: String,
    attempts: Arc<Mutex<Vec<CapturedAttempt>>>,
}

impl VerifyingClient {
    fn new(
        clock: FixedClock,
        validated_token: Arc<HostValidatedToken>,
        replay: Arc<InMemoryReplayStore<FixedClock>>,
        expected_thumbprint: String,
    ) -> Self {
        Self {
            clock,
            validated_token,
            replay,
            expected_thumbprint,
            attempts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn attempts(&self) -> Result<Vec<CapturedAttempt>, FakeError> {
        self.attempts
            .lock()
            .map(|attempts| attempts.clone())
            .map_err(|_| FakeError)
    }

    fn verify_and_capture(
        &self,
        method: &str,
        uri: &str,
        auth_header: Option<String>,
        custom_headers: &HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<FakeError>> {
        let authorization = auth_header.ok_or(StreamableHttpError::Client(FakeError))?;
        let token = authorization
            .strip_prefix("DPoP ")
            .ok_or(StreamableHttpError::Client(FakeError))?;
        let proof = custom_headers
            .get(&HeaderName::from_static("dpop"))
            .ok_or(StreamableHttpError::Client(FakeError))?
            .to_str()
            .map_err(|_| StreamableHttpError::Client(FakeError))?
            .to_owned();
        let target = EffectiveRequestTarget::parse(uri)
            .map_err(|_| StreamableHttpError::Client(FakeError))?;
        let proof_headers = [proof.as_str()];
        let request = McpHttpRequest::new(method, &target, token.as_bytes(), &proof_headers);
        let server = McpDpopServer::new(
            &self.clock,
            VerificationPolicy::default(),
            self.replay.as_ref(),
        );
        let binding = server
            .verify(&request, self.validated_token.as_ref())
            .map_err(|_| StreamableHttpError::Client(FakeError))?;
        if binding.key_thumbprint().to_base64url() != self.expected_thumbprint {
            return Err(StreamableHttpError::Client(FakeError));
        }

        self.attempts
            .lock()
            .map_err(|_| StreamableHttpError::Client(FakeError))?
            .push(CapturedAttempt {
                method: method.to_owned(),
                uri: uri.to_owned(),
                authorization,
                proof,
            });
        Ok(())
    }
}

impl StreamableHttpClient for VerifyingClient {
    type Error = FakeError;

    async fn post_message(
        &self,
        uri: Arc<str>,
        _message: ClientJsonRpcMessage,
        _session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        self.verify_and_capture("POST", &uri, auth_header, &custom_headers)?;
        Ok(StreamableHttpPostResponse::Accepted)
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        _session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        self.verify_and_capture("DELETE", &uri, auth_header, &custom_headers)
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        _session_id: Option<Arc<str>>,
        _last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        self.verify_and_capture("GET", &uri, auth_header, &custom_headers)?;
        Ok(Box::pin(futures::stream::empty()))
    }
}

#[test]
fn kx_mcp_e2e_client_transport_server_sender_binding_round_trip() -> Result<(), FakeError> {
    let signer = Arc::new(AwsLcP256Signer::generate().map_err(|_| FakeError)?);
    let clock = Arc::new(FixedClock(1_700_000_000));
    let proof_ids = Arc::new(RandomProofIdGenerator);
    let nonces = Arc::new(InMemoryClientNonceStore::new(8).map_err(|_| FakeError)?);

    let oauth = DpopRequiredClient::new(
        signer.as_ref(),
        clock.as_ref(),
        proof_ids.as_ref(),
        nonces.as_ref(),
    );
    let tokens = oauth
        .accept_token_response("DPoP", ACCESS_TOKEN.to_owned(), None)
        .map_err(|_| FakeError)?;
    let (access_token, _) = tokens.into_parts();

    let thumbprint = signer.public_jwk().thumbprint().to_base64url();
    let validated_token = Arc::new(
        HostValidatedToken::from_host_validated_jwt(ACCESS_TOKEN.as_bytes(), Some(&thumbprint))
            .map_err(|_| FakeError)?,
    );
    let replay = Arc::new(InMemoryReplayStore::new(*clock, 8).map_err(|_| FakeError)?);
    let dpop = McpDpopClient::new(
        Arc::clone(&signer),
        Arc::clone(&clock),
        proof_ids,
        nonces,
        "https://issuer.example",
        "https://mcp.example",
    )
    .map_err(|_| FakeError)?;
    let inner = VerifyingClient::new(
        *clock,
        Arc::clone(&validated_token),
        Arc::clone(&replay),
        thumbprint,
    );
    let capture = inner.clone();
    let client = DpopStreamableHttpClient::new(inner, dpop, Arc::new(access_token));

    let uri: Arc<str> = Arc::from("https://mcp.example/rpc");
    let session: Arc<str> = Arc::from("e2e-session");
    block_on(client.delete_session(uri, session, None, HashMap::new())).map_err(|_| FakeError)?;

    let attempts = capture.attempts()?;
    assert_eq!(attempts.len(), 1);
    let attempt = attempts.first().ok_or(FakeError)?;
    assert_eq!(attempt.method, "DELETE");
    assert_eq!(attempt.uri, "https://mcp.example/rpc");
    assert_eq!(attempt.authorization, "DPoP e2e-bound-access-token");

    let target = EffectiveRequestTarget::parse(&attempt.uri).map_err(|_| FakeError)?;
    let token = attempt
        .authorization
        .strip_prefix("DPoP ")
        .ok_or(FakeError)?;
    let proof_headers = [attempt.proof.as_str()];
    let replayed = McpHttpRequest::new("DELETE", &target, token.as_bytes(), &proof_headers);
    let server = McpDpopServer::new(
        clock.as_ref(),
        VerificationPolicy::default(),
        replay.as_ref(),
    );

    assert!(matches!(
        server.verify(&replayed, validated_token.as_ref()),
        Err(McpDpopServerError::Proof(DpopError::ReplayDetected))
    ));
    Ok(())
}
