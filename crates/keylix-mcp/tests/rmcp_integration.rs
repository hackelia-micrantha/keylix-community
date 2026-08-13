//! `rmcp` transport integration coverage for the experimental MCP `DPoP` profile.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use futures::{executor::block_on, stream::BoxStream};
use http::{HeaderName, HeaderValue};
use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopNonce, DpopPortError, DpopRequest, DpopVerifier,
    EffectiveRequestTarget, InMemoryClientNonceStore, InMemoryReplayStore, RandomProofIdGenerator,
    UnverifiedDpopProof, VerificationPolicy,
};
use keylix_mcp::{
    DpopStreamableHttpClient, MCP_SPEC_VERSION, McpDpopClient, ProfileStatus, RMCP_ADAPTER_VERSION,
    SEP_1932_DRAFT_PROFILE, profile_metadata, require_profile,
};
use keylix_oauth::{DpopRequiredClient, NonceRetryBudget};
use rmcp::{
    model::ClientJsonRpcMessage,
    transport::streamable_http_client::{
        SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
    },
};
use sse_stream::Sse;

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

type CapturedAttempt = (String, String);

#[derive(Clone, Default)]
struct CapturingClient {
    attempts: Arc<Mutex<Vec<CapturedAttempt>>>,
}

impl CapturingClient {
    fn attempts(&self) -> Result<Vec<CapturedAttempt>, FakeError> {
        self.attempts
            .lock()
            .map(|attempts| attempts.clone())
            .map_err(|_| FakeError)
    }

    fn capture(
        &self,
        auth_header: Option<String>,
        custom_headers: &HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<FakeError>> {
        let authorization = auth_header.ok_or(StreamableHttpError::Client(FakeError))?;
        let proof = custom_headers
            .get(&HeaderName::from_static("dpop"))
            .ok_or(StreamableHttpError::Client(FakeError))?
            .to_str()
            .map_err(|_| StreamableHttpError::Client(FakeError))?
            .to_owned();
        self.attempts
            .lock()
            .map_err(|_| StreamableHttpError::Client(FakeError))?
            .push((authorization, proof));
        Ok(())
    }
}

impl StreamableHttpClient for CapturingClient {
    type Error = FakeError;

    async fn post_message(
        &self,
        _uri: Arc<str>,
        _message: ClientJsonRpcMessage,
        _session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        self.capture(auth_header, &custom_headers)?;
        Ok(StreamableHttpPostResponse::Accepted)
    }

    async fn delete_session(
        &self,
        _uri: Arc<str>,
        _session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        self.capture(auth_header, &custom_headers)
    }

    async fn get_stream(
        &self,
        _uri: Arc<str>,
        _session_id: Option<Arc<str>>,
        _last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        self.capture(auth_header, &custom_headers)?;
        let stream: BoxStream<'static, Result<Sse, SseError>> = Box::pin(futures::stream::empty());
        Ok(stream)
    }
}

#[test]
fn kx_mcp_005_profile_is_explicitly_draft_and_no_unknown_profile_downgrades() {
    let metadata = profile_metadata();
    assert_eq!(metadata.profile, SEP_1932_DRAFT_PROFILE);
    assert_eq!(metadata.status, ProfileStatus::Draft);
    assert_eq!(metadata.rmcp_version, RMCP_ADAPTER_VERSION);
    assert_eq!(metadata.mcp_spec_version, MCP_SPEC_VERSION);
    assert!(require_profile(SEP_1932_DRAFT_PROFILE).is_ok());
    assert!(require_profile("sep-1932-stable").is_err());
}

#[test]
fn kx_mcp_001_004_rmcp_http_attempts_use_dpop_and_fresh_proofs() -> Result<(), FakeError> {
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
        .accept_token_response("DPoP", "access-token-mcp".to_owned(), None)
        .map_err(|_| FakeError)?;
    let (access_token, _) = tokens.into_parts();

    let dpop = McpDpopClient::new(
        Arc::clone(&signer),
        Arc::clone(&clock),
        Arc::clone(&proof_ids),
        Arc::clone(&nonces),
        "https://issuer.example",
        "https://mcp.example",
    )
    .map_err(|_| FakeError)?;
    let inner = CapturingClient::default();
    let capture = inner.clone();
    let client = DpopStreamableHttpClient::new(inner, dpop, Arc::new(access_token));

    let uri: Arc<str> = Arc::from("https://mcp.example/rpc?transport=streamable");
    let session: Arc<str> = Arc::from("session-1");
    let first = block_on(client.delete_session(
        Arc::clone(&uri),
        Arc::clone(&session),
        None,
        HashMap::new(),
    ));
    assert!(
        first.is_ok(),
        "KX-MCP-001: first strict HTTP attempt failed"
    );
    let second = block_on(client.delete_session(uri, session, None, HashMap::new()));
    assert!(
        second.is_ok(),
        "KX-MCP-001: second strict HTTP attempt failed"
    );

    let attempts = capture.attempts()?;
    assert_eq!(attempts.len(), 2);
    let first_attempt = attempts.first().ok_or(FakeError)?;
    let second_attempt = attempts.get(1).ok_or(FakeError)?;
    assert_eq!(first_attempt.0, "DPoP access-token-mcp");
    assert_eq!(second_attempt.0, "DPoP access-token-mcp");
    assert_ne!(
        first_attempt.1, second_attempt.1,
        "KX-MCP-001: HTTP retry reused a DPoP proof"
    );

    let target = EffectiveRequestTarget::parse("https://mcp.example/rpc").map_err(|_| FakeError)?;
    let request = DpopRequest::new("DELETE", &target)
        .map_err(|_| FakeError)?
        .with_access_token(b"access-token-mcp");
    for proof in [&first_attempt.1, &second_attempt.1] {
        let parsed = UnverifiedDpopProof::parse(proof).map_err(|_| FakeError)?;
        let replay = InMemoryReplayStore::new(*clock, 4).map_err(|_| FakeError)?;
        DpopVerifier::new(clock.as_ref(), VerificationPolicy::default())
            .verify(&parsed, &request, &replay)
            .map_err(|_| FakeError)?;
    }
    Ok(())
}

#[test]
fn kx_mcp_002_003_token_proof_and_nonce_scopes_remain_separate() -> Result<(), FakeError> {
    let signer = Arc::new(AwsLcP256Signer::generate().map_err(|_| FakeError)?);
    let clock = Arc::new(FixedClock(1_700_000_000));
    let proof_ids = Arc::new(RandomProofIdGenerator);
    let nonces = Arc::new(InMemoryClientNonceStore::new(8).map_err(|_| FakeError)?);
    let client = McpDpopClient::new(
        signer,
        clock,
        proof_ids,
        nonces,
        "https://issuer.example",
        "https://mcp.example",
    )
    .map_err(|_| FakeError)?;

    let endpoint =
        EffectiveRequestTarget::parse("https://issuer.example/token").map_err(|_| FakeError)?;
    let first = client
        .token_endpoint_attempt(&endpoint)
        .map_err(|_| FakeError)?;
    assert!(UnverifiedDpopProof::parse(first.dpop_header_value()).is_ok());

    let as_nonce = DpopNonce::new("as-nonce").map_err(|_| FakeError)?;
    let rs_nonce = DpopNonce::new("rs-nonce").map_err(|_| FakeError)?;
    let mut as_budget = NonceRetryBudget::single_retry();
    let mut rs_budget = NonceRetryBudget::single_retry();
    client
        .record_authorization_server_nonce_challenge(&as_nonce, &mut as_budget)
        .map_err(|_| FakeError)?;
    client
        .record_resource_server_nonce_challenge(&rs_nonce, &mut rs_budget)
        .map_err(|_| FakeError)?;
    assert!(!as_budget.can_retry());
    assert!(!rs_budget.can_retry());

    let retry = client
        .token_endpoint_attempt(&endpoint)
        .map_err(|_| FakeError)?;
    assert_ne!(first.dpop_header_value(), retry.dpop_header_value());
    let parsed = UnverifiedDpopProof::parse(retry.dpop_header_value()).map_err(|_| FakeError)?;
    let expected = DpopRequest::new("POST", &endpoint)
        .map_err(|_| FakeError)?
        .with_nonce(&as_nonce);
    let replay = InMemoryReplayStore::new(FixedClock(1_700_000_000), 4).map_err(|_| FakeError)?;
    DpopVerifier::new(&FixedClock(1_700_000_000), VerificationPolicy::default())
        .verify(&parsed, &expected, &replay)
        .map_err(|_| FakeError)?;
    Ok(())
}

#[test]
fn kx_mcp_001_conflicting_authorization_or_proof_headers_never_dispatch() -> Result<(), FakeError> {
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
        .accept_token_response("DPoP", "access-token-mcp".to_owned(), None)
        .map_err(|_| FakeError)?;
    let (access_token, _) = tokens.into_parts();
    let dpop = McpDpopClient::new(
        signer,
        clock,
        proof_ids,
        nonces,
        "https://issuer.example",
        "https://mcp.example",
    )
    .map_err(|_| FakeError)?;
    let inner = CapturingClient::default();
    let capture = inner.clone();
    let client = DpopStreamableHttpClient::new(inner, dpop, Arc::new(access_token));
    let uri: Arc<str> = Arc::from("https://mcp.example/rpc");
    let session: Arc<str> = Arc::from("session-conflict");

    let bearer = block_on(client.delete_session(
        Arc::clone(&uri),
        Arc::clone(&session),
        Some("Bearer attacker-token".to_owned()),
        HashMap::new(),
    ));
    assert!(
        bearer.is_err(),
        "KX-MCP-001: pre-existing Bearer authorization was accepted"
    );

    let mut attacker_headers = HashMap::new();
    attacker_headers.insert(
        HeaderName::from_static("dpop"),
        HeaderValue::from_static("attacker-proof"),
    );
    let duplicate_proof = block_on(client.delete_session(uri, session, None, attacker_headers));
    assert!(
        duplicate_proof.is_err(),
        "KX-MCP-001: pre-existing DPoP proof header was accepted"
    );
    assert!(
        capture.attempts()?.is_empty(),
        "KX-MCP-001: conflicting authorization reached the inner transport"
    );
    Ok(())
}

#[test]
fn kx_mcp_001_003_resource_nonce_replay_method_and_target_binding_are_enforced()
-> Result<(), FakeError> {
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
        .accept_token_response("DPoP", "access-token-mcp".to_owned(), None)
        .map_err(|_| FakeError)?;
    let (access_token, _) = tokens.into_parts();
    let dpop = McpDpopClient::new(
        Arc::clone(&signer),
        Arc::clone(&clock),
        Arc::clone(&proof_ids),
        Arc::clone(&nonces),
        "https://issuer.example",
        "https://mcp.example",
    )
    .map_err(|_| FakeError)?;

    let as_nonce = DpopNonce::new("as-only-nonce").map_err(|_| FakeError)?;
    let rs_nonce = DpopNonce::new("rs-only-nonce").map_err(|_| FakeError)?;
    let mut as_budget = NonceRetryBudget::single_retry();
    let mut rs_budget = NonceRetryBudget::single_retry();
    dpop.record_authorization_server_nonce_challenge(&as_nonce, &mut as_budget)
        .map_err(|_| FakeError)?;
    dpop.record_resource_server_nonce_challenge(&rs_nonce, &mut rs_budget)
        .map_err(|_| FakeError)?;

    let inner = CapturingClient::default();
    let capture = inner.clone();
    let client = DpopStreamableHttpClient::new(inner, dpop, Arc::new(access_token));
    let uri: Arc<str> = Arc::from("https://mcp.example/rpc");
    let session: Arc<str> = Arc::from("session-binding");
    block_on(client.delete_session(uri, session, None, HashMap::new())).map_err(|_| FakeError)?;

    let attempts = capture.attempts()?;
    let attempt = attempts.first().ok_or(FakeError)?;
    let parsed = UnverifiedDpopProof::parse(&attempt.1).map_err(|_| FakeError)?;
    let target = EffectiveRequestTarget::parse("https://mcp.example/rpc").map_err(|_| FakeError)?;
    let expected = DpopRequest::new("DELETE", &target)
        .map_err(|_| FakeError)?
        .with_access_token(b"access-token-mcp")
        .with_nonce(&rs_nonce);
    let replay = InMemoryReplayStore::new(*clock, 8).map_err(|_| FakeError)?;
    let verifier = DpopVerifier::new(clock.as_ref(), VerificationPolicy::default());
    verifier
        .verify(&parsed, &expected, &replay)
        .map_err(|_| FakeError)?;
    assert!(
        verifier.verify(&parsed, &expected, &replay).is_err(),
        "KX-MCP-001: replayed MCP proof was accepted"
    );

    let wrong_nonce = DpopRequest::new("DELETE", &target)
        .map_err(|_| FakeError)?
        .with_access_token(b"access-token-mcp")
        .with_nonce(&as_nonce);
    let fresh_replay = InMemoryReplayStore::new(*clock, 8).map_err(|_| FakeError)?;
    assert!(
        verifier
            .verify(&parsed, &wrong_nonce, &fresh_replay)
            .is_err(),
        "KX-MCP-003: AS nonce was accepted in the MCP resource-server scope"
    );

    let wrong_method = DpopRequest::new("GET", &target)
        .map_err(|_| FakeError)?
        .with_access_token(b"access-token-mcp")
        .with_nonce(&rs_nonce);
    let fresh_replay = InMemoryReplayStore::new(*clock, 8).map_err(|_| FakeError)?;
    assert!(
        verifier
            .verify(&parsed, &wrong_method, &fresh_replay)
            .is_err(),
        "KX-MCP-001: proof moved to a different HTTP method"
    );

    let other_target =
        EffectiveRequestTarget::parse("https://mcp.example/other").map_err(|_| FakeError)?;
    let wrong_target = DpopRequest::new("DELETE", &other_target)
        .map_err(|_| FakeError)?
        .with_access_token(b"access-token-mcp")
        .with_nonce(&rs_nonce);
    let fresh_replay = InMemoryReplayStore::new(*clock, 8).map_err(|_| FakeError)?;
    assert!(
        verifier
            .verify(&parsed, &wrong_target, &fresh_replay)
            .is_err(),
        "KX-MCP-001: proof moved to a different MCP endpoint"
    );
    Ok(())
}

#[test]
fn kx_mcp_004_dependency_direction_remains_downstream() {
    let dpop_manifest = include_str!("../../keylix-dpop/Cargo.toml");
    let mcp_manifest = include_str!("../Cargo.toml");
    let mcp_source = include_str!("../src/lib.rs");

    assert!(!dpop_manifest.contains("keylix-mcp"));
    assert!(!dpop_manifest.contains("rmcp"));
    assert!(mcp_manifest.contains("keylix-dpop"));
    assert!(mcp_manifest.contains("keylix-oauth"));
    assert!(mcp_manifest.contains("rmcp"));
    assert!(
        mcp_source.contains(".post_message(uri, message, session_id, auth_header, custom_headers)"),
        "KX-MCP-004: wrapper no longer forwards the original JSON-RPC message directly"
    );
}
