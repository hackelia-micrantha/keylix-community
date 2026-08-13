//! Model Context Protocol adapters for Keylix.
//!
//! `DPoP` is applied only to MCP HTTP authorization. This crate deliberately
//! does not add proof material to MCP JSON-RPC messages. The current profile is
//! experimental because SEP-1932 remains a draft.

#![forbid(unsafe_code)]

mod server;
pub use server::{McpDpopServer, McpDpopServerError, McpHttpRequest};

use core::fmt;
use std::{collections::HashMap, sync::Arc};

use futures::stream::BoxStream;
use http::{HeaderName, HeaderValue};
use keylix_dpop::{
    ClientNonceStore, Clock, DpopNonce, DpopSigner, EffectiveRequestTarget, NonceContext,
    NonceNamespace, ProofIdGenerator,
};
use keylix_oauth::{
    BoundAccessToken, DpopRequiredClient, NonceRetryBudget, OAuthDpopError, TokenEndpointDpop,
};
use rmcp::{
    model::ClientJsonRpcMessage,
    transport::streamable_http_client::{
        SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
    },
};
use sse_stream::Sse;

const DPOP_HEADER: HeaderName = HeaderName::from_static("dpop");
const AUTHORIZATION_HEADER: HeaderName = HeaderName::from_static("authorization");

/// Stable identifier for the experimental Keylix MCP `DPoP` profile.
pub const SEP_1932_DRAFT_PROFILE: &str = "sep-1932-draft";

/// Official `rmcp` release against which this adapter is intentionally pinned.
pub const RMCP_ADAPTER_VERSION: &str = "3.0.1";

/// MCP specification generation supported by `rmcp` 3.0.x.
pub const MCP_SPEC_VERSION: &str = "2026-07-28";

/// Maturity of an MCP authorization profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileStatus {
    /// The upstream profile is still a standards-track draft.
    Draft,
}

/// Explicit compatibility metadata for the MCP adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McpDpopProfileMetadata {
    /// Keylix profile identifier.
    pub profile: &'static str,
    /// Upstream SEP identifier.
    pub sep: &'static str,
    /// Upstream profile maturity.
    pub status: ProfileStatus,
    /// Official Rust SDK release targeted by this adapter.
    pub rmcp_version: &'static str,
    /// MCP specification generation targeted by that SDK release.
    pub mcp_spec_version: &'static str,
}

/// Returns the explicit draft-profile compatibility contract.
#[must_use]
pub const fn profile_metadata() -> McpDpopProfileMetadata {
    McpDpopProfileMetadata {
        profile: SEP_1932_DRAFT_PROFILE,
        sep: "SEP-1932",
        status: ProfileStatus::Draft,
        rmcp_version: RMCP_ADAPTER_VERSION,
        mcp_spec_version: MCP_SPEC_VERSION,
    }
}

/// Errors produced by the strict MCP `DPoP` adapter.
#[derive(Debug)]
#[non_exhaustive]
pub enum McpDpopError {
    /// An unsupported profile identifier was requested.
    UnsupportedProfile,
    /// Keylix OAuth/DPoP decoration failed.
    OAuth(OAuthDpopError),
    /// The host supplied an authorization value in addition to Keylix-managed `DPoP`.
    ExistingAuthorization,
    /// The host supplied a `DPoP` proof header in addition to Keylix-managed `DPoP`.
    ExistingDpopHeader,
    /// A generated protocol value could not be represented as an HTTP header.
    InvalidHeaderValue,
}

impl fmt::Display for McpDpopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedProfile => "unsupported MCP DPoP profile",
            Self::OAuth(_) => "MCP DPoP authorization failed",
            Self::ExistingAuthorization => "pre-existing authorization value rejected",
            Self::ExistingDpopHeader => "pre-existing DPoP header rejected",
            Self::InvalidHeaderValue => "invalid generated MCP DPoP header value",
        })
    }
}

impl std::error::Error for McpDpopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OAuth(error) => Some(error),
            _ => None,
        }
    }
}

impl From<OAuthDpopError> for McpDpopError {
    fn from(error: OAuthDpopError) -> Self {
        Self::OAuth(error)
    }
}

/// Validates an externally supplied MCP `DPoP` profile identifier.
///
/// # Errors
///
/// Unknown or future profile identifiers fail explicitly; the adapter never
/// silently downgrades to bearer authorization.
pub fn require_profile(profile: &str) -> Result<McpDpopProfileMetadata, McpDpopError> {
    if profile == SEP_1932_DRAFT_PROFILE {
        Ok(profile_metadata())
    } else {
        Err(McpDpopError::UnsupportedProfile)
    }
}

/// Transport-independent MCP `DPoP` decorator built on `keylix-oauth`.
///
/// The two nonce contexts are kept distinct so an authorization-server nonce
/// cannot be applied to a protected MCP resource request, or vice versa.
pub struct McpDpopClient<S, C, G, N> {
    signer: Arc<S>,
    clock: Arc<C>,
    proof_ids: Arc<G>,
    nonces: Arc<N>,
    authorization_server: NonceContext,
    resource_server: NonceContext,
}

impl<S, C, G, N> Clone for McpDpopClient<S, C, G, N> {
    fn clone(&self) -> Self {
        Self {
            signer: Arc::clone(&self.signer),
            clock: Arc::clone(&self.clock),
            proof_ids: Arc::clone(&self.proof_ids),
            nonces: Arc::clone(&self.nonces),
            authorization_server: self.authorization_server.clone(),
            resource_server: self.resource_server.clone(),
        }
    }
}

impl<S, C, G, N> McpDpopClient<S, C, G, N>
where
    S: DpopSigner,
    C: Clock,
    G: ProofIdGenerator,
    N: ClientNonceStore,
{
    /// Creates a client with explicit authorization-server and resource-server scopes.
    ///
    /// # Errors
    ///
    /// Returns an error when either nonce-scope identifier is invalid.
    pub fn new(
        signer: Arc<S>,
        clock: Arc<C>,
        proof_ids: Arc<G>,
        nonces: Arc<N>,
        authorization_server_id: impl Into<String>,
        resource_server_id: impl Into<String>,
    ) -> Result<Self, McpDpopError> {
        Ok(Self {
            signer,
            clock,
            proof_ids,
            nonces,
            authorization_server: NonceContext::new(
                NonceNamespace::AuthorizationServer,
                authorization_server_id,
            )
            .map_err(OAuthDpopError::from)?,
            resource_server: NonceContext::new(NonceNamespace::ResourceServer, resource_server_id)
                .map_err(OAuthDpopError::from)?,
        })
    }

    /// Builds a fresh `DPoP` proof for one OAuth token-endpoint attempt.
    ///
    /// # Errors
    ///
    /// Returns an error when nonce state or proof construction fails.
    pub fn token_endpoint_attempt(
        &self,
        token_endpoint: &EffectiveRequestTarget,
    ) -> Result<TokenEndpointDpop, McpDpopError> {
        self.oauth_client()
            .token_request(&self.authorization_server, token_endpoint)
            .map_err(Into::into)
    }

    /// Builds strict MCP protected-resource authorization for one HTTP attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for key-continuity, nonce-state, target, or proof failures.
    pub fn resource_attempt(
        &self,
        method: &str,
        target: &EffectiveRequestTarget,
        access_token: &BoundAccessToken,
    ) -> Result<McpHttpAuthorization, McpDpopError> {
        let authorization = self.oauth_client().protected_resource(
            &self.resource_server,
            method,
            target,
            access_token,
        )?;
        Ok(McpHttpAuthorization {
            authorization: authorization.authorization_header_value().to_owned(),
            proof: authorization.dpop_header_value().to_owned(),
        })
    }

    /// Records an authorization-server nonce challenge under a bounded retry budget.
    ///
    /// # Errors
    ///
    /// Returns an error when the retry budget is exhausted or state cannot be updated.
    pub fn record_authorization_server_nonce_challenge(
        &self,
        nonce: &DpopNonce,
        retry_budget: &mut NonceRetryBudget,
    ) -> Result<(), McpDpopError> {
        self.oauth_client()
            .record_nonce_challenge(&self.authorization_server, nonce, retry_budget)
            .map_err(Into::into)
    }

    /// Records a resource-server nonce challenge under a bounded retry budget.
    ///
    /// # Errors
    ///
    /// Returns an error when the retry budget is exhausted or state cannot be updated.
    pub fn record_resource_server_nonce_challenge(
        &self,
        nonce: &DpopNonce,
        retry_budget: &mut NonceRetryBudget,
    ) -> Result<(), McpDpopError> {
        self.oauth_client()
            .record_nonce_challenge(&self.resource_server, nonce, retry_budget)
            .map_err(Into::into)
    }

    /// Records an optional nonce from a successful authorization-server response.
    ///
    /// # Errors
    ///
    /// Returns an error when state cannot be updated reliably.
    pub fn record_authorization_server_success_nonce(
        &self,
        nonce: Option<&DpopNonce>,
    ) -> Result<(), McpDpopError> {
        self.oauth_client()
            .record_success_nonce(&self.authorization_server, nonce)
            .map_err(Into::into)
    }

    /// Records an optional nonce from a successful resource-server response.
    ///
    /// # Errors
    ///
    /// Returns an error when state cannot be updated reliably.
    pub fn record_resource_server_success_nonce(
        &self,
        nonce: Option<&DpopNonce>,
    ) -> Result<(), McpDpopError> {
        self.oauth_client()
            .record_success_nonce(&self.resource_server, nonce)
            .map_err(Into::into)
    }

    fn oauth_client(&self) -> DpopRequiredClient<'_, S, C, G, N> {
        DpopRequiredClient::new(
            self.signer.as_ref(),
            self.clock.as_ref(),
            self.proof_ids.as_ref(),
            self.nonces.as_ref(),
        )
    }
}

impl<S, C, G, N> fmt::Debug for McpDpopClient<S, C, G, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpDpopClient([credential capabilities redacted])")
    }
}

/// Fresh `DPoP` authorization metadata for one MCP HTTP attempt.
///
/// This value intentionally contains no MCP JSON-RPC fields and is not `Clone`;
/// a retry must ask [`McpDpopClient::resource_attempt`] for a fresh proof.
pub struct McpHttpAuthorization {
    authorization: String,
    proof: String,
}

impl McpHttpAuthorization {
    fn into_rmcp_parts(
        self,
        mut custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(Option<String>, HashMap<HeaderName, HeaderValue>), McpDpopError> {
        let proof =
            HeaderValue::from_str(&self.proof).map_err(|_| McpDpopError::InvalidHeaderValue)?;
        custom_headers.insert(DPOP_HEADER, proof);
        Ok((Some(self.authorization), custom_headers))
    }
}

impl fmt::Debug for McpHttpAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpHttpAuthorization([redacted credentials])")
    }
}

/// Error type surfaced through an `rmcp` streamable HTTP client wrapper.
pub enum DpopStreamableHttpClientError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Keylix rejected or could not decorate the HTTP attempt.
    Keylix(McpDpopError),
    /// The wrapped `rmcp` HTTP client failed after strict decoration.
    Inner(Box<StreamableHttpError<E>>),
}

impl<E> fmt::Debug for DpopStreamableHttpClientError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Keylix(_) => "DpopStreamableHttpClientError::Keylix([redacted])",
            Self::Inner(_) => "DpopStreamableHttpClientError::Inner([redacted])",
        })
    }
}

impl<E> fmt::Display for DpopStreamableHttpClientError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Keylix(_) => "Keylix MCP DPoP HTTP decoration failed",
            Self::Inner(_) => "wrapped MCP HTTP client failed",
        })
    }
}

impl<E> std::error::Error for DpopStreamableHttpClientError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Keylix(error) => Some(error),
            Self::Inner(error) => Some(error.as_ref()),
        }
    }
}

/// `rmcp` streamable-HTTP client wrapper that applies a fresh `DPoP` proof per attempt.
pub struct DpopStreamableHttpClient<I, S, C, G, N> {
    inner: I,
    dpop: McpDpopClient<S, C, G, N>,
    access_token: Arc<BoundAccessToken>,
}

impl<I, S, C, G, N> Clone for DpopStreamableHttpClient<I, S, C, G, N>
where
    I: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            dpop: self.dpop.clone(),
            access_token: Arc::clone(&self.access_token),
        }
    }
}

impl<I, S, C, G, N> DpopStreamableHttpClient<I, S, C, G, N>
where
    S: DpopSigner,
    C: Clock,
    G: ProofIdGenerator,
    N: ClientNonceStore,
{
    /// Wraps an official `rmcp` HTTP backend with strict `DPoP` authorization.
    #[must_use]
    pub fn new(
        inner: I,
        dpop: McpDpopClient<S, C, G, N>,
        access_token: Arc<BoundAccessToken>,
    ) -> Self {
        Self {
            inner,
            dpop,
            access_token,
        }
    }

    fn decorate(
        &self,
        method: &str,
        uri: &str,
        auth_header_present: bool,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(Option<String>, HashMap<HeaderName, HeaderValue>), McpDpopError> {
        if auth_header_present || custom_headers.contains_key(&AUTHORIZATION_HEADER) {
            return Err(McpDpopError::ExistingAuthorization);
        }
        if custom_headers.contains_key(&DPOP_HEADER) {
            return Err(McpDpopError::ExistingDpopHeader);
        }
        let target = EffectiveRequestTarget::parse(uri).map_err(OAuthDpopError::from)?;
        self.dpop
            .resource_attempt(method, &target, self.access_token.as_ref())?
            .into_rmcp_parts(custom_headers)
    }
}

impl<I, S, C, G, N> fmt::Debug for DpopStreamableHttpClient<I, S, C, G, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopStreamableHttpClient([credential capabilities redacted])")
    }
}

fn inner_error<E>(
    error: StreamableHttpError<E>,
) -> StreamableHttpError<DpopStreamableHttpClientError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    StreamableHttpError::Client(DpopStreamableHttpClientError::Inner(Box::new(error)))
}

impl<I, S, C, G, N> StreamableHttpClient for DpopStreamableHttpClient<I, S, C, G, N>
where
    I: StreamableHttpClient + Sync,
    S: DpopSigner + 'static,
    C: Clock + 'static,
    G: ProofIdGenerator + 'static,
    N: ClientNonceStore + 'static,
{
    type Error = DpopStreamableHttpClientError<I::Error>;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let (auth_header, custom_headers) = self
            .decorate("POST", &uri, auth_header.is_some(), custom_headers)
            .map_err(|error| {
                StreamableHttpError::Client(DpopStreamableHttpClientError::Keylix(error))
            })?;
        self.inner
            .post_message(uri, message, session_id, auth_header, custom_headers)
            .await
            .map_err(inner_error)
    }

    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let (auth_header, custom_headers) = self
            .decorate("POST", &uri, auth_header.is_some(), custom_headers)
            .map_err(|error| {
                StreamableHttpError::Client(DpopStreamableHttpClientError::Keylix(error))
            })?;
        self.inner
            .post_message_with_max_sse_event_size(
                uri,
                message,
                session_id,
                auth_header,
                custom_headers,
                max_sse_event_size,
            )
            .await
            .map_err(inner_error)
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let (auth_header, custom_headers) = self
            .decorate("DELETE", &uri, auth_header.is_some(), custom_headers)
            .map_err(|error| {
                StreamableHttpError::Client(DpopStreamableHttpClientError::Keylix(error))
            })?;
        self.inner
            .delete_session(uri, session_id, auth_header, custom_headers)
            .await
            .map_err(inner_error)
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        let (auth_header, custom_headers) = self
            .decorate("GET", &uri, auth_header.is_some(), custom_headers)
            .map_err(|error| {
                StreamableHttpError::Client(DpopStreamableHttpClientError::Keylix(error))
            })?;
        self.inner
            .get_stream(uri, session_id, last_event_id, auth_header, custom_headers)
            .await
            .map_err(inner_error)
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        let (auth_header, custom_headers) = self
            .decorate("GET", &uri, auth_header.is_some(), custom_headers)
            .map_err(|error| {
                StreamableHttpError::Client(DpopStreamableHttpClientError::Keylix(error))
            })?;
        self.inner
            .get_stream_with_max_sse_event_size(
                uri,
                session_id,
                last_event_id,
                auth_header,
                custom_headers,
                max_sse_event_size,
            )
            .await
            .map_err(inner_error)
    }
}
