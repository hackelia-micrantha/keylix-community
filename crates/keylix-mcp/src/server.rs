use core::fmt;

use keylix_dpop::{
    Clock, DpopError, DpopNonce, DpopRequest, DpopVerifier, EffectiveRequestTarget, ReplayStore,
    VerificationPolicy, parse_dpop_header_values,
};
use keylix_oauth::{
    HostValidatedToken, OAuthDpopError, VerifiedSenderBinding, compose_sender_binding,
};

/// One MCP HTTP request at the server-side `DPoP` verification boundary.
///
/// The host constructs the trusted effective request target before entering this
/// type. Query and fragment handling remain governed by [`EffectiveRequestTarget`].
pub struct McpHttpRequest<'a> {
    method: &'a str,
    target: &'a EffectiveRequestTarget,
    access_token: &'a [u8],
    dpop_header_values: &'a [&'a str],
    nonce: Option<&'a DpopNonce>,
}

impl<'a> McpHttpRequest<'a> {
    /// Creates a request using exact presented access-token bytes and all HTTP
    /// `DPoP` header field values observed by the framework adapter.
    #[must_use]
    pub const fn new(
        method: &'a str,
        target: &'a EffectiveRequestTarget,
        access_token: &'a [u8],
        dpop_header_values: &'a [&'a str],
    ) -> Self {
        Self {
            method,
            target,
            access_token,
            dpop_header_values,
            nonce: None,
        }
    }

    /// Requires the supplied resource-server nonce for this verification.
    #[must_use]
    pub const fn with_nonce(mut self, nonce: &'a DpopNonce) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

impl fmt::Debug for McpHttpRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpHttpRequest")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("access_token", &"[redacted]")
            .field("dpop_header_values", &"[redacted]")
            .field("nonce", &self.nonce.map(|_| "[redacted]"))
            .finish()
    }
}

/// Distinguishes proof/request failures from OAuth sender-binding failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum McpDpopServerError {
    /// RFC 9449 proof, request-binding, nonce, freshness, or replay verification failed.
    Proof(DpopError),
    /// The verified proof could not compose with the host-validated exact token.
    SenderBinding(OAuthDpopError),
}

impl fmt::Display for McpDpopServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Proof(_) => "MCP DPoP proof verification failed",
            Self::SenderBinding(_) => "MCP OAuth sender binding failed",
        })
    }
}

impl std::error::Error for McpDpopServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Proof(error) => Some(error),
            Self::SenderBinding(error) => Some(error),
        }
    }
}

impl From<DpopError> for McpDpopServerError {
    fn from(error: DpopError) -> Self {
        Self::Proof(error)
    }
}

/// Pre-dispatch MCP HTTP verifier that composes strict `DPoP` with host OAuth validation.
pub struct McpDpopServer<'a, C, R> {
    clock: &'a C,
    policy: VerificationPolicy,
    replay_store: &'a R,
}

impl<'a, C, R> McpDpopServer<'a, C, R>
where
    C: Clock,
    R: ReplayStore,
{
    /// Creates a verifier with explicit proof-freshness policy and replay backend.
    #[must_use]
    pub const fn new(clock: &'a C, policy: VerificationPolicy, replay_store: &'a R) -> Self {
        Self {
            clock,
            policy,
            replay_store,
        }
    }

    /// Verifies the MCP HTTP proof and composes it with trusted OAuth token metadata.
    ///
    /// This method returns only [`VerifiedSenderBinding`]. Raw proof/token material
    /// is intentionally not propagated to MCP method dispatch.
    ///
    /// # Errors
    ///
    /// [`McpDpopServerError::Proof`] covers proof/request/nonce/replay failures.
    /// [`McpDpopServerError::SenderBinding`] covers exact-token or trusted
    /// confirmation-key composition failures after the proof itself is verified.
    pub fn verify(
        &self,
        request: &McpHttpRequest<'_>,
        validated_token: &HostValidatedToken,
    ) -> Result<VerifiedSenderBinding, McpDpopServerError> {
        let proof = parse_dpop_header_values(request.dpop_header_values)?;
        let mut dpop_request = DpopRequest::new(request.method, request.target)?
            .with_access_token(request.access_token);
        if let Some(nonce) = request.nonce {
            dpop_request = dpop_request.with_nonce(nonce);
        }
        let verified = DpopVerifier::new(self.clock, self.policy).verify(
            &proof,
            &dpop_request,
            self.replay_store,
        )?;
        compose_sender_binding(&verified, request.access_token, validated_token)
            .map_err(McpDpopServerError::SenderBinding)
    }
}

impl<C, R> fmt::Debug for McpDpopServer<'_, C, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpDpopServer([verification capabilities])")
    }
}
