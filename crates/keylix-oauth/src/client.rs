use core::fmt;

use keylix_core::JwkThumbprint;
use keylix_dpop::{
    ClientNonceStore, Clock, DpopNonce, DpopProof, DpopProofBuilder, DpopRequest, DpopSigner,
    EffectiveRequestTarget, NonceContext, NonceNamespace, ProofIdGenerator,
};

use crate::{NonceRetryBudget, OAuthDpopError};

const MAX_CREDENTIAL_BYTES: usize = 16_384;

/// Access token accepted from a `DPoP`-required token response and bound to one proof key.
pub struct BoundAccessToken {
    value: String,
    proof_key: JwkThumbprint,
}

impl BoundAccessToken {
    /// Returns the access token only for an explicit credential-bearing integration surface.
    #[must_use]
    pub fn as_secret_value(&self) -> &str {
        &self.value
    }

    /// Returns the proof key to which this client-side token relationship is bound.
    #[must_use]
    pub const fn proof_key(&self) -> JwkThumbprint {
        self.proof_key
    }
}

impl fmt::Debug for BoundAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundAccessToken")
            .field("value", &"[redacted]")
            .field("proof_key", &"[redacted]")
            .finish()
    }
}

/// Refresh token relationship pinned to the proof key used when the `DPoP` token set was accepted.
pub struct BoundRefreshToken {
    value: String,
    proof_key: JwkThumbprint,
}

impl BoundRefreshToken {
    /// Returns the refresh token only for an explicit credential-bearing token request.
    #[must_use]
    pub fn as_secret_value(&self) -> &str {
        &self.value
    }

    /// Returns the proof key that must remain continuous for this refresh relationship.
    #[must_use]
    pub const fn proof_key(&self) -> JwkThumbprint {
        self.proof_key
    }
}

impl fmt::Debug for BoundRefreshToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundRefreshToken")
            .field("value", &"[redacted]")
            .field("proof_key", &"[redacted]")
            .finish()
    }
}

/// `DPoP` token response state accepted in strict, no-Bearer-downgrade mode.
pub struct BoundTokenSet {
    access_token: BoundAccessToken,
    refresh_token: Option<BoundRefreshToken>,
}

impl BoundTokenSet {
    /// Returns the bound access token.
    #[must_use]
    pub const fn access_token(&self) -> &BoundAccessToken {
        &self.access_token
    }

    /// Returns the optional bound refresh token.
    #[must_use]
    pub const fn refresh_token(&self) -> Option<&BoundRefreshToken> {
        self.refresh_token.as_ref()
    }

    /// Consumes the set and transfers ownership of its typed credential state.
    ///
    /// This does not expose raw credential strings; callers retain the same
    /// proof-key-bound access and refresh token types.
    #[must_use]
    pub fn into_parts(self) -> (BoundAccessToken, Option<BoundRefreshToken>) {
        (self.access_token, self.refresh_token)
    }
}

impl fmt::Debug for BoundTokenSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundTokenSet")
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// Fresh `DPoP` metadata for one `OAuth` token-endpoint HTTP attempt.
pub struct TokenEndpointDpop {
    proof: DpopProof,
}

impl TokenEndpointDpop {
    /// Returns the fresh `DPoP` header value for this token-endpoint attempt.
    #[must_use]
    pub fn dpop_header_value(&self) -> &str {
        self.proof.as_header_value()
    }
}

impl fmt::Debug for TokenEndpointDpop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenEndpointDpop([redacted proof])")
    }
}

/// Fresh protected-resource authorization metadata for exactly one HTTP attempt.
///
/// This type is intentionally not `Clone`: retries should call the decorator again
/// so a fresh proof and `jti` are generated.
pub struct ProtectedResourceAuthorization {
    authorization: String,
    proof: DpopProof,
}

impl ProtectedResourceAuthorization {
    /// Returns `Authorization: DPoP <access-token>` for explicit HTTP emission.
    #[must_use]
    pub fn authorization_header_value(&self) -> &str {
        &self.authorization
    }

    /// Returns the fresh `DPoP` proof header for the same HTTP attempt.
    #[must_use]
    pub fn dpop_header_value(&self) -> &str {
        self.proof.as_header_value()
    }
}

impl fmt::Debug for ProtectedResourceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedResourceAuthorization([redacted credentials])")
    }
}

/// Transport-agnostic `DPoP`-required `OAuth` client decorator.
///
/// The host owns HTTP execution and `OAuth` response parsing. Every decorator call
/// creates fresh proof material; Keylix never caches a fully decorated request.
pub struct DpopRequiredClient<'a, S, C, G, N> {
    signer: &'a S,
    clock: &'a C,
    proof_ids: &'a G,
    nonces: &'a N,
}

impl<'a, S, C, G, N> DpopRequiredClient<'a, S, C, G, N>
where
    S: DpopSigner,
    C: Clock,
    G: ProofIdGenerator,
    N: ClientNonceStore,
{
    /// Creates a strict client that never silently falls back to Bearer.
    #[must_use]
    pub const fn new(signer: &'a S, clock: &'a C, proof_ids: &'a G, nonces: &'a N) -> Self {
        Self {
            signer,
            clock,
            proof_ids,
            nonces,
        }
    }

    /// Builds a fresh `DPoP` proof for one authorization-server token request.
    ///
    /// # Errors
    ///
    /// Fails for the wrong nonce namespace, unavailable nonce state, or strict
    /// `DPoP` proof construction failure.
    pub fn token_request(
        &self,
        context: &NonceContext,
        token_endpoint: &EffectiveRequestTarget,
    ) -> Result<TokenEndpointDpop, OAuthDpopError> {
        require_namespace(context, NonceNamespace::AuthorizationServer)?;
        let nonce = self
            .nonces
            .nonce_for(context)
            .map_err(|_| OAuthDpopError::NonceStateUnavailable)?;
        let mut request = DpopRequest::new("POST", token_endpoint)?;
        if let Some(nonce) = nonce.as_ref() {
            request = request.with_nonce(nonce);
        }
        let proof =
            DpopProofBuilder::new(self.signer, self.clock, self.proof_ids).build(&request)?;
        Ok(TokenEndpointDpop { proof })
    }

    /// Accepts a token response only when its token type is `DPoP`.
    ///
    /// The token values are bound to the current signer identity so later resource
    /// requests and refreshes cannot silently move to another proof key.
    ///
    /// # Errors
    ///
    /// Rejects Bearer/other token types and malformed or unbounded credentials.
    pub fn accept_token_response(
        &self,
        token_type: &str,
        access_token: String,
        refresh_token: Option<String>,
    ) -> Result<BoundTokenSet, OAuthDpopError> {
        if !token_type.eq_ignore_ascii_case("DPoP") {
            return Err(OAuthDpopError::TokenTypeNotDpop);
        }
        validate_access_token(&access_token)?;
        if let Some(value) = refresh_token.as_deref() {
            validate_refresh_token(value)?;
        }
        let proof_key = self.signer.public_jwk().thumbprint();
        Ok(BoundTokenSet {
            access_token: BoundAccessToken {
                value: access_token,
                proof_key,
            },
            refresh_token: refresh_token.map(|value| BoundRefreshToken { value, proof_key }),
        })
    }

    /// Builds fresh protected-resource headers using `Authorization: DPoP`.
    ///
    /// # Errors
    ///
    /// Rejects wrong nonce namespaces, proof-key continuity changes, unavailable
    /// nonce state, or `DPoP` construction failures. It never emits Bearer fallback.
    pub fn protected_resource(
        &self,
        context: &NonceContext,
        method: &str,
        target: &EffectiveRequestTarget,
        token: &BoundAccessToken,
    ) -> Result<ProtectedResourceAuthorization, OAuthDpopError> {
        require_namespace(context, NonceNamespace::ResourceServer)?;
        self.require_key_continuity(token.proof_key)?;
        let nonce = self
            .nonces
            .nonce_for(context)
            .map_err(|_| OAuthDpopError::NonceStateUnavailable)?;
        let mut request =
            DpopRequest::new(method, target)?.with_access_token(token.value.as_bytes());
        if let Some(nonce) = nonce.as_ref() {
            request = request.with_nonce(nonce);
        }
        let proof =
            DpopProofBuilder::new(self.signer, self.clock, self.proof_ids).build(&request)?;
        Ok(ProtectedResourceAuthorization {
            authorization: format!("DPoP {}", token.value),
            proof,
        })
    }

    /// Builds a fresh token-endpoint proof for a bound refresh-token relationship.
    ///
    /// # Errors
    ///
    /// Rejects a proof-key change before any refresh request can be emitted.
    pub fn refresh_token_request(
        &self,
        context: &NonceContext,
        token_endpoint: &EffectiveRequestTarget,
        refresh_token: &BoundRefreshToken,
    ) -> Result<TokenEndpointDpop, OAuthDpopError> {
        self.require_key_continuity(refresh_token.proof_key)?;
        self.token_request(context, token_endpoint)
    }

    /// Records a nonce challenge while consuming the retry budget for one logical request.
    ///
    /// The budget is consumed before state mutation. A caller therefore cannot
    /// accidentally turn repeated `use_dpop_nonce` responses into an unbounded
    /// automatic retry loop through the normal integration boundary.
    ///
    /// # Errors
    ///
    /// Fails when the retry budget is exhausted or nonce state cannot be updated.
    pub fn record_nonce_challenge(
        &self,
        context: &NonceContext,
        nonce: &DpopNonce,
        retry_budget: &mut NonceRetryBudget,
    ) -> Result<(), OAuthDpopError> {
        retry_budget.consume()?;
        self.nonces
            .record_challenge(context, nonce)
            .map_err(|_| OAuthDpopError::NonceStateUnavailable)
    }

    /// Records an optional nonce from a successful AS or RS response.
    ///
    /// `None` preserves established nonce state according to ADR-0009.
    ///
    /// # Errors
    ///
    /// Fails closed when nonce state cannot be updated.
    pub fn record_success_nonce(
        &self,
        context: &NonceContext,
        nonce: Option<&DpopNonce>,
    ) -> Result<(), OAuthDpopError> {
        self.nonces
            .record_success(context, nonce)
            .map_err(|_| OAuthDpopError::NonceStateUnavailable)
    }

    fn require_key_continuity(&self, expected: JwkThumbprint) -> Result<(), OAuthDpopError> {
        if self.signer.public_jwk().thumbprint() != expected {
            return Err(OAuthDpopError::ProofKeyContinuityMismatch);
        }
        Ok(())
    }
}

impl<S, C, G, N> fmt::Debug for DpopRequiredClient<'_, S, C, G, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopRequiredClient([credential capabilities redacted])")
    }
}

fn require_namespace(
    context: &NonceContext,
    expected: NonceNamespace,
) -> Result<(), OAuthDpopError> {
    if context.namespace() != expected {
        return Err(OAuthDpopError::NonceContextMismatch);
    }
    Ok(())
}

fn validate_access_token(value: &str) -> Result<(), OAuthDpopError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES || !value.is_ascii() {
        return Err(OAuthDpopError::InvalidCredential);
    }
    let bytes = value.as_bytes();
    let first_padding = bytes
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(bytes.len());
    let (body, padding) = bytes.split_at(first_padding);
    if body.is_empty()
        || !body.iter().copied().all(is_b64token_byte)
        || !padding.iter().all(|byte| *byte == b'=')
    {
        return Err(OAuthDpopError::InvalidCredential);
    }
    Ok(())
}

const fn is_b64token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'+'
            | b'/'
    )
}

fn validate_refresh_token(value: &str) -> Result<(), OAuthDpopError> {
    if value.is_empty()
        || value.len() > MAX_CREDENTIAL_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| !(0x20..=0x7e).contains(&byte))
    {
        return Err(OAuthDpopError::InvalidCredential);
    }
    Ok(())
}
