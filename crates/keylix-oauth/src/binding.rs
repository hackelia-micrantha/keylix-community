use core::fmt;

use aws_lc_rs::digest::{SHA256, digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use keylix_core::JwkThumbprint;
use keylix_dpop::VerifiedDpopProof;

use crate::OAuthDpopError;

const SHA256_BYTES: usize = 32;
const SHA256_BASE64URL_BYTES: usize = 43;

/// Opaque `SHA-256` identity of the exact `OAuth` token bytes validated by the host.
///
/// This value is a stable correlator and is therefore redacted from ordinary
/// diagnostics. It exists only to prevent token-A validation metadata from being
/// accidentally composed with token-B presentation bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenFingerprint([u8; SHA256_BYTES]);

impl TokenFingerprint {
    /// Computes the exact-token fingerprint used by the `OAuth` trust boundary.
    #[must_use]
    pub fn from_token_bytes(token: &[u8]) -> Self {
        let hash = digest(&SHA256, token);
        let mut bytes = [0_u8; SHA256_BYTES];
        bytes.copy_from_slice(hash.as_ref());
        Self(bytes)
    }
}

impl fmt::Debug for TokenFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenFingerprint([redacted])")
    }
}

/// Host validation path that established an `OAuth` token result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenValidationSource {
    /// A `JWT` access credential successfully validated under host `OAuth` policy.
    ValidatedJwt,
    /// An authenticated and active `OAuth` token-introspection result.
    AuthenticatedIntrospection,
    /// Another host validator with equivalent validity guarantees.
    EquivalentHostValidator,
}

/// Explicit host-attested `OAuth` validation result used for `DPoP` composition.
///
/// Keylix does **not** validate the token when constructing this value. Callers
/// must use these constructors only after their `OAuth`/`JWT`/introspection policy has
/// established validity for the exact token bytes supplied here. The explicit
/// `from_host_*` naming prevents this type from being confused with raw decoded
/// claims.
pub struct HostValidatedToken {
    fingerprint: TokenFingerprint,
    confirmation: Option<[u8; SHA256_BYTES]>,
    source: TokenValidationSource,
}

impl HostValidatedToken {
    /// Adapts a `JWT` access credential that the host has already fully validated.
    ///
    /// `confirmation_jkt` is the trusted `cnf.jkt` value obtained from that
    /// validated result, or `None` when the validated token is not `DPoP`-bound.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthDpopError::TokenBindingMalformed`] when a supplied `jkt`
    /// is not canonical unpadded base64url for exactly 32 `SHA-256` bytes.
    pub fn from_host_validated_jwt(
        exact_token: &[u8],
        confirmation_jkt: Option<&str>,
    ) -> Result<Self, OAuthDpopError> {
        Self::new(
            exact_token,
            confirmation_jkt,
            TokenValidationSource::ValidatedJwt,
        )
    }

    /// Adapts an authenticated `OAuth` introspection result.
    ///
    /// The caller attests that the introspection channel/result was authenticated;
    /// `active` must also be true before the result can enter the trusted boundary.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthDpopError::TokenInactive`] for an inactive response and
    /// [`OAuthDpopError::TokenBindingMalformed`] for malformed `cnf.jkt`.
    pub fn from_host_authenticated_introspection(
        exact_token: &[u8],
        active: bool,
        confirmation_jkt: Option<&str>,
    ) -> Result<Self, OAuthDpopError> {
        if !active {
            return Err(OAuthDpopError::TokenInactive);
        }
        Self::new(
            exact_token,
            confirmation_jkt,
            TokenValidationSource::AuthenticatedIntrospection,
        )
    }

    /// Adapts another host token validator with equivalent `OAuth` validity guarantees.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthDpopError::TokenBindingMalformed`] for malformed `cnf.jkt`.
    pub fn from_equivalent_host_validator(
        exact_token: &[u8],
        confirmation_jkt: Option<&str>,
    ) -> Result<Self, OAuthDpopError> {
        Self::new(
            exact_token,
            confirmation_jkt,
            TokenValidationSource::EquivalentHostValidator,
        )
    }

    fn new(
        exact_token: &[u8],
        confirmation_jkt: Option<&str>,
        source: TokenValidationSource,
    ) -> Result<Self, OAuthDpopError> {
        Ok(Self {
            fingerprint: TokenFingerprint::from_token_bytes(exact_token),
            confirmation: confirmation_jkt.map(parse_jkt).transpose()?,
            source,
        })
    }
}

impl fmt::Debug for HostValidatedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostValidatedToken")
            .field("source", &self.source)
            .field("fingerprint", &"[redacted]")
            .field("confirmation", &self.confirmation.map(|_| "[redacted]"))
            .finish()
    }
}

/// Fully composed `OAuth` + `DPoP` sender-binding trust state.
///
/// This type can only be produced after exact-token correlation, verified `ath`,
/// and proof-key/token-key equality have all succeeded.
pub struct VerifiedSenderBinding {
    key_thumbprint: JwkThumbprint,
    source: TokenValidationSource,
    proof_issued_at_unix: i64,
    nonce_enforced: bool,
    replay_checked: bool,
}

impl VerifiedSenderBinding {
    /// Returns the verified sender key for explicit security-evidence use.
    #[must_use]
    pub const fn key_thumbprint(&self) -> JwkThumbprint {
        self.key_thumbprint
    }

    /// Returns which host validation path established the token's `OAuth` validity.
    #[must_use]
    pub const fn validation_source(&self) -> TokenValidationSource {
        self.source
    }

    /// Returns the verified `DPoP` proof issue time.
    #[must_use]
    pub const fn proof_issued_at_unix(&self) -> i64 {
        self.proof_issued_at_unix
    }

    /// Reports whether a server nonce was enforced during proof verification.
    #[must_use]
    pub const fn nonce_enforced(&self) -> bool {
        self.nonce_enforced
    }

    /// Reports whether atomic replay checking was performed.
    #[must_use]
    pub const fn replay_checked(&self) -> bool {
        self.replay_checked
    }
}

impl fmt::Debug for VerifiedSenderBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSenderBinding")
            .field("mechanism", &"DPoP")
            .field("validation_source", &self.source)
            .field("key_thumbprint", &"[redacted]")
            .field("proof_issued_at_unix", &self.proof_issued_at_unix)
            .field("nonce_enforced", &self.nonce_enforced)
            .field("replay_checked", &self.replay_checked)
            .finish()
    }
}

/// Composes strict `DPoP` proof verification with an explicit host `OAuth` validation result.
///
/// # Errors
///
/// Fails when the proof did not verify `ath`, the validation result belongs to a
/// different exact token, the token has no `DPoP` confirmation, or the confirmation
/// key does not match the verified proof key.
pub fn compose_sender_binding(
    proof: &VerifiedDpopProof,
    exact_presented_token: &[u8],
    validated: &HostValidatedToken,
) -> Result<VerifiedSenderBinding, OAuthDpopError> {
    if !proof.access_token_hash_verified() {
        return Err(OAuthDpopError::ProofNotAccessTokenBound);
    }

    let presented = TokenFingerprint::from_token_bytes(exact_presented_token);
    if presented != validated.fingerprint {
        return Err(OAuthDpopError::TokenIdentityMismatch);
    }

    let confirmation = validated
        .confirmation
        .ok_or(OAuthDpopError::TokenBindingMissing)?;
    if proof.key_thumbprint().as_bytes() != &confirmation {
        return Err(OAuthDpopError::TokenBindingMismatch);
    }

    Ok(VerifiedSenderBinding {
        key_thumbprint: proof.key_thumbprint(),
        source: validated.source,
        proof_issued_at_unix: proof.issued_at_unix(),
        nonce_enforced: proof.nonce_enforced(),
        replay_checked: proof.replay_checked(),
    })
}

fn parse_jkt(value: &str) -> Result<[u8; SHA256_BYTES], OAuthDpopError> {
    if value.len() != SHA256_BASE64URL_BYTES || value.contains('=') {
        return Err(OAuthDpopError::TokenBindingMalformed);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| OAuthDpopError::TokenBindingMalformed)?;
    let bytes: [u8; SHA256_BYTES] = decoded
        .try_into()
        .map_err(|_| OAuthDpopError::TokenBindingMalformed)?;
    if URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(OAuthDpopError::TokenBindingMalformed);
    }
    Ok(bytes)
}
