use core::fmt;

use keylix_dpop::DpopError;

/// Stable, non-secret failure categories for `OAuth`/`DPoP` composition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OAuthDpopError {
    /// A `DPoP`-required token response returned another token type.
    TokenTypeNotDpop,
    /// The host-validated token result belongs to a different presented token.
    TokenIdentityMismatch,
    /// The host-validated token has no trusted `DPoP` confirmation thumbprint.
    TokenBindingMissing,
    /// The trusted confirmation thumbprint is malformed or non-canonical.
    TokenBindingMalformed,
    /// The trusted token confirmation key differs from the verified proof key.
    TokenBindingMismatch,
    /// The proof was not verified against an exact access credential through `ath`.
    ProofNotAccessTokenBound,
    /// An inactive introspection result cannot enter the trusted binding boundary.
    TokenInactive,
    /// A bound access/refresh credential is being used with a different proof key.
    ProofKeyContinuityMismatch,
    /// An AS-only operation received an RS nonce context, or vice versa.
    NonceContextMismatch,
    /// Nonce state could not be read or updated reliably.
    NonceStateUnavailable,
    /// The nonce retry budget for one logical `HTTP` operation has been exhausted.
    NonceRetryLimitExceeded,
    /// A token/refresh credential cannot be emitted safely as protocol input.
    InvalidCredential,
    /// The underlying strict `DPoP` operation failed.
    Dpop(DpopError),
}

impl fmt::Display for OAuthDpopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TokenTypeNotDpop => "DPoP token type required",
            Self::TokenIdentityMismatch => "validated token identity mismatch",
            Self::TokenBindingMissing => "validated token is not DPoP-bound",
            Self::TokenBindingMalformed => "validated token binding is malformed",
            Self::TokenBindingMismatch => "validated token binding does not match proof key",
            Self::ProofNotAccessTokenBound => "DPoP proof was not verified against access token",
            Self::TokenInactive => "validated token is inactive",
            Self::ProofKeyContinuityMismatch => "DPoP proof-key continuity mismatch",
            Self::NonceContextMismatch => "OAuth DPoP nonce context mismatch",
            Self::NonceStateUnavailable => "OAuth DPoP nonce state unavailable",
            Self::NonceRetryLimitExceeded => "OAuth DPoP nonce retry limit exceeded",
            Self::InvalidCredential => "invalid OAuth credential value",
            Self::Dpop(error) => return error.fmt(formatter),
        })
    }
}

impl std::error::Error for OAuthDpopError {}

impl From<DpopError> for OAuthDpopError {
    fn from(error: DpopError) -> Self {
        Self::Dpop(error)
    }
}
