use core::fmt;

/// A stable, non-secret failure category for `DPoP` processing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DpopError {
    /// No `DPoP` header value was supplied at the HTTP boundary.
    MissingProof,
    /// More than one proof value, or a comma-joined ambiguous value, was supplied.
    AmbiguousProof,
    /// The compact JWS, JSON, or required `DPoP` fields are malformed.
    MalformedProof,
    /// The proof exceeds the configured protocol size bounds.
    ProofTooLarge,
    /// The JOSE algorithm is not accepted by the v0.1 profile.
    UnsupportedAlgorithm,
    /// The proof JWK is not an accepted public P-256 key.
    UnsupportedKey,
    /// The ES256 signature is malformed or invalid.
    InvalidSignature,
    /// The proof HTTP method does not match the current request.
    MethodMismatch,
    /// The proof target URI does not match the trusted effective request target.
    TargetMismatch,
    /// The proof is older than the configured maximum age.
    ProofExpired,
    /// The proof is dated too far in the future.
    ProofFromFuture,
    /// A protected-resource proof omitted the access-token hash.
    AccessTokenHashMissing,
    /// The access-token hash does not match the exact presented token bytes.
    AccessTokenHashMismatch,
    /// The current verification context requires a nonce but the proof omitted it.
    NonceRequired,
    /// The proof nonce does not match the nonce required by the current context.
    NonceMismatch,
    /// The proof has already been accepted in its replay scope.
    ReplayDetected,
    /// Replay state could not be checked atomically.
    ReplayStoreUnavailable,
    /// A signing dependency failed or returned output inconsistent with its public key.
    SignerFailure,
    /// The clock dependency failed.
    ClockUnavailable,
    /// The proof identifier dependency failed or returned an invalid identifier.
    ProofIdUnavailable,
    /// The effective HTTP request target is invalid for the supported HTTP(S) profile.
    InvalidRequestTarget,
    /// The HTTP method is not a valid bounded method token.
    InvalidMethod,
    /// A verification policy value is outside the supported range.
    InvalidPolicy,
}

impl fmt::Display for DpopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingProof => "DPoP proof missing",
            Self::AmbiguousProof => "ambiguous DPoP proof",
            Self::MalformedProof => "malformed DPoP proof",
            Self::ProofTooLarge => "DPoP proof exceeds size limit",
            Self::UnsupportedAlgorithm => "unsupported DPoP algorithm",
            Self::UnsupportedKey => "unsupported DPoP public key",
            Self::InvalidSignature => "invalid DPoP signature",
            Self::MethodMismatch => "DPoP method mismatch",
            Self::TargetMismatch => "DPoP target mismatch",
            Self::ProofExpired => "DPoP proof expired",
            Self::ProofFromFuture => "DPoP proof is from the future",
            Self::AccessTokenHashMissing => "DPoP access-token hash missing",
            Self::AccessTokenHashMismatch => "DPoP access-token hash mismatch",
            Self::NonceRequired => "DPoP nonce required",
            Self::NonceMismatch => "DPoP nonce mismatch",
            Self::ReplayDetected => "DPoP replay detected",
            Self::ReplayStoreUnavailable => "DPoP replay store unavailable",
            Self::SignerFailure => "DPoP signer failure",
            Self::ClockUnavailable => "DPoP clock unavailable",
            Self::ProofIdUnavailable => "DPoP proof identifier unavailable",
            Self::InvalidRequestTarget => "invalid effective request target",
            Self::InvalidMethod => "invalid HTTP method",
            Self::InvalidPolicy => "invalid DPoP verification policy",
        })
    }
}

impl std::error::Error for DpopError {}

/// Opaque failure returned by an injected `DPoP` dependency port.
///
/// Port implementations should retain detailed infrastructure errors internally
/// rather than reflecting potentially sensitive values through the protocol API.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DpopPortError;

impl fmt::Display for DpopPortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DPoP dependency failure")
    }
}

impl std::error::Error for DpopPortError {}
