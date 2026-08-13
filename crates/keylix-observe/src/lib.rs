//! Safe operational telemetry and explicit security evidence for Keylix.
//!
//! This crate deliberately does not depend on a logging, tracing, or metrics
//! framework. Operational telemetry is represented by bounded enums and static
//! label values so ordinary observability cannot accidentally acquire credential
//! material or stable key identifiers. Durable sender-binding attribution is a
//! separate, explicit evidence API built only from [`VerifiedSenderBinding`].

#![forbid(unsafe_code)]

use core::fmt;

use keylix_core::JwkThumbprint;
use keylix_oauth::{TokenValidationSource, VerifiedSenderBinding};

/// Sender-constraint mechanism represented by Keylix observability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityMechanism {
    /// OAuth Demonstrating Proof of Possession (`DPoP`).
    Dpop,
}

impl SecurityMechanism {
    /// Returns the bounded telemetry label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dpop => "dpop",
        }
    }
}

/// Cryptographic profile represented by Keylix observability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgorithmProfile {
    /// `ES256` over `P-256`, the Keylix v0.1 profile.
    Es256P256,
}

impl AlgorithmProfile {
    /// Returns the bounded telemetry label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256P256 => "es256-p256",
        }
    }
}

/// Bounded operation categories suitable for ordinary logs, traces, and metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Construct a `DPoP` proof.
    ProofBuild,
    /// Verify a `DPoP` proof.
    ProofVerify,
    /// Decorate or process an OAuth token request.
    OAuthTokenRequest,
    /// Decorate or process an OAuth protected-resource request.
    OAuthResourceRequest,
    /// Compose verified `DPoP` and host-validated OAuth state.
    OAuthSenderBinding,
    /// Resolve an effective external HTTP request target.
    HttpTargetResolution,
    /// Process the MCP client HTTP authorization adapter.
    McpClient,
    /// Process the MCP server HTTP authorization adapter.
    McpServer,
}

impl Operation {
    /// Returns the bounded telemetry label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProofBuild => "proof-build",
            Self::ProofVerify => "proof-verify",
            Self::OAuthTokenRequest => "oauth-token-request",
            Self::OAuthResourceRequest => "oauth-resource-request",
            Self::OAuthSenderBinding => "oauth-sender-binding",
            Self::HttpTargetResolution => "http-target-resolution",
            Self::McpClient => "mcp-client",
            Self::McpServer => "mcp-server",
        }
    }
}

/// Bounded failure classes for ordinary operational telemetry.
///
/// These values intentionally carry no attacker-controlled text, credential
/// bytes, proof identifiers, nonces, or stable sender identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureClass {
    /// Input was malformed or ambiguous.
    MalformedInput,
    /// The requested protocol or algorithm profile is unsupported.
    UnsupportedProfile,
    /// Cryptographic validation or signing failed.
    CryptographicFailure,
    /// HTTP method or target binding failed.
    RequestBindingFailure,
    /// Proof freshness validation failed.
    FreshnessFailure,
    /// Nonce policy or nonce validation failed.
    NonceFailure,
    /// Replay protection rejected the operation.
    ReplayFailure,
    /// OAuth sender or exact-token binding failed.
    TokenBindingFailure,
    /// A credential was rejected by the DPoP-required integration.
    CredentialRejected,
    /// A replay, nonce, clock, or other state dependency was unavailable.
    StateUnavailable,
    /// Explicit deployment or security policy rejected the operation.
    PolicyRejected,
    /// A non-classified internal dependency failed.
    Internal,
}

impl FailureClass {
    /// Returns the bounded telemetry label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedInput => "malformed-input",
            Self::UnsupportedProfile => "unsupported-profile",
            Self::CryptographicFailure => "cryptographic-failure",
            Self::RequestBindingFailure => "request-binding-failure",
            Self::FreshnessFailure => "freshness-failure",
            Self::NonceFailure => "nonce-failure",
            Self::ReplayFailure => "replay-failure",
            Self::TokenBindingFailure => "token-binding-failure",
            Self::CredentialRejected => "credential-rejected",
            Self::StateUnavailable => "state-unavailable",
            Self::PolicyRejected => "policy-rejected",
            Self::Internal => "internal",
        }
    }
}

/// Outcome of a bounded operational telemetry event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TelemetryOutcome {
    /// Operation completed successfully.
    Success,
    /// Operation failed in the supplied bounded class.
    Failure(FailureClass),
}

impl TelemetryOutcome {
    const fn result_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure(_) => "failure",
        }
    }

    const fn failure_label(self) -> Option<&'static str> {
        match self {
            Self::Success => None,
            Self::Failure(class) => Some(class.as_str()),
        }
    }
}

/// Safe, low-cardinality operational event.
///
/// There is intentionally no constructor parameter for a token, proof, nonce,
/// request identifier, JWK thumbprint, free-form message, or arbitrary label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelemetryEvent {
    operation: Operation,
    outcome: TelemetryOutcome,
}

impl TelemetryEvent {
    /// Creates a successful bounded event.
    #[must_use]
    pub const fn success(operation: Operation) -> Self {
        Self {
            operation,
            outcome: TelemetryOutcome::Success,
        }
    }

    /// Creates a failed bounded event.
    #[must_use]
    pub const fn failure(operation: Operation, class: FailureClass) -> Self {
        Self {
            operation,
            outcome: TelemetryOutcome::Failure(class),
        }
    }

    /// Returns the fixed sender-constraint mechanism.
    #[must_use]
    pub const fn mechanism(&self) -> SecurityMechanism {
        SecurityMechanism::Dpop
    }

    /// Returns the fixed cryptographic profile.
    #[must_use]
    pub const fn algorithm(&self) -> AlgorithmProfile {
        AlgorithmProfile::Es256P256
    }

    /// Returns the bounded operation category.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// Returns the bounded event outcome.
    #[must_use]
    pub const fn outcome(&self) -> TelemetryOutcome {
        self.outcome
    }

    /// Returns static, low-cardinality labels for a host metrics/tracing adapter.
    #[must_use]
    pub const fn labels(&self) -> TelemetryLabels {
        TelemetryLabels {
            mechanism: self.mechanism().as_str(),
            algorithm: self.algorithm().as_str(),
            operation: self.operation.as_str(),
            result: self.outcome.result_label(),
            failure_class: self.outcome.failure_label(),
        }
    }
}

/// Static low-cardinality labels derived from [`TelemetryEvent`].
///
/// Hosts can map these values to their logging, tracing, or metrics framework.
/// No API exists here for adding arbitrary labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelemetryLabels {
    mechanism: &'static str,
    algorithm: &'static str,
    operation: &'static str,
    result: &'static str,
    failure_class: Option<&'static str>,
}

impl TelemetryLabels {
    /// Returns the sender-constraint mechanism label.
    #[must_use]
    pub const fn mechanism(&self) -> &'static str {
        self.mechanism
    }

    /// Returns the algorithm-profile label.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// Returns the operation label.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// Returns `success` or `failure`.
    #[must_use]
    pub const fn result(&self) -> &'static str {
        self.result
    }

    /// Returns the bounded failure class when the event failed.
    #[must_use]
    pub const fn failure_class(&self) -> Option<&'static str> {
        self.failure_class
    }
}

/// Whether explicit security evidence should include the stable sender-key thumbprint.
///
/// The default omits the thumbprint because it is a durable pseudonymous
/// correlator even though it is derived from public key material.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EvidenceKeyPolicy {
    /// Omit the stable key identifier from evidence.
    #[default]
    Omit,
    /// Include the stable key identifier for explicit audit/provenance use.
    Include,
}

/// Stable error categories for evidence construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceError {
    /// The host supplied a non-positive verification timestamp.
    InvalidVerificationTime,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidVerificationTime => "invalid evidence verification time",
        })
    }
}

impl std::error::Error for EvidenceError {}

/// Explicit, compact security evidence derived from a fully verified sender binding.
///
/// This value intentionally contains no access/refresh token, proof JWT, nonce,
/// proof identifier, authorization header, private key, or host-supplied free-form
/// resource field. A host that needs resource attribution should envelope this
/// evidence in its own audit model after Keylix has produced it.
pub struct SenderBindingEvidence {
    mechanism: SecurityMechanism,
    algorithm: AlgorithmProfile,
    validation_source: TokenValidationSource,
    proof_issued_at_unix: i64,
    verified_at_unix: i64,
    nonce_enforced: bool,
    replay_checked: bool,
    key_thumbprint: Option<JwkThumbprint>,
}

impl SenderBindingEvidence {
    /// Builds explicit evidence from fully composed OAuth + `DPoP` sender state.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError::InvalidVerificationTime`] when
    /// `verified_at_unix` is not positive.
    pub fn from_binding(
        binding: &VerifiedSenderBinding,
        verified_at_unix: i64,
        key_policy: EvidenceKeyPolicy,
    ) -> Result<Self, EvidenceError> {
        if verified_at_unix <= 0 {
            return Err(EvidenceError::InvalidVerificationTime);
        }

        Ok(Self {
            mechanism: SecurityMechanism::Dpop,
            algorithm: AlgorithmProfile::Es256P256,
            validation_source: binding.validation_source(),
            proof_issued_at_unix: binding.proof_issued_at_unix(),
            verified_at_unix,
            nonce_enforced: binding.nonce_enforced(),
            replay_checked: binding.replay_checked(),
            key_thumbprint: match key_policy {
                EvidenceKeyPolicy::Omit => None,
                EvidenceKeyPolicy::Include => Some(binding.key_thumbprint()),
            },
        })
    }

    /// Returns the sender-constraint mechanism.
    #[must_use]
    pub const fn mechanism(&self) -> SecurityMechanism {
        self.mechanism
    }

    /// Returns the cryptographic profile.
    #[must_use]
    pub const fn algorithm(&self) -> AlgorithmProfile {
        self.algorithm
    }

    /// Returns how the host established OAuth token validity.
    #[must_use]
    pub const fn validation_source(&self) -> TokenValidationSource {
        self.validation_source
    }

    /// Returns the issue time of the verified proof.
    #[must_use]
    pub const fn proof_issued_at_unix(&self) -> i64 {
        self.proof_issued_at_unix
    }

    /// Returns the host-supplied time at which evidence was produced.
    #[must_use]
    pub const fn verified_at_unix(&self) -> i64 {
        self.verified_at_unix
    }

    /// Reports whether nonce enforcement occurred during verification.
    #[must_use]
    pub const fn nonce_enforced(&self) -> bool {
        self.nonce_enforced
    }

    /// Reports whether atomic replay checking occurred during verification.
    #[must_use]
    pub const fn replay_checked(&self) -> bool {
        self.replay_checked
    }

    /// Returns the stable sender-key identity only when explicitly requested.
    #[must_use]
    pub const fn key_thumbprint(&self) -> Option<JwkThumbprint> {
        self.key_thumbprint
    }
}

impl fmt::Debug for SenderBindingEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SenderBindingEvidence")
            .field("mechanism", &self.mechanism)
            .field("algorithm", &self.algorithm)
            .field("validation_source", &self.validation_source)
            .field("proof_issued_at_unix", &self.proof_issued_at_unix)
            .field("verified_at_unix", &self.verified_at_unix)
            .field("nonce_enforced", &self.nonce_enforced)
            .field("replay_checked", &self.replay_checked)
            .field("key_thumbprint", &self.key_thumbprint.map(|_| "[redacted]"))
            .finish()
    }
}
