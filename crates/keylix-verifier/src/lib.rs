//! Bounded server-side sender-binding verification for Keylix.
//!
//! This crate composes existing Keylix `DPoP` and OAuth primitives behind a
//! versioned application contract. It intentionally does not validate access
//! credentials, construct application principals, or authorize application
//! actions. A transport adapter must authenticate its host peer before treating
//! the token-validation assertion in a request as trusted.

#![forbid(unsafe_code)]

mod replay;
mod secure_fs;

pub use replay::FileReplayStore;

use aws_lc_rs::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use keylix_dpop::{
    Clock, DpopError, DpopRequest, DpopVerifier, EffectiveRequestTarget, NonceContext, ReplayStore,
    ServerNonceStore, VerificationPolicy, parse_dpop_header_values,
};
use keylix_oauth::{HostValidatedToken, OAuthDpopError, compose_sender_binding};
use serde::{Deserialize, Serialize};

/// Version of the verifier application and IPC payload contract.
pub const VERIFIER_PROTOCOL_VERSION: u16 = 1;

/// Maximum decoded verifier request payload size accepted by the reference IPC adapter.
pub const MAX_VERIFIER_PAYLOAD_BYTES: usize = 32 * 1024;

/// Stable failure classes returned by the verifier.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FailureClass {
    /// The request/result version is unsupported.
    UnsupportedVersion,
    /// The request envelope or trusted request fields are malformed.
    MalformedRequest,
    /// The `DPoP` proof is absent, ambiguous, malformed, or cryptographically invalid.
    InvalidProof,
    /// The `DPoP` HTTP method does not match the trusted request method.
    MethodMismatch,
    /// The `DPoP` target does not match the trusted effective request target.
    TargetMismatch,
    /// The proof is older than the configured acceptance window.
    StaleProof,
    /// The proof is dated too far into the future.
    FutureProof,
    /// Server-owned nonce policy requires a nonce.
    NonceRequired,
    /// The proof carries the wrong server nonce.
    NonceMismatch,
    /// Nonce state is unavailable or indeterminate.
    NonceStateUnavailable,
    /// The proof was already accepted in its replay scope.
    Replay,
    /// Replay state is unavailable or indeterminate.
    ReplayStoreUnavailable,
    /// The exact access-token hash does not match the proof.
    TokenHashMismatch,
    /// The host-validated token is not DPoP-bound.
    TokenBindingMissing,
    /// The host-validated token binding is malformed.
    TokenBindingMalformed,
    /// The host-validated token key differs from the proof key.
    ConfirmationKeyMismatch,
    /// The validated-token assertion does not match the exact presented token.
    TokenIdentityMismatch,
    /// The verifier clock is unavailable.
    ClockUnavailable,
    /// The failure did not map to another stable public category.
    InternalFailure,
}

/// Host-attested verifier request accepted by the application service.
///
/// The token fields are not self-authenticating. A process transport must
/// authenticate its peer before constructing or forwarding this value.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequest {
    /// Protocol version. Must equal `VERIFIER_PROTOCOL_VERSION`.
    pub version: u16,
    /// Effective external HTTP method observed by the trusted host adapter.
    pub method: String,
    /// Trusted normalized external HTTP(S) target used for `DPoP` htu comparison.
    pub target: String,
    /// Exact access credential bytes represented as a UTF-8 string.
    pub access_token: String,
    /// Exactly one `DPoP` compact proof/header value.
    pub dpop_proof: String,
    /// Trusted cnf.jkt from validation of the exact access credential.
    pub confirmation_jkt: Option<String>,
}

/// Sender-binding evidence returned after complete `DPoP` and token-key composition.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedBinding {
    /// RFC 7638 thumbprint of the verified sender key.
    pub key_thumbprint: String,
    /// Proof issue time after freshness validation.
    pub proof_issued_at_unix: i64,
    /// Whether a server-owned nonce was enforced.
    pub nonce_enforced: bool,
    /// Whether atomic replay state was checked.
    pub replay_checked: bool,
}

/// Versioned verifier result.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VerifierResult {
    /// Verification succeeded.
    Verified {
        /// Protocol version.
        version: u16,
        /// Verified sender-binding evidence.
        binding: VerifiedBinding,
    },
    /// Verification failed closed.
    Rejected {
        /// Protocol version.
        version: u16,
        /// Stable failure class.
        failure: FailureClass,
        /// Current server nonce when retry with a fresh proof is permitted.
        #[serde(skip_serializing_if = "Option::is_none")]
        dpop_nonce: Option<String>,
    },
}

impl VerifierResult {
    /// Creates a stable rejected result without reflecting secret input.
    #[must_use]
    pub const fn rejected(failure: FailureClass) -> Self {
        Self::Rejected {
            version: VERIFIER_PROTOCOL_VERSION,
            failure,
            dpop_nonce: None,
        }
    }

    fn rejected_with_nonce(failure: FailureClass, dpop_nonce: Option<String>) -> Self {
        Self::Rejected {
            version: VERIFIER_PROTOCOL_VERSION,
            failure,
            dpop_nonce,
        }
    }
}

/// Server-owned nonce policy.
///
/// Wire requests cannot choose this policy or its nonce namespace.
pub enum NoncePolicy {
    /// No nonce has been challenged for this verifier profile.
    Optional,
    /// A nonce is required for the configured protected-resource context.
    Required(NonceContext),
}

/// Transport-neutral verifier application service.
pub struct VerifierApplication<'a, C, R, N> {
    clock: &'a C,
    replay_store: &'a R,
    nonce_store: &'a N,
    nonce_policy: &'a NoncePolicy,
    verification_policy: VerificationPolicy,
}

impl<'a, C, R, N> VerifierApplication<'a, C, R, N>
where
    C: Clock,
    R: ReplayStore,
    N: ServerNonceStore,
{
    /// Creates an application service with injected clock, replay, and nonce capabilities.
    #[must_use]
    pub const fn new(
        clock: &'a C,
        replay_store: &'a R,
        nonce_store: &'a N,
        nonce_policy: &'a NoncePolicy,
        verification_policy: VerificationPolicy,
    ) -> Self {
        Self {
            clock,
            replay_store,
            nonce_store,
            nonce_policy,
            verification_policy,
        }
    }

    /// Verifies one authenticated host request.
    ///
    /// The caller must establish application credential validity before this
    /// method is called. This method verifies only sender binding and exact-token
    /// correlation.
    #[must_use]
    pub fn verify(&self, request: &VerifierRequest) -> VerifierResult {
        if request.version != VERIFIER_PROTOCOL_VERSION {
            return VerifierResult::rejected(FailureClass::UnsupportedVersion);
        }
        if request.access_token.is_empty() || request.dpop_proof.is_empty() {
            return VerifierResult::rejected(FailureClass::MalformedRequest);
        }

        let target = match EffectiveRequestTarget::parse(&request.target) {
            Ok(target) => target,
            Err(error) => return VerifierResult::rejected(map_dpop_error(error)),
        };

        let required_nonce = match self.required_nonce() {
            Ok(nonce) => nonce,
            Err(failure) => return VerifierResult::rejected(failure),
        };
        let challenge = required_nonce
            .as_ref()
            .map(|nonce| nonce.as_header_value().to_owned());

        let mut dpop_request = match DpopRequest::new(&request.method, &target) {
            Ok(value) => value.with_access_token(request.access_token.as_bytes()),
            Err(error) => return VerifierResult::rejected(map_dpop_error(error)),
        };
        if let Some(nonce) = required_nonce.as_ref() {
            dpop_request = dpop_request.with_nonce(nonce);
        }

        let proof = match parse_dpop_header_values(&[request.dpop_proof.as_str()]) {
            Ok(proof) => proof,
            Err(error) => return VerifierResult::rejected(map_dpop_error(error)),
        };
        let dpop_verifier = DpopVerifier::new(self.clock, self.verification_policy);
        let verified_proof = match dpop_verifier.verify(&proof, &dpop_request, self.replay_store) {
            Ok(value) => value,
            Err(error) => {
                let failure = map_dpop_error(error);
                let nonce = matches!(
                    failure,
                    FailureClass::NonceRequired | FailureClass::NonceMismatch
                )
                .then_some(challenge)
                .flatten();
                return VerifierResult::rejected_with_nonce(failure, nonce);
            }
        };

        let validated = match HostValidatedToken::from_equivalent_host_validator(
            request.access_token.as_bytes(),
            request.confirmation_jkt.as_deref(),
        ) {
            Ok(validated) => validated,
            Err(error) => return VerifierResult::rejected(map_oauth_error(error)),
        };
        let binding = match compose_sender_binding(
            &verified_proof,
            request.access_token.as_bytes(),
            &validated,
        ) {
            Ok(binding) => binding,
            Err(error) => return VerifierResult::rejected(map_oauth_error(error)),
        };

        VerifierResult::Verified {
            version: VERIFIER_PROTOCOL_VERSION,
            binding: VerifiedBinding {
                key_thumbprint: binding.key_thumbprint().to_base64url(),
                proof_issued_at_unix: binding.proof_issued_at_unix(),
                nonce_enforced: binding.nonce_enforced(),
                replay_checked: binding.replay_checked(),
            },
        }
    }

    fn required_nonce(&self) -> Result<Option<keylix_dpop::DpopNonce>, FailureClass> {
        match self.nonce_policy {
            NoncePolicy::Optional => Ok(None),
            NoncePolicy::Required(context) => match self.nonce_store.expected_nonce(context) {
                Ok(Some(nonce)) => Ok(Some(nonce)),
                Ok(None) => self
                    .nonce_store
                    .issue_nonce(context)
                    .map(Some)
                    .map_err(|_| FailureClass::NonceStateUnavailable),
                Err(_) => Err(FailureClass::NonceStateUnavailable),
            },
        }
    }
}

fn map_dpop_error(error: DpopError) -> FailureClass {
    match error {
        DpopError::MissingProof
        | DpopError::AmbiguousProof
        | DpopError::MalformedProof
        | DpopError::ProofTooLarge
        | DpopError::UnsupportedAlgorithm
        | DpopError::UnsupportedKey
        | DpopError::InvalidSignature => FailureClass::InvalidProof,
        DpopError::MethodMismatch => FailureClass::MethodMismatch,
        DpopError::TargetMismatch | DpopError::InvalidRequestTarget => FailureClass::TargetMismatch,
        DpopError::ProofExpired => FailureClass::StaleProof,
        DpopError::ProofFromFuture => FailureClass::FutureProof,
        DpopError::AccessTokenHashMissing | DpopError::AccessTokenHashMismatch => {
            FailureClass::TokenHashMismatch
        }
        DpopError::NonceRequired => FailureClass::NonceRequired,
        DpopError::NonceMismatch => FailureClass::NonceMismatch,
        DpopError::ReplayDetected => FailureClass::Replay,
        DpopError::ReplayStoreUnavailable => FailureClass::ReplayStoreUnavailable,
        DpopError::ClockUnavailable => FailureClass::ClockUnavailable,
        DpopError::InvalidMethod | DpopError::InvalidPolicy => FailureClass::MalformedRequest,
        _ => FailureClass::InternalFailure,
    }
}

fn map_oauth_error(error: OAuthDpopError) -> FailureClass {
    match error {
        OAuthDpopError::TokenIdentityMismatch => FailureClass::TokenIdentityMismatch,
        OAuthDpopError::TokenBindingMissing => FailureClass::TokenBindingMissing,
        OAuthDpopError::TokenBindingMalformed => FailureClass::TokenBindingMalformed,
        OAuthDpopError::TokenBindingMismatch | OAuthDpopError::ProofKeyContinuityMismatch => {
            FailureClass::ConfirmationKeyMismatch
        }
        OAuthDpopError::ProofNotAccessTokenBound => FailureClass::TokenHashMismatch,
        OAuthDpopError::Dpop(error) => map_dpop_error(error),
        _ => FailureClass::InternalFailure,
    }
}

/// Failure while authenticating or framing the local IPC peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpcFailure {
    /// Outer envelope is malformed or exceeds the supported contract.
    MalformedEnvelope,
    /// Peer identity, response correlation, or message authentication failed.
    UnauthorizedPeer,
    /// A fresh request-correlation value could not be generated.
    EntropyUnavailable,
}

const IPC_CORRELATION_BYTES: usize = 32;

/// A freshly sealed verifier request.
///
/// The correlation value is intentionally private. Clients retain this value
/// until the matching response is authenticated, preventing an old response
/// from being substituted for a different verification attempt.
pub struct SealedIpcRequest {
    frame: Vec<u8>,
    peer_id: String,
    correlation: [u8; IPC_CORRELATION_BYTES],
}

impl SealedIpcRequest {
    /// Returns the authenticated request frame to send over the local transport.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.frame
    }
}

/// Successfully authenticated local IPC request.
pub struct AuthenticatedIpcRequest {
    peer_id: String,
    correlation: [u8; IPC_CORRELATION_BYTES],
    payload: Vec<u8>,
}

impl AuthenticatedIpcRequest {
    /// Returns the allowlisted peer identity.
    #[must_use]
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Returns the authenticated inner request bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerConfigDocument {
    schema_version: u16,
    peers: Vec<PeerConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerConfig {
    id: String,
    secret_base64url: String,
}

struct PeerCredential {
    id: String,
    key: hmac::Key,
}

/// Bounded allowlist of HMAC-authenticated local verifier peers.
pub struct PeerCredentialSet {
    peers: Vec<PeerCredential>,
}

impl PeerCredentialSet {
    /// Parses an owner-protected peer credential document.
    ///
    /// # Errors
    ///
    /// Returns `IpcFailure` when the document is malformed, oversized, has duplicate
    /// peers, or contains a non-canonical 256-bit peer secret.
    pub fn from_json(input: &[u8]) -> Result<Self, IpcFailure> {
        const MAX_CREDENTIAL_DOCUMENT_BYTES: usize = 16 * 1024;
        const MAX_PEERS: usize = 16;
        if input.is_empty() || input.len() > MAX_CREDENTIAL_DOCUMENT_BYTES {
            return Err(IpcFailure::MalformedEnvelope);
        }
        let document: PeerConfigDocument =
            serde_json::from_slice(input).map_err(|_| IpcFailure::MalformedEnvelope)?;
        if document.schema_version != VERIFIER_PROTOCOL_VERSION
            || document.peers.is_empty()
            || document.peers.len() > MAX_PEERS
        {
            return Err(IpcFailure::MalformedEnvelope);
        }

        let mut peers = Vec::with_capacity(document.peers.len());
        for peer in document.peers {
            if !valid_peer_id(&peer.id)
                || peers
                    .iter()
                    .any(|known: &PeerCredential| known.id == peer.id)
            {
                return Err(IpcFailure::MalformedEnvelope);
            }
            let secret = URL_SAFE_NO_PAD
                .decode(&peer.secret_base64url)
                .map_err(|_| IpcFailure::MalformedEnvelope)?;
            if secret.len() != 32 || URL_SAFE_NO_PAD.encode(&secret) != peer.secret_base64url {
                return Err(IpcFailure::MalformedEnvelope);
            }
            peers.push(PeerCredential {
                id: peer.id,
                key: hmac::Key::new(hmac::HMAC_SHA256, &secret),
            });
        }
        Ok(Self { peers })
    }

    /// Authenticates a request envelope before its inner host attestation is decoded.
    ///
    /// # Errors
    ///
    /// Returns `IpcFailure` for malformed envelopes, unknown peers, invalid MACs,
    /// or oversized decoded payloads.
    pub fn open_request(&self, input: &[u8]) -> Result<AuthenticatedIpcRequest, IpcFailure> {
        self.open(input, b"keylix-verifier-request-v1\0")
    }

    /// Seals a response for the exact authenticated request.
    ///
    /// # Errors
    ///
    /// Returns `IpcFailure` when the peer is unknown or the payload is oversized.
    pub fn seal_response(
        &self,
        request: &AuthenticatedIpcRequest,
        payload: &[u8],
    ) -> Result<Vec<u8>, IpcFailure> {
        self.seal(
            request.peer_id(),
            &request.correlation,
            payload,
            b"keylix-verifier-response-v1\0",
        )
    }

    /// Seals a request with a fresh correlation value.
    ///
    /// # Errors
    ///
    /// Returns `IpcFailure` when the peer is unknown, the payload is oversized, or
    /// secure randomness is unavailable.
    pub fn seal_request(
        &self,
        peer_id: &str,
        payload: &[u8],
    ) -> Result<SealedIpcRequest, IpcFailure> {
        let mut correlation = [0_u8; IPC_CORRELATION_BYTES];
        SystemRandom::new()
            .fill(&mut correlation)
            .map_err(|_| IpcFailure::EntropyUnavailable)?;
        let frame = self.seal(
            peer_id,
            &correlation,
            payload,
            b"keylix-verifier-request-v1\0",
        )?;
        Ok(SealedIpcRequest {
            frame,
            peer_id: peer_id.to_owned(),
            correlation,
        })
    }

    /// Authenticates a response and binds it to the exact sealed request.
    ///
    /// The request value is consumed so the Rust adapter cannot accidentally
    /// authenticate more than one response against one correlation value.
    ///
    /// # Errors
    ///
    /// Returns `IpcFailure` for malformed envelopes, unknown peers, invalid MACs,
    /// mismatched request correlation, or oversized decoded payloads.
    #[allow(clippy::needless_pass_by_value)]
    pub fn open_response_for_request(
        &self,
        request: SealedIpcRequest,
        input: &[u8],
    ) -> Result<AuthenticatedIpcRequest, IpcFailure> {
        let response = self.open(input, b"keylix-verifier-response-v1\0")?;
        if response.peer_id != request.peer_id || response.correlation != request.correlation {
            return Err(IpcFailure::UnauthorizedPeer);
        }
        Ok(response)
    }

    fn open(&self, input: &[u8], domain: &[u8]) -> Result<AuthenticatedIpcRequest, IpcFailure> {
        if input.is_empty() || input.len() > MAX_VERIFIER_PAYLOAD_BYTES * 2 {
            return Err(IpcFailure::MalformedEnvelope);
        }
        let envelope: WireEnvelope =
            serde_json::from_slice(input).map_err(|_| IpcFailure::MalformedEnvelope)?;
        if envelope.version != VERIFIER_PROTOCOL_VERSION || !valid_peer_id(&envelope.peer_id) {
            return Err(IpcFailure::MalformedEnvelope);
        }
        let correlation = URL_SAFE_NO_PAD
            .decode(&envelope.correlation_base64url)
            .map_err(|_| IpcFailure::MalformedEnvelope)?;
        let correlation: [u8; IPC_CORRELATION_BYTES] = correlation
            .try_into()
            .map_err(|_| IpcFailure::MalformedEnvelope)?;
        if URL_SAFE_NO_PAD.encode(correlation) != envelope.correlation_base64url {
            return Err(IpcFailure::MalformedEnvelope);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(&envelope.payload_base64url)
            .map_err(|_| IpcFailure::MalformedEnvelope)?;
        if payload.is_empty() || payload.len() > MAX_VERIFIER_PAYLOAD_BYTES {
            return Err(IpcFailure::MalformedEnvelope);
        }
        let mac = URL_SAFE_NO_PAD
            .decode(&envelope.mac_base64url)
            .map_err(|_| IpcFailure::MalformedEnvelope)?;
        if mac.len() != 32 || URL_SAFE_NO_PAD.encode(&mac) != envelope.mac_base64url {
            return Err(IpcFailure::MalformedEnvelope);
        }
        let peer = self
            .peers
            .iter()
            .find(|candidate| candidate.id == envelope.peer_id)
            .ok_or(IpcFailure::UnauthorizedPeer)?;
        verify_mac(&peer.key, domain, &peer.id, &correlation, &payload, &mac)
            .map_err(|_| IpcFailure::UnauthorizedPeer)?;
        Ok(AuthenticatedIpcRequest {
            peer_id: peer.id.clone(),
            correlation,
            payload,
        })
    }

    fn seal(
        &self,
        peer_id: &str,
        correlation: &[u8; IPC_CORRELATION_BYTES],
        payload: &[u8],
        domain: &[u8],
    ) -> Result<Vec<u8>, IpcFailure> {
        if payload.is_empty() || payload.len() > MAX_VERIFIER_PAYLOAD_BYTES {
            return Err(IpcFailure::MalformedEnvelope);
        }
        let peer = self
            .peers
            .iter()
            .find(|candidate| candidate.id == peer_id)
            .ok_or(IpcFailure::UnauthorizedPeer)?;
        let mac = calculate_mac(&peer.key, domain, peer_id, correlation, payload);
        let envelope = WireEnvelope {
            version: VERIFIER_PROTOCOL_VERSION,
            peer_id: peer_id.to_owned(),
            correlation_base64url: URL_SAFE_NO_PAD.encode(correlation),
            payload_base64url: URL_SAFE_NO_PAD.encode(payload),
            mac_base64url: URL_SAFE_NO_PAD.encode(mac.as_ref()),
        };
        serde_json::to_vec(&envelope).map_err(|_| IpcFailure::MalformedEnvelope)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope {
    version: u16,
    peer_id: String,
    correlation_base64url: String,
    payload_base64url: String,
    mac_base64url: String,
}

fn valid_peer_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn calculate_mac(
    key: &hmac::Key,
    domain: &[u8],
    peer_id: &str,
    correlation: &[u8; IPC_CORRELATION_BYTES],
    payload: &[u8],
) -> hmac::Tag {
    let mut context = hmac::Context::with_key(key);
    context.update(domain);
    context.update(peer_id.as_bytes());
    context.update(b"\0");
    context.update(correlation);
    context.update(payload);
    context.sign()
}

fn verify_mac(
    key: &hmac::Key,
    domain: &[u8],
    peer_id: &str,
    correlation: &[u8; IPC_CORRELATION_BYTES],
    payload: &[u8],
    mac: &[u8],
) -> Result<(), aws_lc_rs::error::Unspecified> {
    let mut input =
        Vec::with_capacity(domain.len() + peer_id.len() + 1 + correlation.len() + payload.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(peer_id.as_bytes());
    input.push(0);
    input.extend_from_slice(correlation);
    input.extend_from_slice(payload);
    hmac::verify(key, &input, mac)
}

#[cfg(test)]
mod tests {
    use keylix_dpop::{
        AwsLcP256Signer, Clock, DpopPortError, DpopProofBuilder, DpopRequest, DpopSigner,
        EffectiveRequestTarget, InMemoryReplayStore, InMemoryServerNonceStore,
        RandomNonceGenerator, RandomProofIdGenerator,
    };

    use super::*;

    #[derive(Clone, Copy)]
    struct FixedClock(i64);

    impl Clock for FixedClock {
        fn unix_seconds(&self) -> Result<i64, DpopPortError> {
            Ok(self.0)
        }
    }

    fn request_for(
        signer: &AwsLcP256Signer,
        proof_clock: FixedClock,
        method: &str,
        target_value: &str,
        token: &str,
    ) -> Result<VerifierRequest, DpopError> {
        let target = EffectiveRequestTarget::parse(target_value)?;
        let ids = RandomProofIdGenerator;
        let proof_request = DpopRequest::new(method, &target)?.with_access_token(token.as_bytes());
        let proof = DpopProofBuilder::new(signer, &proof_clock, &ids).build(&proof_request)?;
        Ok(VerifierRequest {
            version: VERIFIER_PROTOCOL_VERSION,
            method: method.to_owned(),
            target: target_value.to_owned(),
            access_token: token.to_owned(),
            dpop_proof: proof.as_header_value().to_owned(),
            confirmation_jkt: Some(signer.public_jwk().thumbprint().to_base64url()),
        })
    }

    #[test]
    fn valid_sender_binding_succeeds_and_replay_fails_closed() -> Result<(), DpopError> {
        let signer = AwsLcP256Signer::generate()?;
        let clock = FixedClock(1_700_000_000);
        let replay = InMemoryReplayStore::new(clock, 16)?;
        let nonces = InMemoryServerNonceStore::new(RandomNonceGenerator, 4)?;
        let policy = NoncePolicy::Optional;
        let app = VerifierApplication::new(
            &clock,
            &replay,
            &nonces,
            &policy,
            VerificationPolicy::default(),
        );
        let request = request_for(
            &signer,
            clock,
            "GET",
            "https://operator.example/v1/health",
            "credential-a",
        )?;

        assert!(matches!(
            app.verify(&request),
            VerifierResult::Verified { .. }
        ));
        assert_eq!(
            app.verify(&request),
            VerifierResult::rejected(FailureClass::Replay)
        );
        Ok(())
    }

    #[test]
    fn method_target_key_and_freshness_fail_closed() -> Result<(), DpopError> {
        let signer = AwsLcP256Signer::generate()?;
        let other_signer = AwsLcP256Signer::generate()?;
        let proof_clock = FixedClock(1_700_000_000);
        let app_clock = FixedClock(1_700_000_000);
        let replay = InMemoryReplayStore::new(app_clock, 32)?;
        let nonces = InMemoryServerNonceStore::new(RandomNonceGenerator, 4)?;
        let policy = NoncePolicy::Optional;
        let app = VerifierApplication::new(
            &app_clock,
            &replay,
            &nonces,
            &policy,
            VerificationPolicy::default(),
        );
        let base = request_for(
            &signer,
            proof_clock,
            "GET",
            "https://operator.example/v1/health",
            "credential-a",
        )?;

        let mut wrong_method = base.clone();
        wrong_method.method = "POST".to_owned();
        assert_eq!(
            app.verify(&wrong_method),
            VerifierResult::rejected(FailureClass::MethodMismatch)
        );

        let mut wrong_target = base.clone();
        wrong_target.target = "https://operator.example/v1/other".to_owned();
        assert_eq!(
            app.verify(&wrong_target),
            VerifierResult::rejected(FailureClass::TargetMismatch)
        );

        let mut wrong_key = request_for(
            &signer,
            proof_clock,
            "GET",
            "https://operator.example/v1/key",
            "credential-b",
        )?;
        wrong_key.confirmation_jkt = Some(other_signer.public_jwk().thumbprint().to_base64url());
        assert_eq!(
            app.verify(&wrong_key),
            VerifierResult::rejected(FailureClass::ConfirmationKeyMismatch)
        );

        let stale_clock = FixedClock(1_700_000_301);
        let stale_replay = InMemoryReplayStore::new(stale_clock, 8)?;
        let stale_nonces = InMemoryServerNonceStore::new(RandomNonceGenerator, 2)?;
        let stale_app = VerifierApplication::new(
            &stale_clock,
            &stale_replay,
            &stale_nonces,
            &policy,
            VerificationPolicy::default(),
        );
        let stale = request_for(
            &signer,
            proof_clock,
            "GET",
            "https://operator.example/v1/stale",
            "credential-c",
        )?;
        assert_eq!(
            stale_app.verify(&stale),
            VerifierResult::rejected(FailureClass::StaleProof)
        );

        let future_clock = FixedClock(1_699_999_699);
        let future_replay = InMemoryReplayStore::new(future_clock, 8)?;
        let future_nonces = InMemoryServerNonceStore::new(RandomNonceGenerator, 2)?;
        let future_app = VerifierApplication::new(
            &future_clock,
            &future_replay,
            &future_nonces,
            &policy,
            VerificationPolicy::default(),
        );
        let future = request_for(
            &signer,
            proof_clock,
            "GET",
            "https://operator.example/v1/future",
            "credential-d",
        )?;
        assert_eq!(
            future_app.verify(&future),
            VerifierResult::rejected(FailureClass::FutureProof)
        );
        Ok(())
    }

    #[test]
    fn durable_replay_store_serializes_same_proof_concurrently() -> Result<(), DpopError> {
        use std::{
            fs,
            os::unix::fs::{MetadataExt as _, PermissionsExt as _},
            thread,
            time::{SystemTime, UNIX_EPOCH},
        };

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DpopError::ReplayStoreUnavailable)?
            .as_nanos();
        let directory = std::env::current_dir()
            .map_err(|_| DpopError::ReplayStoreUnavailable)?
            .join(format!(
                "keylix-verifier-concurrent-{}-{nanos}",
                std::process::id()
            ));
        fs::create_dir(&directory).map_err(|_| DpopError::ReplayStoreUnavailable)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| DpopError::ReplayStoreUnavailable)?;
        let trusted_uid = fs::metadata(&directory)
            .map_err(|_| DpopError::ReplayStoreUnavailable)?
            .uid();

        let signer = AwsLcP256Signer::generate()?;
        let clock = FixedClock(1_700_000_000);
        let replay = FileReplayStore::new(clock, &directory, trusted_uid, 8)
            .map_err(|_| DpopError::ReplayStoreUnavailable)?;
        let nonces = InMemoryServerNonceStore::new(RandomNonceGenerator, 2)?;
        let policy = NoncePolicy::Optional;
        {
            let app = VerifierApplication::new(
                &clock,
                &replay,
                &nonces,
                &policy,
                VerificationPolicy::default(),
            );
            let request = request_for(
                &signer,
                clock,
                "GET",
                "https://operator.example/v1/concurrent",
                "credential-concurrent",
            )?;

            let (first, second) = thread::scope(|scope| -> Result<_, DpopError> {
                let first = scope.spawn(|| app.verify(&request));
                let second = scope.spawn(|| app.verify(&request));
                Ok((
                    first
                        .join()
                        .map_err(|_| DpopError::ReplayStoreUnavailable)?,
                    second
                        .join()
                        .map_err(|_| DpopError::ReplayStoreUnavailable)?,
                ))
            })?;

            let expected_replay = VerifierResult::rejected(FailureClass::Replay);
            let verified_count = usize::from(matches!(first, VerifierResult::Verified { .. }))
                + usize::from(matches!(second, VerifierResult::Verified { .. }));
            let replay_count =
                usize::from(first == expected_replay) + usize::from(second == expected_replay);
            assert_eq!(verified_count, 1);
            assert_eq!(replay_count, 1);
        }

        drop(replay);
        fs::remove_dir_all(directory).map_err(|_| DpopError::ReplayStoreUnavailable)?;
        Ok(())
    }

    #[test]
    fn durable_replay_store_rejects_proof_after_reopen() -> Result<(), DpopError> {
        use std::{
            fs,
            os::unix::fs::{MetadataExt as _, PermissionsExt as _},
            sync::atomic::{AtomicU64, Ordering},
            time::{SystemTime, UNIX_EPOCH},
        };

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let suffix = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DpopError::ReplayStoreUnavailable)?
            .as_nanos();
        let directory = std::env::current_dir()
            .map_err(|_| DpopError::ReplayStoreUnavailable)?
            .join(format!(
                "keylix-verifier-replay-{}-{nanos}-{suffix}",
                std::process::id()
            ));
        fs::create_dir(&directory).map_err(|_| DpopError::ReplayStoreUnavailable)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| DpopError::ReplayStoreUnavailable)?;
        let trusted_uid = fs::metadata(&directory)
            .map_err(|_| DpopError::ReplayStoreUnavailable)?
            .uid();

        let signer = AwsLcP256Signer::generate()?;
        let clock = FixedClock(1_700_000_000);
        let nonces = InMemoryServerNonceStore::new(RandomNonceGenerator, 2)?;
        let policy = NoncePolicy::Optional;
        let request = request_for(
            &signer,
            clock,
            "GET",
            "https://operator.example/v1/restart",
            "credential-restart",
        )?;

        {
            let replay = FileReplayStore::new(clock, &directory, trusted_uid, 8)
                .map_err(|_| DpopError::ReplayStoreUnavailable)?;
            let app = VerifierApplication::new(
                &clock,
                &replay,
                &nonces,
                &policy,
                VerificationPolicy::default(),
            );
            assert!(matches!(
                app.verify(&request),
                VerifierResult::Verified { .. }
            ));
        }
        {
            let replay = FileReplayStore::new(clock, &directory, trusted_uid, 8)
                .map_err(|_| DpopError::ReplayStoreUnavailable)?;
            let app = VerifierApplication::new(
                &clock,
                &replay,
                &nonces,
                &policy,
                VerificationPolicy::default(),
            );
            assert_eq!(
                app.verify(&request),
                VerifierResult::rejected(FailureClass::Replay)
            );
        }

        fs::remove_dir_all(directory).map_err(|_| DpopError::ReplayStoreUnavailable)?;
        Ok(())
    }

    #[test]
    fn ipc_authentication_precedes_inner_request_decoding() -> Result<(), IpcFailure> {
        let credentials = br#"{"schema_version":1,"peers":[{"id":"operator","secret_base64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}"#;
        let peers = PeerCredentialSet::from_json(credentials)?;
        let invalid_inner = b"this is intentionally not verifier JSON";
        let envelope = peers.seal_request("operator", invalid_inner)?;
        let opened = peers.open_request(envelope.as_bytes())?;
        assert_eq!(opened.peer_id(), "operator");
        assert_eq!(opened.payload(), invalid_inner);

        let mut tampered = envelope.as_bytes().to_vec();
        let index = tampered.len().saturating_sub(8);
        tampered[index] ^= 1;
        assert!(peers.open_request(&tampered).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_response_is_bound_to_exact_request() -> Result<(), IpcFailure> {
        let credentials = br#"{"schema_version":1,"peers":[{"id":"operator","secret_base64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}"#;
        let peers = PeerCredentialSet::from_json(credentials)?;
        let first = peers.seal_request("operator", b"same verifier payload")?;
        let second = peers.seal_request("operator", b"same verifier payload")?;
        assert_ne!(first.as_bytes(), second.as_bytes());

        let authenticated = peers.open_request(first.as_bytes())?;
        let response = peers.seal_response(&authenticated, b"verified")?;

        assert!(peers.open_response_for_request(second, &response).is_err());
        let opened = peers.open_response_for_request(first, &response)?;
        assert_eq!(opened.payload(), b"verified");
        Ok(())
    }
}
