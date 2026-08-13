use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::{
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use keylix_core::PublicP256Jwk;

use crate::{DpopError, DpopPortError};

const MAX_PROOF_ID_BYTES: usize = 256;
const MAX_NONCE_BYTES: usize = 1_024;
const GENERATED_PROOF_ID_BYTES: usize = 16;

/// An opaque `DPoP` proof identifier (`jti`).
///
/// Raw values are intentionally omitted from `Debug` output because they are
/// attacker-controlled/high-cardinality request identifiers.
#[derive(Clone, PartialEq, Eq)]
pub struct ProofId(String);

impl ProofId {
    /// Creates a bounded non-empty proof identifier.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::ProofIdUnavailable`] when the identifier is empty or
    /// exceeds the protocol bound.
    pub fn new(value: impl Into<String>) -> Result<Self, DpopError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PROOF_ID_BYTES {
            return Err(DpopError::ProofIdUnavailable);
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProofId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProofId([redacted])")
    }
}

/// An opaque server-provided `DPoP` nonce.
#[derive(Clone, PartialEq, Eq)]
pub struct DpopNonce(String);

impl DpopNonce {
    /// Creates a bounded non-empty nonce value.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::MalformedProof`] for an empty or oversized nonce.
    pub fn new(value: impl Into<String>) -> Result<Self, DpopError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_NONCE_BYTES {
            return Err(DpopError::MalformedProof);
        }
        Ok(Self(value))
    }

    /// Returns the nonce value for explicit `DPoP-Nonce` header emission.
    ///
    /// This is an explicit credential-bearing accessor; ordinary `Debug`
    /// formatting remains redacted.
    #[must_use]
    pub fn as_header_value(&self) -> &str {
        &self.0
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DpopNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopNonce([redacted])")
    }
}

/// A fixed-size digest identifying a proof within its replay scope.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplayKey([u8; 32]);

impl ReplayKey {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-size replay-store key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ReplayKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReplayKey([redacted])")
    }
}

/// Result of an atomic replay-store check-and-record operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayStatus {
    /// The replay key was not present and has now been recorded atomically.
    Fresh,
    /// The replay key was already present for its active acceptance lifetime.
    Replay,
}

/// Capability used by the proof builder to sign ES256 JWS signing input.
///
/// Implementations may delegate to software, a TPM/HSM, an OS keystore, KMS,
/// or another reviewed provider. Private-key extraction is never required by
/// this interface.
pub trait DpopSigner: Send + Sync {
    /// Returns the public P-256 JWK corresponding to the signing capability.
    fn public_jwk(&self) -> &PublicP256Jwk;

    /// Signs the exact compact-JWS signing input.
    ///
    /// The builder independently requires and verifies a 64-byte fixed-format
    /// ES256 signature before emitting a proof.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when the signing provider cannot sign.
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, DpopPortError>;
}

/// Injectable source of Unix time in seconds.
pub trait Clock: Send + Sync {
    /// Returns the current Unix timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when current time cannot be established.
    fn unix_seconds(&self) -> Result<i64, DpopPortError>;
}

/// Injectable source of fresh `DPoP` proof identifiers.
pub trait ProofIdGenerator: Send + Sync {
    /// Generates a fresh collision-resistant proof identifier.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when a fresh identifier cannot be produced.
    fn generate(&self) -> Result<ProofId, DpopPortError>;
}

/// Atomic replay-state capability used by strict proof verification.
pub trait ReplayStore: Send + Sync {
    /// Atomically checks and records `key` until the supplied Unix expiry.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when the store cannot provide its documented
    /// atomicity/consistency guarantee. Strict verification fails closed.
    fn check_and_record(
        &self,
        key: &ReplayKey,
        expires_at_unix: i64,
    ) -> Result<ReplayStatus, DpopPortError>;
}

/// System clock implementation for normal native deployments.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DpopPortError)?;
        i64::try_from(duration.as_secs()).map_err(|_| DpopPortError)
    }
}

/// Cryptographically strong reference proof-ID generator using 128 random bits.
#[derive(Clone, Copy, Debug, Default)]
pub struct RandomProofIdGenerator;

impl ProofIdGenerator for RandomProofIdGenerator {
    fn generate(&self) -> Result<ProofId, DpopPortError> {
        let random = SystemRandom::new();
        let mut bytes = [0_u8; GENERATED_PROOF_ID_BYTES];
        random.fill(&mut bytes).map_err(|_| DpopPortError)?;
        ProofId::new(URL_SAFE_NO_PAD.encode(bytes)).map_err(|_| DpopPortError)
    }
}

/// Reference in-process P-256 software signer backed by `aws-lc-rs`.
pub struct AwsLcP256Signer {
    key_pair: EcdsaKeyPair,
    public_jwk: PublicP256Jwk,
}

impl AwsLcP256Signer {
    /// Generates a fresh in-process P-256 signing key.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::SignerFailure`] when key generation or public-key
    /// conversion fails.
    pub fn generate() -> Result<Self, DpopError> {
        let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
            .map_err(|_| DpopError::SignerFailure)?;
        let public_key = key_pair.public_key().as_ref();
        if public_key.len() != 65 || public_key.first().copied() != Some(0x04) {
            return Err(DpopError::SignerFailure);
        }
        let x = URL_SAFE_NO_PAD.encode(&public_key[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&public_key[33..65]);
        let jwk_json = format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}"#);
        let public_jwk =
            PublicP256Jwk::from_json(&jwk_json).map_err(|_| DpopError::SignerFailure)?;
        Ok(Self {
            key_pair,
            public_jwk,
        })
    }
}

impl DpopSigner for AwsLcP256Signer {
    fn public_jwk(&self) -> &PublicP256Jwk {
        &self.public_jwk
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, DpopPortError> {
        let random = SystemRandom::new();
        let signature = self
            .key_pair
            .sign(&random, signing_input)
            .map_err(|_| DpopPortError)?;
        Ok(signature.as_ref().to_vec())
    }
}

impl fmt::Debug for AwsLcP256Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AwsLcP256Signer([private signing capability])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_proof_ids_are_bounded_and_distinct() -> Result<(), DpopPortError> {
        let generator = RandomProofIdGenerator;
        let first = generator.generate()?;
        let second = generator.generate()?;
        assert_ne!(first, second);
        assert!(first.as_str().len() <= MAX_PROOF_ID_BYTES);
        Ok(())
    }

    #[test]
    fn sensitive_port_types_redact_debug_values() -> Result<(), DpopError> {
        let proof_id = ProofId::new("distinctive-jti")?;
        let nonce = DpopNonce::new("distinctive-nonce")?;
        let replay = ReplayKey::new([0x5a; 32]);
        assert!(!format!("{proof_id:?}").contains("distinctive-jti"));
        assert!(!format!("{nonce:?}").contains("distinctive-nonce"));
        assert!(!format!("{replay:?}").contains("5a"));
        Ok(())
    }
}
