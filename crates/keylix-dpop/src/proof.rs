use core::fmt;
use std::collections::BTreeSet;

use aws_lc_rs::{
    digest,
    signature::{ECDSA_P256_SHA256_FIXED, ParsedPublicKey},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use keylix_core::{JwkThumbprint, PublicP256Jwk};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, Error as _, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;

use crate::{
    Clock, DpopError, DpopNonce, DpopRequest, DpopSigner, EffectiveRequestTarget, ProofIdGenerator,
    ReplayKey, ReplayStatus, ReplayStore,
};

const MAX_PROOF_BYTES: usize = 8_192;
const MAX_HEADER_BYTES: usize = 2_048;
const MAX_PAYLOAD_BYTES: usize = 4_096;
const MAX_SIGNATURE_BYTES: usize = 128;
const MAX_JTI_BYTES: usize = 256;
const MAX_HTM_BYTES: usize = 64;
const MAX_HTU_BYTES: usize = 2_048;
const MAX_NONCE_BYTES: usize = 1_024;
const SHA256_BASE64URL_BYTES: usize = 43;
const ES256_SIGNATURE_BYTES: usize = 64;
const SEC1_PUBLIC_KEY_BYTES: usize = 65;
const P256_COORDINATE_BYTES: usize = 32;

/// A freshly constructed compact `DPoP` proof suitable for the HTTP `DPoP` header.
pub struct DpopProof(String);

impl DpopProof {
    /// Returns the complete proof value for explicit HTTP header use.
    #[must_use]
    pub fn as_header_value(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DpopProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopProof([redacted])")
    }
}

/// Parsed but not trusted compact `DPoP` proof state.
///
/// Parsing establishes bounded compact-JWS/JSON structure and a valid public
/// P-256 JWK. It does not establish signature validity, request binding,
/// freshness, nonce, access-token hash, or replay status.
pub struct UnverifiedDpopProof {
    encoded_header: String,
    encoded_payload: String,
    signature: Vec<u8>,
    header: HeaderWire,
    claims: ClaimsWire,
    public_jwk: PublicP256Jwk,
}

impl UnverifiedDpopProof {
    /// Parses a bounded compact `DPoP` JWS without granting any verified trust state.
    ///
    /// # Errors
    ///
    /// Returns a stable [`DpopError`] category for malformed framing, encoding,
    /// JSON, duplicate members, required fields, or unsupported proof-key input.
    pub fn parse(input: &str) -> Result<Self, DpopError> {
        if input.is_empty() {
            return Err(DpopError::MalformedProof);
        }
        if input.len() > MAX_PROOF_BYTES {
            return Err(DpopError::ProofTooLarge);
        }

        let mut parts = input.split('.');
        let encoded_header = parts.next().ok_or(DpopError::MalformedProof)?;
        let encoded_payload = parts.next().ok_or(DpopError::MalformedProof)?;
        let encoded_signature = parts.next().ok_or(DpopError::MalformedProof)?;
        if parts.next().is_some()
            || encoded_header.is_empty()
            || encoded_payload.is_empty()
            || encoded_signature.is_empty()
        {
            return Err(DpopError::MalformedProof);
        }

        let header_bytes = decode_segment(encoded_header, MAX_HEADER_BYTES)?;
        let payload_bytes = decode_segment(encoded_payload, MAX_PAYLOAD_BYTES)?;
        let signature = decode_segment(encoded_signature, MAX_SIGNATURE_BYTES)?;
        reject_duplicate_json_members(&header_bytes)?;
        reject_duplicate_json_members(&payload_bytes)?;

        let header: HeaderWire =
            serde_json::from_slice(&header_bytes).map_err(|_| DpopError::MalformedProof)?;
        let claims: ClaimsWire =
            serde_json::from_slice(&payload_bytes).map_err(|_| DpopError::MalformedProof)?;
        validate_claim_shape(&claims)?;

        let jwk_json = serde_json::to_string(&header.jwk).map_err(|_| DpopError::MalformedProof)?;
        let public_jwk =
            PublicP256Jwk::from_json(&jwk_json).map_err(|_| DpopError::UnsupportedKey)?;

        Ok(Self {
            encoded_header: encoded_header.to_owned(),
            encoded_payload: encoded_payload.to_owned(),
            signature,
            header,
            claims,
            public_jwk,
        })
    }
}

impl fmt::Debug for UnverifiedDpopProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnverifiedDpopProof([redacted])")
    }
}

/// Successfully verified RFC 9449 proof state before OAuth token-key composition.
pub struct VerifiedDpopProof {
    key_thumbprint: JwkThumbprint,
    issued_at_unix: i64,
    nonce_enforced: bool,
    replay_checked: bool,
    access_token_hash_verified: bool,
}

impl VerifiedDpopProof {
    /// Returns the verified proof-key thumbprint for explicit downstream binding/evidence use.
    #[must_use]
    pub const fn key_thumbprint(&self) -> JwkThumbprint {
        self.key_thumbprint
    }

    /// Returns the verified proof issue time in Unix seconds.
    #[must_use]
    pub const fn issued_at_unix(&self) -> i64 {
        self.issued_at_unix
    }

    /// Reports whether an expected server nonce was enforced for this verification.
    #[must_use]
    pub const fn nonce_enforced(&self) -> bool {
        self.nonce_enforced
    }

    /// Reports whether the proof passed the atomic replay handoff.
    #[must_use]
    pub const fn replay_checked(&self) -> bool {
        self.replay_checked
    }

    /// Reports whether `ath` was verified against an exact presented access token.
    #[must_use]
    pub const fn access_token_hash_verified(&self) -> bool {
        self.access_token_hash_verified
    }
}

impl fmt::Debug for VerifiedDpopProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDpopProof")
            .field("algorithm", &"ES256")
            .field("key_thumbprint", &"[redacted]")
            .field("issued_at_unix", &self.issued_at_unix)
            .field("nonce_enforced", &self.nonce_enforced)
            .field("replay_checked", &self.replay_checked)
            .field(
                "access_token_hash_verified",
                &self.access_token_hash_verified,
            )
            .finish()
    }
}

/// Explicit proof-freshness policy for strict verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationPolicy {
    max_proof_age_seconds: i64,
    allowed_future_skew_seconds: i64,
}

impl VerificationPolicy {
    /// Creates a freshness policy from non-negative second values.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::InvalidPolicy`] if either value cannot be represented
    /// by the verifier's signed Unix-time arithmetic.
    pub fn new(
        max_proof_age_seconds: u64,
        allowed_future_skew_seconds: u64,
    ) -> Result<Self, DpopError> {
        Ok(Self {
            max_proof_age_seconds: i64::try_from(max_proof_age_seconds)
                .map_err(|_| DpopError::InvalidPolicy)?,
            allowed_future_skew_seconds: i64::try_from(allowed_future_skew_seconds)
                .map_err(|_| DpopError::InvalidPolicy)?,
        })
    }

    /// Returns the maximum accepted proof age in seconds.
    #[must_use]
    pub const fn max_proof_age_seconds(&self) -> i64 {
        self.max_proof_age_seconds
    }

    /// Returns the maximum accepted future clock skew in seconds.
    #[must_use]
    pub const fn allowed_future_skew_seconds(&self) -> i64 {
        self.allowed_future_skew_seconds
    }
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            max_proof_age_seconds: 300,
            allowed_future_skew_seconds: 300,
        }
    }
}

/// RFC 9449 proof builder parameterized by narrow signing, clock, and ID ports.
pub struct DpopProofBuilder<'a, S, C, G> {
    signer: &'a S,
    clock: &'a C,
    proof_ids: &'a G,
}

impl<'a, S, C, G> DpopProofBuilder<'a, S, C, G>
where
    S: DpopSigner,
    C: Clock,
    G: ProofIdGenerator,
{
    /// Creates a proof builder from injected capabilities.
    #[must_use]
    pub const fn new(signer: &'a S, clock: &'a C, proof_ids: &'a G) -> Self {
        Self {
            signer,
            clock,
            proof_ids,
        }
    }

    /// Builds a fresh `DPoP` proof for one HTTP attempt.
    ///
    /// A protected-resource request includes `ath` over the exact token bytes.
    /// A supplied nonce is copied into the proof. Every call obtains a new `jti`.
    /// The signer output is length-checked and independently verified against its
    /// advertised public JWK before the proof is returned.
    ///
    /// # Errors
    ///
    /// Returns a stable [`DpopError`] if time/ID/signing dependencies fail or
    /// emit inconsistent output.
    pub fn build(&self, request: &DpopRequest<'_>) -> Result<DpopProof, DpopError> {
        let issued_at = self
            .clock
            .unix_seconds()
            .map_err(|_| DpopError::ClockUnavailable)?;
        if issued_at <= 0 {
            return Err(DpopError::ClockUnavailable);
        }
        let proof_id = self
            .proof_ids
            .generate()
            .map_err(|_| DpopError::ProofIdUnavailable)?;
        let access_token_hash = request.access_token().map(access_token_hash);
        let nonce = request.nonce().map(DpopNonce::as_str);

        let header = HeaderBuild {
            typ: "dpop+jwt",
            alg: "ES256",
            jwk: self.signer.public_jwk(),
        };
        let claims = ClaimsBuild {
            jti: proof_id.as_str(),
            htm: request.method(),
            htu: request.target().as_str(),
            iat: issued_at,
            ath: access_token_hash.as_deref(),
            nonce,
        };
        let header_json = serde_json::to_vec(&header).map_err(|_| DpopError::SignerFailure)?;
        let claims_json = serde_json::to_vec(&claims).map_err(|_| DpopError::SignerFailure)?;
        let encoded_header = URL_SAFE_NO_PAD.encode(header_json);
        let encoded_payload = URL_SAFE_NO_PAD.encode(claims_json);
        let signing_input = format!("{encoded_header}.{encoded_payload}");
        let signature = self
            .signer
            .sign(signing_input.as_bytes())
            .map_err(|_| DpopError::SignerFailure)?;
        if signature.len() != ES256_SIGNATURE_BYTES {
            return Err(DpopError::SignerFailure);
        }
        verify_es256_signature(
            self.signer.public_jwk(),
            signing_input.as_bytes(),
            &signature,
        )
        .map_err(|_| DpopError::SignerFailure)?;
        let encoded_signature = URL_SAFE_NO_PAD.encode(signature);
        Ok(DpopProof(format!("{signing_input}.{encoded_signature}")))
    }
}

/// Strict `DPoP` verifier parameterized by an injected clock.
pub struct DpopVerifier<'a, C> {
    clock: &'a C,
    policy: VerificationPolicy,
}

impl<'a, C> DpopVerifier<'a, C>
where
    C: Clock,
{
    /// Creates a strict verifier using the supplied freshness policy.
    #[must_use]
    pub const fn new(clock: &'a C, policy: VerificationPolicy) -> Self {
        Self { clock, policy }
    }

    /// Verifies signature, request binding, freshness, optional nonce, `ath`, and replay.
    ///
    /// This method intentionally stops at [`VerifiedDpopProof`]. Trusted OAuth
    /// token validity and `cnf.jkt` composition belong to `keylix-oauth`.
    ///
    /// # Errors
    ///
    /// Returns a stable [`DpopError`] category and never reflects proof, token,
    /// nonce, JWK coordinates, or raw `jti` contents.
    pub fn verify<R>(
        &self,
        proof: &UnverifiedDpopProof,
        request: &DpopRequest<'_>,
        replay_store: &R,
    ) -> Result<VerifiedDpopProof, DpopError>
    where
        R: ReplayStore,
    {
        if proof.header.typ != "dpop+jwt" {
            return Err(DpopError::MalformedProof);
        }
        if proof.header.alg != "ES256" {
            return Err(DpopError::UnsupportedAlgorithm);
        }
        if proof.signature.len() != ES256_SIGNATURE_BYTES {
            return Err(DpopError::InvalidSignature);
        }

        let signing_input = format!("{}.{}", proof.encoded_header, proof.encoded_payload);
        verify_es256_signature(
            &proof.public_jwk,
            signing_input.as_bytes(),
            &proof.signature,
        )?;

        if proof.claims.htm != request.method() {
            return Err(DpopError::MethodMismatch);
        }
        let proof_target = EffectiveRequestTarget::parse(&proof.claims.htu)
            .map_err(|_| DpopError::TargetMismatch)?;
        if proof_target != *request.target() {
            return Err(DpopError::TargetMismatch);
        }

        let now = self
            .clock
            .unix_seconds()
            .map_err(|_| DpopError::ClockUnavailable)?;
        verify_freshness(proof.claims.iat, now, self.policy)?;
        verify_nonce(proof.claims.nonce.as_deref(), request.nonce())?;

        let access_token_hash_verified = match request.access_token() {
            Some(token) => {
                let presented = proof
                    .claims
                    .ath
                    .as_deref()
                    .ok_or(DpopError::AccessTokenHashMissing)?;
                if presented != access_token_hash(token) {
                    return Err(DpopError::AccessTokenHashMismatch);
                }
                true
            }
            None => false,
        };

        let key_thumbprint = proof.public_jwk.thumbprint();
        let replay_key = derive_replay_key(
            key_thumbprint,
            request.method(),
            request.target(),
            &proof.claims.jti,
        )?;
        let expires_at_unix = proof
            .claims
            .iat
            .checked_add(self.policy.max_proof_age_seconds)
            .ok_or(DpopError::InvalidPolicy)?;
        match replay_store
            .check_and_record(&replay_key, expires_at_unix)
            .map_err(|_| DpopError::ReplayStoreUnavailable)?
        {
            ReplayStatus::Fresh => {}
            ReplayStatus::Replay => return Err(DpopError::ReplayDetected),
        }

        Ok(VerifiedDpopProof {
            key_thumbprint,
            issued_at_unix: proof.claims.iat,
            nonce_enforced: request.nonce().is_some(),
            replay_checked: true,
            access_token_hash_verified,
        })
    }
}

/// Parses exactly one HTTP `DPoP` header field value into unverified proof state.
///
/// # Errors
///
/// Returns [`DpopError::MissingProof`] for no value and
/// [`DpopError::AmbiguousProof`] for multiple or comma-joined values.
pub fn parse_dpop_header_values(values: &[&str]) -> Result<UnverifiedDpopProof, DpopError> {
    let [value] = values else {
        return if values.is_empty() {
            Err(DpopError::MissingProof)
        } else {
            Err(DpopError::AmbiguousProof)
        };
    };
    if value.contains(',') {
        return Err(DpopError::AmbiguousProof);
    }
    UnverifiedDpopProof::parse(value)
}

#[derive(Serialize)]
struct HeaderBuild<'a> {
    typ: &'static str,
    alg: &'static str,
    jwk: &'a PublicP256Jwk,
}

#[derive(Serialize)]
struct ClaimsBuild<'a> {
    jti: &'a str,
    htm: &'a str,
    htu: &'a str,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
}

#[derive(Deserialize)]
struct HeaderWire {
    typ: String,
    alg: String,
    jwk: Value,
}

#[derive(Deserialize)]
struct ClaimsWire {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(default)]
    ath: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

fn validate_claim_shape(claims: &ClaimsWire) -> Result<(), DpopError> {
    if claims.jti.is_empty()
        || claims.jti.len() > MAX_JTI_BYTES
        || claims.htm.is_empty()
        || claims.htm.len() > MAX_HTM_BYTES
        || claims.htu.is_empty()
        || claims.htu.len() > MAX_HTU_BYTES
        || claims.iat <= 0
        || claims
            .ath
            .as_ref()
            .is_some_and(|value| value.len() != SHA256_BASE64URL_BYTES)
        || claims
            .nonce
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_NONCE_BYTES)
    {
        return Err(DpopError::MalformedProof);
    }
    Ok(())
}

fn decode_segment(encoded: &str, max_decoded_bytes: usize) -> Result<Vec<u8>, DpopError> {
    if encoded.contains('=') || encoded.len() > max_decoded_bytes.saturating_mul(2) {
        return Err(DpopError::MalformedProof);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| DpopError::MalformedProof)?;
    if decoded.len() > max_decoded_bytes {
        return Err(DpopError::ProofTooLarge);
    }
    Ok(decoded)
}

fn access_token_hash(access_token: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, access_token).as_ref())
}

fn verify_es256_signature(
    jwk: &PublicP256Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), DpopError> {
    if signature.len() != ES256_SIGNATURE_BYTES {
        return Err(DpopError::InvalidSignature);
    }
    let mut point = [0_u8; SEC1_PUBLIC_KEY_BYTES];
    point[0] = 0x04;
    point[1..=P256_COORDINATE_BYTES].copy_from_slice(jwk.x_bytes());
    point[(P256_COORDINATE_BYTES + 1)..].copy_from_slice(jwk.y_bytes());
    let public_key = ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .map_err(|_| DpopError::UnsupportedKey)?;
    public_key
        .verify_sig(signing_input, signature)
        .map_err(|_| DpopError::InvalidSignature)
}

fn verify_freshness(issued_at: i64, now: i64, policy: VerificationPolicy) -> Result<(), DpopError> {
    if issued_at <= 0 {
        return Err(DpopError::MalformedProof);
    }
    let age = i128::from(now) - i128::from(issued_at);
    if age > i128::from(policy.max_proof_age_seconds) {
        return Err(DpopError::ProofExpired);
    }
    let future = i128::from(issued_at) - i128::from(now);
    if future > i128::from(policy.allowed_future_skew_seconds) {
        return Err(DpopError::ProofFromFuture);
    }
    Ok(())
}

fn verify_nonce(presented: Option<&str>, required: Option<&DpopNonce>) -> Result<(), DpopError> {
    let Some(required) = required else {
        return Ok(());
    };
    let presented = presented.ok_or(DpopError::NonceRequired)?;
    if presented != required.as_str() {
        return Err(DpopError::NonceMismatch);
    }
    Ok(())
}

fn derive_replay_key(
    thumbprint: JwkThumbprint,
    method: &str,
    target: &EffectiveRequestTarget,
    jti: &str,
) -> Result<ReplayKey, DpopError> {
    let parts: [&[u8]; 4] = [
        thumbprint.as_bytes(),
        method.as_bytes(),
        target.as_str().as_bytes(),
        jti.as_bytes(),
    ];
    let mut material =
        Vec::with_capacity(32 + method.len() + target.as_str().len() + jti.len() + 32);
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| DpopError::MalformedProof)?;
        material.extend_from_slice(&length.to_be_bytes());
        material.extend_from_slice(part);
    }
    let digest = digest::digest(&digest::SHA256, &material);
    let mut key = [0_u8; 32];
    key.copy_from_slice(digest.as_ref());
    Ok(ReplayKey::new(key))
}

fn reject_duplicate_json_members(input: &[u8]) -> Result<(), DpopError> {
    serde_json::from_slice::<UniqueJson>(input)
        .map(|_| ())
        .map_err(|_| DpopError::MalformedProof)
}

struct UniqueJson;

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueJson)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueJson)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueJson)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueJson)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueJson)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueJson)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<UniqueJson>()?.is_some() {}
        Ok(UniqueJson)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(A::Error::custom("duplicate JSON member"));
            }
            map.next_value::<UniqueJson>()?;
        }
        Ok(UniqueJson)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    use super::*;
    use crate::{AwsLcP256Signer, DpopPortError, ProofId};

    const RFC_HEADER_JSON: &str = r#"{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","crv":"P-256"}}"#;
    const RFC_TOKEN_PROOF: &str = concat!(
        "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.",
        "eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.",
        "2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
    );
    const RFC_RESOURCE_PROOF: &str = concat!(
        "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.",
        "eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.",
        "2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"
    );
    const RFC_ACCESS_TOKEN: &[u8] = b"Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

    struct FixedClock(i64);

    impl Clock for FixedClock {
        fn unix_seconds(&self) -> Result<i64, DpopPortError> {
            Ok(self.0)
        }
    }

    #[derive(Default)]
    struct SequenceIds(AtomicU64);

    impl ProofIdGenerator for SequenceIds {
        fn generate(&self) -> Result<ProofId, DpopPortError> {
            let value = self.0.fetch_add(1, Ordering::Relaxed);
            ProofId::new(format!("test-proof-{value}")).map_err(|_| DpopPortError)
        }
    }

    #[derive(Default)]
    struct MemoryReplayStore {
        keys: Mutex<HashSet<[u8; 32]>>,
    }

    impl ReplayStore for MemoryReplayStore {
        fn check_and_record(
            &self,
            key: &ReplayKey,
            _expires_at_unix: i64,
        ) -> Result<ReplayStatus, DpopPortError> {
            let mut keys = self.keys.lock().map_err(|_| DpopPortError)?;
            if keys.insert(*key.as_bytes()) {
                Ok(ReplayStatus::Fresh)
            } else {
                Ok(ReplayStatus::Replay)
            }
        }
    }

    struct FailingReplayStore;

    impl ReplayStore for FailingReplayStore {
        fn check_and_record(
            &self,
            _key: &ReplayKey,
            _expires_at_unix: i64,
        ) -> Result<ReplayStatus, DpopPortError> {
            Err(DpopPortError)
        }
    }

    struct ShortSignatureSigner {
        jwk: PublicP256Jwk,
    }

    impl DpopSigner for ShortSignatureSigner {
        fn public_jwk(&self) -> &PublicP256Jwk {
            &self.jwk
        }

        fn sign(&self, _signing_input: &[u8]) -> Result<Vec<u8>, DpopPortError> {
            Ok(vec![0_u8; 63])
        }
    }

    fn compact(header: &str, payload: &str, signature: &[u8]) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        )
    }

    #[test]
    fn verifies_rfc_9449_token_endpoint_vector() -> Result<(), DpopError> {
        let proof = UnverifiedDpopProof::parse(RFC_TOKEN_PROOF)?;
        let target =
            EffectiveRequestTarget::parse("HTTPS://SERVER.EXAMPLE.COM:443/token?ignored=1")?;
        let request = DpopRequest::new("POST", &target)?;
        let clock = FixedClock(1_562_262_616);
        let engine = DpopVerifier::new(&clock, VerificationPolicy::default());
        let accepted = engine.verify(&proof, &request, &MemoryReplayStore::default())?;
        assert!(!accepted.access_token_hash_verified());
        assert!(accepted.replay_checked());
        Ok(())
    }

    #[test]
    fn verifies_rfc_9449_protected_resource_vector_and_exact_token_hash() -> Result<(), DpopError> {
        let proof = UnverifiedDpopProof::parse(RFC_RESOURCE_PROOF)?;
        let target =
            EffectiveRequestTarget::parse("https://resource.example.org/protectedresource")?;
        let request = DpopRequest::new("GET", &target)?.with_access_token(RFC_ACCESS_TOKEN);
        let clock = FixedClock(1_562_262_618);
        let engine = DpopVerifier::new(&clock, VerificationPolicy::default());
        let accepted = engine.verify(&proof, &request, &MemoryReplayStore::default())?;
        assert!(accepted.access_token_hash_verified());
        Ok(())
    }

    #[test]
    fn builder_and_verifier_interoperate_with_reference_signer() -> Result<(), DpopError> {
        let signer = AwsLcP256Signer::generate()?;
        let clock = FixedClock(1_700_000_000);
        let ids = SequenceIds::default();
        let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
        let nonce = DpopNonce::new("server-nonce")?;
        let request = DpopRequest::new("POST", &target)?
            .with_access_token(b"exact-token")
            .with_nonce(&nonce);
        let builder = DpopProofBuilder::new(&signer, &clock, &ids);
        let proof = builder.build(&request)?;
        let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
        let engine = DpopVerifier::new(&clock, VerificationPolicy::default());
        let accepted = engine.verify(&parsed, &request, &MemoryReplayStore::default())?;
        assert!(accepted.nonce_enforced());
        assert!(accepted.access_token_hash_verified());
        Ok(())
    }

    #[test]
    fn each_build_uses_a_fresh_proof_identifier() -> Result<(), DpopError> {
        let signer = AwsLcP256Signer::generate()?;
        let clock = FixedClock(1_700_000_000);
        let ids = SequenceIds::default();
        let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
        let request = DpopRequest::new("GET", &target)?;
        let builder = DpopProofBuilder::new(&signer, &clock, &ids);
        let first = UnverifiedDpopProof::parse(builder.build(&request)?.as_header_value())?;
        let second = UnverifiedDpopProof::parse(builder.build(&request)?.as_header_value())?;
        assert_ne!(first.claims.jti, second.claims.jti);
        Ok(())
    }

    #[test]
    fn rejects_multiple_comma_joined_and_missing_header_values() {
        assert!(matches!(
            parse_dpop_header_values(&[]),
            Err(DpopError::MissingProof)
        ));
        assert!(matches!(
            parse_dpop_header_values(&[RFC_TOKEN_PROOF, RFC_TOKEN_PROOF]),
            Err(DpopError::AmbiguousProof)
        ));
        assert!(matches!(
            parse_dpop_header_values(&["a.b.c,d.e.f"]),
            Err(DpopError::AmbiguousProof)
        ));
    }

    #[test]
    fn rejects_duplicate_json_members_recursively() {
        let header = RFC_HEADER_JSON.replacen(
            r#""typ":"dpop+jwt""#,
            r#""typ":"dpop+jwt","typ":"dpop+jwt""#,
            1,
        );
        let payload = r#"{"jti":"id","htm":"POST","htu":"https://server.example.com/token","iat":1562262616}"#;
        let proof = compact(&header, payload, &[0_u8; 64]);
        assert!(matches!(
            UnverifiedDpopProof::parse(&proof),
            Err(DpopError::MalformedProof)
        ));
    }

    #[test]
    fn rejects_algorithm_confusion_before_signature_acceptance() -> Result<(), DpopError> {
        let header = RFC_HEADER_JSON.replace("ES256", "none");
        let payload = r#"{"jti":"id","htm":"POST","htu":"https://server.example.com/token","iat":1562262616}"#;
        let proof = UnverifiedDpopProof::parse(&compact(&header, payload, &[0_u8; 64]))?;
        let target = EffectiveRequestTarget::parse("https://server.example.com/token")?;
        let request = DpopRequest::new("POST", &target)?;
        let clock = FixedClock(1_562_262_616);
        let engine = DpopVerifier::new(&clock, VerificationPolicy::default());
        assert!(matches!(
            engine.verify(&proof, &request, &MemoryReplayStore::default()),
            Err(DpopError::UnsupportedAlgorithm)
        ));
        Ok(())
    }

    #[test]
    fn rejects_private_proof_jwk_during_parse() {
        let header = RFC_HEADER_JSON.replace(r#""crv":"P-256""#, r#""crv":"P-256","d":null"#);
        let payload = r#"{"jti":"id","htm":"POST","htu":"https://server.example.com/token","iat":1562262616}"#;
        let proof = compact(&header, payload, &[0_u8; 64]);
        assert!(matches!(
            UnverifiedDpopProof::parse(&proof),
            Err(DpopError::UnsupportedKey)
        ));
    }

    #[test]
    fn rejects_wrong_length_fixed_signature() -> Result<(), DpopError> {
        let payload = r#"{"jti":"id","htm":"POST","htu":"https://server.example.com/token","iat":1562262616}"#;
        let proof = UnverifiedDpopProof::parse(&compact(RFC_HEADER_JSON, payload, &[0_u8; 63]))?;
        let target = EffectiveRequestTarget::parse("https://server.example.com/token")?;
        let request = DpopRequest::new("POST", &target)?;
        let clock = FixedClock(1_562_262_616);
        let engine = DpopVerifier::new(&clock, VerificationPolicy::default());
        assert!(matches!(
            engine.verify(&proof, &request, &MemoryReplayStore::default()),
            Err(DpopError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn rejects_method_target_and_token_substitution() -> Result<(), DpopError> {
        let clock = FixedClock(1_562_262_618);
        let engine = DpopVerifier::new(&clock, VerificationPolicy::default());
        let good_target =
            EffectiveRequestTarget::parse("https://resource.example.org/protectedresource")?;
        let wrong_target = EffectiveRequestTarget::parse("https://resource.example.org/other")?;
        let wrong_method =
            DpopRequest::new("POST", &good_target)?.with_access_token(RFC_ACCESS_TOKEN);
        let wrong_target_request =
            DpopRequest::new("GET", &wrong_target)?.with_access_token(RFC_ACCESS_TOKEN);
        let wrong_token =
            DpopRequest::new("GET", &good_target)?.with_access_token(b"different-token");

        assert!(matches!(
            engine.verify(
                &UnverifiedDpopProof::parse(RFC_RESOURCE_PROOF)?,
                &wrong_method,
                &MemoryReplayStore::default()
            ),
            Err(DpopError::MethodMismatch)
        ));
        assert!(matches!(
            engine.verify(
                &UnverifiedDpopProof::parse(RFC_RESOURCE_PROOF)?,
                &wrong_target_request,
                &MemoryReplayStore::default()
            ),
            Err(DpopError::TargetMismatch)
        ));
        assert!(matches!(
            engine.verify(
                &UnverifiedDpopProof::parse(RFC_RESOURCE_PROOF)?,
                &wrong_token,
                &MemoryReplayStore::default()
            ),
            Err(DpopError::AccessTokenHashMismatch)
        ));
        Ok(())
    }

    #[test]
    fn freshness_boundaries_are_inclusive_and_explicit() -> Result<(), DpopError> {
        let target = EffectiveRequestTarget::parse("https://server.example.com/token")?;
        let request = DpopRequest::new("POST", &target)?;
        let policy = VerificationPolicy::default();

        let inside_past_clock = FixedClock(1_562_262_916);
        let inside_past = DpopVerifier::new(&inside_past_clock, policy);
        inside_past.verify(
            &UnverifiedDpopProof::parse(RFC_TOKEN_PROOF)?,
            &request,
            &MemoryReplayStore::default(),
        )?;
        let outside_past_clock = FixedClock(1_562_262_917);
        let outside_past = DpopVerifier::new(&outside_past_clock, policy);
        assert!(matches!(
            outside_past.verify(
                &UnverifiedDpopProof::parse(RFC_TOKEN_PROOF)?,
                &request,
                &MemoryReplayStore::default()
            ),
            Err(DpopError::ProofExpired)
        ));

        let inside_future_clock = FixedClock(1_562_262_316);
        let inside_future = DpopVerifier::new(&inside_future_clock, policy);
        inside_future.verify(
            &UnverifiedDpopProof::parse(RFC_TOKEN_PROOF)?,
            &request,
            &MemoryReplayStore::default(),
        )?;
        let outside_future_clock = FixedClock(1_562_262_315);
        let outside_future = DpopVerifier::new(&outside_future_clock, policy);
        assert!(matches!(
            outside_future.verify(
                &UnverifiedDpopProof::parse(RFC_TOKEN_PROOF)?,
                &request,
                &MemoryReplayStore::default()
            ),
            Err(DpopError::ProofFromFuture)
        ));
        Ok(())
    }

    #[test]
    fn nonce_requirement_fails_closed() -> Result<(), DpopError> {
        let target = EffectiveRequestTarget::parse("https://server.example.com/token")?;
        let nonce = DpopNonce::new("required-nonce")?;
        let request = DpopRequest::new("POST", &target)?.with_nonce(&nonce);
        let clock = FixedClock(1_562_262_616);
        let engine = DpopVerifier::new(&clock, VerificationPolicy::default());
        assert!(matches!(
            engine.verify(
                &UnverifiedDpopProof::parse(RFC_TOKEN_PROOF)?,
                &request,
                &MemoryReplayStore::default()
            ),
            Err(DpopError::NonceRequired)
        ));
        Ok(())
    }

    #[test]
    fn replay_is_atomic_handoff_and_store_failure_fails_closed() -> Result<(), DpopError> {
        let target = EffectiveRequestTarget::parse("https://server.example.com/token")?;
        let request = DpopRequest::new("POST", &target)?;
        let clock = FixedClock(1_562_262_616);
        let engine = DpopVerifier::new(&clock, VerificationPolicy::default());
        let store = MemoryReplayStore::default();
        engine.verify(
            &UnverifiedDpopProof::parse(RFC_TOKEN_PROOF)?,
            &request,
            &store,
        )?;
        assert!(matches!(
            engine.verify(
                &UnverifiedDpopProof::parse(RFC_TOKEN_PROOF)?,
                &request,
                &store
            ),
            Err(DpopError::ReplayDetected)
        ));
        assert!(matches!(
            engine.verify(
                &UnverifiedDpopProof::parse(RFC_TOKEN_PROOF)?,
                &request,
                &FailingReplayStore
            ),
            Err(DpopError::ReplayStoreUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn builder_rejects_malformed_external_signer_output() -> Result<(), DpopError> {
        let good_signer = AwsLcP256Signer::generate()?;
        let signer = ShortSignatureSigner {
            jwk: good_signer.public_jwk().clone(),
        };
        let clock = FixedClock(1_700_000_000);
        let ids = SequenceIds::default();
        let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
        let request = DpopRequest::new("GET", &target)?;
        let builder = DpopProofBuilder::new(&signer, &clock, &ids);
        assert!(matches!(
            builder.build(&request),
            Err(DpopError::SignerFailure)
        ));
        Ok(())
    }

    #[test]
    fn proof_diagnostics_do_not_reflect_credentials() -> Result<(), DpopError> {
        let proof = DpopProof(RFC_RESOURCE_PROOF.to_owned());
        let parsed = UnverifiedDpopProof::parse(RFC_RESOURCE_PROOF)?;
        assert!(!format!("{proof:?}").contains("eyJ0eXAi"));
        assert!(!format!("{parsed:?}").contains("e1j3V_bKic8-LAEB"));
        assert!(!format!("{parsed:?}").contains("fUHyO2r2"));
        Ok(())
    }
}
