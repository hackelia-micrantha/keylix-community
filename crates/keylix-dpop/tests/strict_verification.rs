//! Adversarial acceptance tests for the public RFC 9449 verification boundary.

use std::sync::atomic::{AtomicU64, Ordering};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopNonce, DpopPortError, DpopProof, DpopProofBuilder,
    DpopRequest, DpopSigner, DpopVerifier, EffectiveRequestTarget, ProofId, ProofIdGenerator,
    ReplayKey, ReplayStatus, ReplayStore, UnverifiedDpopProof, VerificationPolicy,
};
use serde_json::{Value, json};

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
        ProofId::new(format!("integration-proof-{value}")).map_err(|_| DpopPortError)
    }
}

struct AlwaysFreshReplayStore;

impl ReplayStore for AlwaysFreshReplayStore {
    fn check_and_record(
        &self,
        _key: &ReplayKey,
        _expires_at_unix: i64,
    ) -> Result<ReplayStatus, DpopPortError> {
        Ok(ReplayStatus::Fresh)
    }
}

fn build_proof<'a>(
    signer: &'a AwsLcP256Signer,
    clock: &'a FixedClock,
    ids: &'a SequenceIds,
    request: &DpopRequest<'_>,
) -> Result<DpopProof, DpopError> {
    DpopProofBuilder::new(signer, clock, ids).build(request)
}

fn split_compact(proof: &str) -> Result<(&str, &str, &str), DpopError> {
    let mut segments = proof.split('.');
    let header = segments.next().ok_or(DpopError::MalformedProof)?;
    let payload = segments.next().ok_or(DpopError::MalformedProof)?;
    let signature = segments.next().ok_or(DpopError::MalformedProof)?;
    if segments.next().is_some() {
        return Err(DpopError::MalformedProof);
    }
    Ok((header, payload, signature))
}

fn decode_json(segment: &str) -> Result<Value, DpopError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| DpopError::MalformedProof)?;
    serde_json::from_slice(&bytes).map_err(|_| DpopError::MalformedProof)
}

fn encode_json(value: &Value) -> Result<String, DpopError> {
    let bytes = serde_json::to_vec(value).map_err(|_| DpopError::MalformedProof)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn compact_json(header: &Value, payload: &Value, signature: &[u8]) -> Result<String, DpopError> {
    Ok(format!(
        "{}.{}.{}",
        encode_json(header)?,
        encode_json(payload)?,
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn valid_header(signer: &AwsLcP256Signer) -> Result<Value, DpopError> {
    let jwk = serde_json::to_value(signer.public_jwk()).map_err(|_| DpopError::MalformedProof)?;
    Ok(json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk}))
}

fn valid_payload() -> Value {
    json!({
        "jti":"integration-id",
        "htm":"GET",
        "htu":"https://api.example.com/resource",
        "iat":1_700_000_000_i64
    })
}

#[test]
fn rejects_malformed_compact_and_base64url_framing() {
    for proof in ["a.b", "a.b.c.d", "*.e30.AA", "e30=.e30.AA"] {
        assert!(matches!(
            UnverifiedDpopProof::parse(proof),
            Err(DpopError::MalformedProof)
        ));
    }

    let oversized = "a".repeat(8_193);
    assert!(matches!(
        UnverifiedDpopProof::parse(&oversized),
        Err(DpopError::ProofTooLarge)
    ));
}

#[test]
fn rejects_each_required_header_and_claim_when_missing() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let full_header = valid_header(&signer)?;
    let full_payload = valid_payload();

    for member in ["typ", "alg", "jwk"] {
        let mut header = full_header.clone();
        header
            .as_object_mut()
            .ok_or(DpopError::MalformedProof)?
            .remove(member);
        let proof = compact_json(&header, &full_payload, &[0_u8; 64])?;
        assert!(matches!(
            UnverifiedDpopProof::parse(&proof),
            Err(DpopError::MalformedProof)
        ));
    }

    for member in ["jti", "htm", "htu", "iat"] {
        let mut payload = full_payload.clone();
        payload
            .as_object_mut()
            .ok_or(DpopError::MalformedProof)?
            .remove(member);
        let proof = compact_json(&full_header, &payload, &[0_u8; 64])?;
        assert!(matches!(
            UnverifiedDpopProof::parse(&proof),
            Err(DpopError::MalformedProof)
        ));
    }
    Ok(())
}

#[test]
fn rejects_wrong_typ_exactly_before_signature_acceptance() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = SequenceIds::default();
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let request = DpopRequest::new("GET", &target)?;
    let proof = build_proof(&signer, &clock, &ids, &request)?;
    let (header_segment, payload_segment, signature_segment) =
        split_compact(proof.as_header_value())?;
    let mut header = decode_json(header_segment)?;
    header["typ"] = Value::String("DPoP+jwt".to_owned());
    let modified = format!(
        "{}.{payload_segment}.{signature_segment}",
        encode_json(&header)?
    );
    let parsed = UnverifiedDpopProof::parse(&modified)?;
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

    assert!(matches!(
        verifier.verify(&parsed, &request, &AlwaysFreshReplayStore),
        Err(DpopError::MalformedProof)
    ));
    Ok(())
}

#[test]
fn rejects_unsupported_curve_during_parse() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let mut header = valid_header(&signer)?;
    header["jwk"]["crv"] = Value::String("P-384".to_owned());
    let proof = compact_json(&header, &valid_payload(), &[0_u8; 64])?;

    assert!(matches!(
        UnverifiedDpopProof::parse(&proof),
        Err(DpopError::UnsupportedKey)
    ));
    Ok(())
}

#[test]
fn rejects_key_substitution_and_signature_bit_flip() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let substitute = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = SequenceIds::default();
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let request = DpopRequest::new("GET", &target)?;
    let proof = build_proof(&signer, &clock, &ids, &request)?;
    let (header_segment, payload_segment, signature_segment) =
        split_compact(proof.as_header_value())?;
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

    let mut substituted_header = decode_json(header_segment)?;
    substituted_header["jwk"] =
        serde_json::to_value(substitute.public_jwk()).map_err(|_| DpopError::MalformedProof)?;
    let substituted = format!(
        "{}.{payload_segment}.{signature_segment}",
        encode_json(&substituted_header)?
    );
    let substituted = UnverifiedDpopProof::parse(&substituted)?;
    assert!(matches!(
        verifier.verify(&substituted, &request, &AlwaysFreshReplayStore),
        Err(DpopError::InvalidSignature)
    ));

    let mut signature = URL_SAFE_NO_PAD
        .decode(signature_segment)
        .map_err(|_| DpopError::MalformedProof)?;
    signature[0] ^= 0x01;
    let flipped = format!(
        "{header_segment}.{payload_segment}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    );
    let flipped = UnverifiedDpopProof::parse(&flipped)?;
    assert!(matches!(
        verifier.verify(&flipped, &request, &AlwaysFreshReplayStore),
        Err(DpopError::InvalidSignature)
    ));
    Ok(())
}

#[test]
fn rejects_der_form_signature_explicitly() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = SequenceIds::default();
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let request = DpopRequest::new("GET", &target)?;
    let proof = build_proof(&signer, &clock, &ids, &request)?;
    let (header_segment, payload_segment, _) = split_compact(proof.as_header_value())?;
    let mut der_like = vec![0_u8; 70];
    der_like[0] = 0x30;
    der_like[1] = 68;
    let modified = format!(
        "{header_segment}.{payload_segment}.{}",
        URL_SAFE_NO_PAD.encode(der_like)
    );
    let parsed = UnverifiedDpopProof::parse(&modified)?;
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

    assert!(matches!(
        verifier.verify(&parsed, &request, &AlwaysFreshReplayStore),
        Err(DpopError::InvalidSignature)
    ));
    Ok(())
}

#[test]
fn protected_resource_requires_ath_even_for_otherwise_valid_proof() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = SequenceIds::default();
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let tokenless_request = DpopRequest::new("GET", &target)?;
    let proof = build_proof(&signer, &clock, &ids, &tokenless_request)?;
    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let protected_request = DpopRequest::new("GET", &target)?.with_access_token(b"exact-token");
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

    assert!(matches!(
        verifier.verify(&parsed, &protected_request, &AlwaysFreshReplayStore),
        Err(DpopError::AccessTokenHashMissing)
    ));
    Ok(())
}

#[test]
fn wrong_required_nonce_is_rejected() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = SequenceIds::default();
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let nonce_a = DpopNonce::new("nonce-a")?;
    let nonce_b = DpopNonce::new("nonce-b")?;
    let build_request = DpopRequest::new("GET", &target)?.with_nonce(&nonce_a);
    let proof = build_proof(&signer, &clock, &ids, &build_request)?;
    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let verify_request = DpopRequest::new("GET", &target)?.with_nonce(&nonce_b);
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

    assert!(matches!(
        verifier.verify(&parsed, &verify_request, &AlwaysFreshReplayStore),
        Err(DpopError::NonceMismatch)
    ));
    Ok(())
}

#[test]
fn parser_accepts_unknown_extension_members_without_trusting_them() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let mut header = valid_header(&signer)?;
    header["kid"] = Value::String("extension-key-id".to_owned());
    let mut payload = valid_payload();
    payload["future_extension"] = json!({"nested": true});
    let proof = compact_json(&header, &payload, &[0_u8; 64])?;

    UnverifiedDpopProof::parse(&proof)?;
    Ok(())
}

#[test]
fn rejects_invalid_iat_type() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let header = valid_header(&signer)?;
    let mut payload = valid_payload();
    payload["iat"] = Value::String("1700000000".to_owned());
    let proof = compact_json(&header, &payload, &[0_u8; 64])?;

    assert!(matches!(
        UnverifiedDpopProof::parse(&proof),
        Err(DpopError::MalformedProof)
    ));
    Ok(())
}

#[test]
fn request_debug_does_not_reflect_token_nonce_or_target() -> Result<(), DpopError> {
    let target = EffectiveRequestTarget::parse("https://secret-host.example/private-path")?;
    let nonce = DpopNonce::new("distinctive-secret-nonce")?;
    let request = DpopRequest::new("POST", &target)?
        .with_access_token(b"distinctive-secret-token")
        .with_nonce(&nonce);
    let debug = format!("{request:?}");

    assert!(!debug.contains("distinctive-secret-token"));
    assert!(!debug.contains("distinctive-secret-nonce"));
    assert!(!debug.contains("secret-host.example"));
    assert!(!debug.contains("private-path"));
    Ok(())
}
