//! Proof-construction conformance for requirements not observable through verification alone.

use std::collections::HashSet;

use keylix_core::PublicP256Jwk;
use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopNonce, DpopPortError, DpopProofBuilder, DpopRequest,
    DpopSigner, DpopVerifier, EffectiveRequestTarget, InMemoryClientNonceStore,
    InMemoryReplayStore, NonceContext, NonceNamespace, RandomProofIdGenerator, UnverifiedDpopProof,
    VerificationPolicy,
};
use keylix_oauth::{DpopRequiredClient, NonceRetryBudget};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

struct FailingClock;

impl Clock for FailingClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Err(DpopPortError)
    }
}

struct DelegatingSigner<'a> {
    inner: &'a AwsLcP256Signer,
}

impl DpopSigner for DelegatingSigner<'_> {
    fn public_jwk(&self) -> &PublicP256Jwk {
        self.inner.public_jwk()
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, DpopPortError> {
        self.inner.sign(signing_input)
    }
}

struct WrongLengthSigner<'a> {
    inner: &'a AwsLcP256Signer,
}

impl DpopSigner for WrongLengthSigner<'_> {
    fn public_jwk(&self) -> &PublicP256Jwk {
        self.inner.public_jwk()
    }

    fn sign(&self, _signing_input: &[u8]) -> Result<Vec<u8>, DpopPortError> {
        Ok(vec![0_u8; 63])
    }
}

struct DerEncodingSigner<'a> {
    inner: &'a AwsLcP256Signer,
}

impl DpopSigner for DerEncodingSigner<'_> {
    fn public_jwk(&self) -> &PublicP256Jwk {
        self.inner.public_jwk()
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, DpopPortError> {
        let fixed = self.inner.sign(signing_input)?;
        fixed_es256_to_der(&fixed)
    }
}

struct MismatchedSigner<'a> {
    advertised: &'a AwsLcP256Signer,
    actual: &'a AwsLcP256Signer,
}

impl DpopSigner for MismatchedSigner<'_> {
    fn public_jwk(&self) -> &PublicP256Jwk {
        self.advertised.public_jwk()
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, DpopPortError> {
        self.actual.sign(signing_input)
    }
}

#[test]
fn kx_build_001_reference_generator_yields_large_unique_jti_sample()
-> Result<(), Box<dyn std::error::Error>> {
    const SAMPLE_SIZE: usize = 1_024;

    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let generator = RandomProofIdGenerator;
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let request = DpopRequest::new("GET", &target)?;
    let builder = DpopProofBuilder::new(&signer, &clock, &generator);
    let mut observed = HashSet::with_capacity(SAMPLE_SIZE);

    for _ in 0..SAMPLE_SIZE {
        let proof = builder.build(&request)?;
        let payload = proof_payload_json(proof.as_header_value())?;
        let jti = extract_json_string(&payload, "jti")?;

        assert!(
            jti.len() >= 16,
            "KX-BUILD-001: reference jti does not encode the required entropy floor"
        );
        assert!(
            jti.bytes().all(is_base64url_byte),
            "KX-BUILD-001: reference jti left the base64url alphabet"
        );
        assert!(
            observed.insert(jti),
            "KX-BUILD-001: duplicate reference jti observed in sample"
        );
    }

    assert_eq!(observed.len(), SAMPLE_SIZE);
    Ok(())
}

#[test]
fn kx_build_003_injected_clock_is_exact_and_failure_is_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = AwsLcP256Signer::generate()?;
    let generator = RandomProofIdGenerator;
    let exact_clock = FixedClock(1_700_000_123);
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let request = DpopRequest::new("POST", &target)?;
    let proof = DpopProofBuilder::new(&signer, &exact_clock, &generator).build(&request)?;
    let payload = proof_payload_json(proof.as_header_value())?;

    assert_eq!(
        extract_json_i64(&payload, "iat")?,
        1_700_000_123,
        "KX-BUILD-003: emitted iat did not come from the injected clock"
    );

    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let replay = InMemoryReplayStore::new(exact_clock, 8)?;
    let verified = DpopVerifier::new(&exact_clock, VerificationPolicy::default())
        .verify(&parsed, &request, &replay)?;
    assert_eq!(verified.issued_at_unix(), 1_700_000_123);

    let failing = DpopProofBuilder::new(&signer, &FailingClock, &generator);
    assert!(matches!(
        failing.build(&request),
        Err(DpopError::ClockUnavailable)
    ));

    let non_positive = FixedClock(0);
    let invalid_time = DpopProofBuilder::new(&signer, &non_positive, &generator);
    assert!(matches!(
        invalid_time.build(&request),
        Err(DpopError::ClockUnavailable)
    ));
    Ok(())
}

#[test]
fn kx_build_006_external_signer_contract_accepts_fixed_es256_and_rejects_bad_output()
-> Result<(), Box<dyn std::error::Error>> {
    let software_key = AwsLcP256Signer::generate()?;
    let other_key = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let generator = RandomProofIdGenerator;
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let request = DpopRequest::new("POST", &target)?;

    let external = DelegatingSigner {
        inner: &software_key,
    };
    let proof = DpopProofBuilder::new(&external, &clock, &generator).build(&request)?;
    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    DpopVerifier::new(&clock, VerificationPolicy::default()).verify(&parsed, &request, &replay)?;

    let wrong_length = WrongLengthSigner {
        inner: &software_key,
    };
    assert!(matches!(
        DpopProofBuilder::new(&wrong_length, &clock, &generator).build(&request),
        Err(DpopError::SignerFailure)
    ));

    let der = DerEncodingSigner {
        inner: &software_key,
    };
    assert!(matches!(
        DpopProofBuilder::new(&der, &clock, &generator).build(&request),
        Err(DpopError::SignerFailure)
    ));

    let mismatched = MismatchedSigner {
        advertised: &software_key,
        actual: &other_key,
    };
    assert!(matches!(
        DpopProofBuilder::new(&mismatched, &clock, &generator).build(&request),
        Err(DpopError::SignerFailure)
    ));
    Ok(())
}

#[test]
fn kx_build_007_resource_nonce_retry_uses_fresh_jti_and_old_proof_replays()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let generator = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(8)?;
    let client = DpopRequiredClient::new(&signer, &clock, &generator, &nonces);
    let token_set = client.accept_token_response("DPoP", "access-token-a".to_owned(), None)?;
    let context = NonceContext::new(NonceNamespace::ResourceServer, "resource-a")?;
    let target = EffectiveRequestTarget::parse("https://api.example.com/items")?;

    let initial = client.protected_resource(&context, "GET", &target, token_set.access_token())?;
    let initial_payload = proof_payload_json(initial.dpop_header_value())?;
    let initial_jti = extract_json_string(&initial_payload, "jti")?;

    let nonce = DpopNonce::new("retry-nonce")?;
    let mut budget = NonceRetryBudget::single_retry();
    client.record_nonce_challenge(&context, &nonce, &mut budget)?;
    let retry = client.protected_resource(&context, "GET", &target, token_set.access_token())?;
    let retry_payload = proof_payload_json(retry.dpop_header_value())?;
    let retry_jti = extract_json_string(&retry_payload, "jti")?;

    assert_ne!(
        initial_jti, retry_jti,
        "KX-BUILD-007: nonce retry reused the original jti"
    );

    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());
    let replay = InMemoryReplayStore::new(clock, 8)?;
    let initial_parsed = UnverifiedDpopProof::parse(initial.dpop_header_value())?;
    let initial_request = DpopRequest::new("GET", &target)?.with_access_token(b"access-token-a");
    verifier.verify(&initial_parsed, &initial_request, &replay)?;
    assert!(matches!(
        verifier.verify(&initial_parsed, &initial_request, &replay),
        Err(DpopError::ReplayDetected)
    ));

    let retry_parsed = UnverifiedDpopProof::parse(retry.dpop_header_value())?;
    let retry_request = DpopRequest::new("GET", &target)?
        .with_access_token(b"access-token-a")
        .with_nonce(&nonce);
    verifier.verify(&retry_parsed, &retry_request, &replay)?;
    Ok(())
}

fn fixed_es256_to_der(signature: &[u8]) -> Result<Vec<u8>, DpopPortError> {
    if signature.len() != 64 {
        return Err(DpopPortError);
    }
    let r = der_integer(&signature[..32]);
    let s = der_integer(&signature[32..]);
    let sequence_len = r.len().checked_add(s.len()).ok_or(DpopPortError)?;
    if sequence_len > usize::from(u8::MAX) {
        return Err(DpopPortError);
    }

    let mut der = Vec::with_capacity(sequence_len + 2);
    der.push(0x30);
    der.push(u8::try_from(sequence_len).map_err(|_| DpopPortError)?);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    Ok(der)
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let mut first = 0;
    while first + 1 < value.len() && value[first] == 0 {
        first += 1;
    }
    let significant = &value[first..];
    let prefix_zero = significant.first().is_some_and(|byte| byte & 0x80 != 0);
    let mut encoded = Vec::with_capacity(significant.len() + usize::from(prefix_zero) + 2);
    encoded.push(0x02);
    encoded.push(u8::try_from(significant.len() + usize::from(prefix_zero)).unwrap_or(u8::MAX));
    if prefix_zero {
        encoded.push(0);
    }
    encoded.extend_from_slice(significant);
    encoded
}

fn proof_payload_json(proof: &str) -> Result<String, DpopError> {
    let mut parts = proof.split('.');
    let _header = parts.next().ok_or(DpopError::MalformedProof)?;
    let payload = parts.next().ok_or(DpopError::MalformedProof)?;
    let _signature = parts.next().ok_or(DpopError::MalformedProof)?;
    if parts.next().is_some() {
        return Err(DpopError::MalformedProof);
    }
    let bytes = decode_base64url(payload)?;
    String::from_utf8(bytes).map_err(|_| DpopError::MalformedProof)
}

fn extract_json_string(payload: &str, name: &str) -> Result<String, DpopError> {
    let marker = format!("\"{name}\":\"");
    let start = payload.find(&marker).ok_or(DpopError::MalformedProof)? + marker.len();
    let tail = payload.get(start..).ok_or(DpopError::MalformedProof)?;
    let end = tail.find('"').ok_or(DpopError::MalformedProof)?;
    Ok(tail[..end].to_owned())
}

fn extract_json_i64(payload: &str, name: &str) -> Result<i64, DpopError> {
    let marker = format!("\"{name}\":");
    let start = payload.find(&marker).ok_or(DpopError::MalformedProof)? + marker.len();
    let tail = payload.get(start..).ok_or(DpopError::MalformedProof)?;
    let end = tail
        .find(|character: char| character != '-' && !character.is_ascii_digit())
        .unwrap_or(tail.len());
    tail[..end]
        .parse::<i64>()
        .map_err(|_| DpopError::MalformedProof)
}

fn decode_base64url(input: &str) -> Result<Vec<u8>, DpopError> {
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0_u32;
    let mut bits = 0_u8;

    for byte in input.bytes() {
        let value = base64url_value(byte).ok_or(DpopError::MalformedProof)?;
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(
                u8::try_from((buffer >> bits) & 0xff).map_err(|_| DpopError::MalformedProof)?,
            );
            if bits == 0 {
                buffer = 0;
            } else {
                buffer &= (1_u32 << bits) - 1;
            }
        }
    }

    if buffer != 0 {
        return Err(DpopError::MalformedProof);
    }
    Ok(output)
}

const fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

const fn is_base64url_byte(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}
