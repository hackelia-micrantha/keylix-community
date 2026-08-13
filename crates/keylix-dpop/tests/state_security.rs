//! Concurrency and scope tests for replay and nonce reference state.

use std::sync::{Arc, Barrier};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use keylix_dpop::{
    AwsLcP256Signer, ClientNonceStore, Clock, DpopError, DpopNonce, DpopPortError,
    DpopProofBuilder, DpopRequest, DpopVerifier, EffectiveRequestTarget, InMemoryClientNonceStore,
    InMemoryReplayStore, InMemoryServerNonceStore, NonceContext, NonceGenerator, NonceNamespace,
    ProofId, ProofIdGenerator, RandomNonceGenerator, ServerNonceStore, UnverifiedDpopProof,
    VerificationPolicy,
};
use serde_json::Value;

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

struct ConstantId(&'static str);

impl ProofIdGenerator for ConstantId {
    fn generate(&self) -> Result<ProofId, DpopPortError> {
        ProofId::new(self.0).map_err(|_| DpopPortError)
    }
}

#[derive(Default)]
struct SequenceNonceGenerator(std::sync::atomic::AtomicU64);

impl NonceGenerator for SequenceNonceGenerator {
    fn generate(&self) -> Result<DpopNonce, DpopPortError> {
        let value = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        DpopNonce::new(format!("server-nonce-{value}")).map_err(|_| DpopPortError)
    }
}

fn proof_jti(proof: &str) -> Result<String, DpopError> {
    let payload = proof.split('.').nth(1).ok_or(DpopError::MalformedProof)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| DpopError::MalformedProof)?;
    let payload: Value = serde_json::from_slice(&payload).map_err(|_| DpopError::MalformedProof)?;
    payload
        .get("jti")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(DpopError::MalformedProof)
}

fn proof_nonce(proof: &str) -> Result<Option<String>, DpopError> {
    let payload = proof.split('.').nth(1).ok_or(DpopError::MalformedProof)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| DpopError::MalformedProof)?;
    let payload: Value = serde_json::from_slice(&payload).map_err(|_| DpopError::MalformedProof)?;
    Ok(payload
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_owned))
}

#[test]
fn concurrent_duplicate_submission_has_at_most_one_fresh_result() -> Result<(), DpopError> {
    const THREADS: usize = 16;

    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = ConstantId("same-jti");
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let request = DpopRequest::new("GET", &target)?;
    let proof = DpopProofBuilder::new(&signer, &clock, &ids).build(&request)?;
    let proof = Arc::new(proof.as_header_value().to_owned());
    let store = Arc::new(InMemoryReplayStore::new(clock, 64)?);
    let barrier = Arc::new(Barrier::new(THREADS));

    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let proof = Arc::clone(&proof);
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || -> Result<bool, DpopError> {
            let parsed = UnverifiedDpopProof::parse(&proof)?;
            let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
            let request = DpopRequest::new("GET", &target)?;
            let clock = FixedClock(1_700_000_000);
            let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());
            barrier.wait();
            match verifier.verify(&parsed, &request, store.as_ref()) {
                Ok(_) => Ok(true),
                Err(DpopError::ReplayDetected) => Ok(false),
                Err(error) => Err(error),
            }
        }));
    }

    let mut fresh = 0;
    for handle in handles {
        let accepted = handle
            .join()
            .map_err(|_| DpopError::ReplayStoreUnavailable)??;
        fresh += usize::from(accepted);
    }
    assert_eq!(fresh, 1);
    Ok(())
}

#[test]
fn replay_scope_separates_key_and_target_but_not_access_token_hash() -> Result<(), DpopError> {
    let clock = FixedClock(1_700_000_000);
    let ids = ConstantId("shared-jti");
    let signer_a = AwsLcP256Signer::generate()?;
    let signer_b = AwsLcP256Signer::generate()?;
    let target_a = EffectiveRequestTarget::parse("https://api.example.com/a")?;
    let target_b = EffectiveRequestTarget::parse("https://api.example.com/b")?;
    let store = InMemoryReplayStore::new(clock, 16)?;
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

    let request_a = DpopRequest::new("GET", &target_a)?;
    let proof_a = DpopProofBuilder::new(&signer_a, &clock, &ids).build(&request_a)?;
    let parsed_a = UnverifiedDpopProof::parse(proof_a.as_header_value())?;
    verifier.verify(&parsed_a, &request_a, &store)?;

    let other_key = DpopProofBuilder::new(&signer_b, &clock, &ids).build(&request_a)?;
    let other_key = UnverifiedDpopProof::parse(other_key.as_header_value())?;
    verifier.verify(&other_key, &request_a, &store)?;

    let request_b = DpopRequest::new("GET", &target_b)?;
    let other_target = DpopProofBuilder::new(&signer_a, &clock, &ids).build(&request_b)?;
    let other_target = UnverifiedDpopProof::parse(other_target.as_header_value())?;
    verifier.verify(&other_target, &request_b, &store)?;

    let first_token_request = DpopRequest::new("POST", &target_a)?.with_access_token(b"token-a");
    let second_token_request = DpopRequest::new("POST", &target_a)?.with_access_token(b"token-b");
    let first_token_proof =
        DpopProofBuilder::new(&signer_a, &clock, &ids).build(&first_token_request)?;
    let second_token_proof =
        DpopProofBuilder::new(&signer_a, &clock, &ids).build(&second_token_request)?;
    let first_token_parsed = UnverifiedDpopProof::parse(first_token_proof.as_header_value())?;
    let second_token_parsed = UnverifiedDpopProof::parse(second_token_proof.as_header_value())?;
    verifier.verify(&first_token_parsed, &first_token_request, &store)?;
    assert!(matches!(
        verifier.verify(&second_token_parsed, &second_token_request, &store),
        Err(DpopError::ReplayDetected)
    ));
    Ok(())
}

#[test]
fn as_and_rs_nonce_challenge_retry_are_isolated_and_use_fresh_jti() -> Result<(), DpopError> {
    for namespace in [
        NonceNamespace::AuthorizationServer,
        NonceNamespace::ResourceServer,
    ] {
        let signer = AwsLcP256Signer::generate()?;
        let clock = FixedClock(1_700_000_000);
        let ids = keylix_dpop::RandomProofIdGenerator;
        let client = InMemoryClientNonceStore::new(8)?;
        let server = InMemoryServerNonceStore::new(SequenceNonceGenerator::default(), 8)?;
        let context = NonceContext::new(namespace, "server-a")?;
        let other_context = NonceContext::new(namespace, "server-b")?;
        let cross_namespace = NonceContext::new(
            match namespace {
                NonceNamespace::AuthorizationServer => NonceNamespace::ResourceServer,
                NonceNamespace::ResourceServer => NonceNamespace::AuthorizationServer,
            },
            "server-a",
        )?;
        let target = EffectiveRequestTarget::parse("https://server-a.example/request")?;

        let initial_request = DpopRequest::new("POST", &target)?;
        let builder = DpopProofBuilder::new(&signer, &clock, &ids);
        let initial = builder.build(&initial_request)?;
        let initial_jti = proof_jti(initial.as_header_value())?;

        let challenged = server
            .issue_nonce(&context)
            .map_err(|_| DpopError::NonceMismatch)?;
        client
            .record_challenge(&context, &challenged)
            .map_err(|_| DpopError::NonceMismatch)?;
        assert_eq!(
            client
                .nonce_for(&other_context)
                .map_err(|_| DpopError::NonceMismatch)?,
            None
        );
        assert_eq!(
            client
                .nonce_for(&cross_namespace)
                .map_err(|_| DpopError::NonceMismatch)?,
            None
        );

        let current = client
            .nonce_for(&context)
            .map_err(|_| DpopError::NonceMismatch)?
            .ok_or(DpopError::NonceRequired)?;
        let retry_request = DpopRequest::new("POST", &target)?.with_nonce(&current);
        let retry = builder.build(&retry_request)?;
        assert_ne!(proof_jti(retry.as_header_value())?, initial_jti);
        assert_eq!(
            proof_nonce(retry.as_header_value())?,
            Some(current.as_header_value().to_owned())
        );

        let expected = server
            .expected_nonce(&context)
            .map_err(|_| DpopError::NonceMismatch)?
            .ok_or(DpopError::NonceRequired)?;
        let verify_request = DpopRequest::new("POST", &target)?.with_nonce(&expected);
        let parsed = UnverifiedDpopProof::parse(retry.as_header_value())?;
        let replay = InMemoryReplayStore::new(clock, 8)?;
        let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());
        verifier.verify(&parsed, &verify_request, &replay)?;

        client
            .record_success(&context, None)
            .map_err(|_| DpopError::NonceMismatch)?;
        assert_eq!(
            client
                .nonce_for(&context)
                .map_err(|_| DpopError::NonceMismatch)?,
            Some(current)
        );
    }
    Ok(())
}

#[test]
fn successful_response_nonce_rotation_is_used_on_next_proof() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = keylix_dpop::RandomProofIdGenerator;
    let client = InMemoryClientNonceStore::new(4)?;
    let server = InMemoryServerNonceStore::new(SequenceNonceGenerator::default(), 4)?;
    let context = NonceContext::new(NonceNamespace::ResourceServer, "server-a")?;
    let target = EffectiveRequestTarget::parse("https://server-a.example/resource")?;

    let first = server
        .issue_nonce(&context)
        .map_err(|_| DpopError::NonceMismatch)?;
    client
        .record_challenge(&context, &first)
        .map_err(|_| DpopError::NonceMismatch)?;
    let rotated = server
        .issue_nonce(&context)
        .map_err(|_| DpopError::NonceMismatch)?;
    client
        .record_success(&context, Some(&rotated))
        .map_err(|_| DpopError::NonceMismatch)?;

    let current = client
        .nonce_for(&context)
        .map_err(|_| DpopError::NonceMismatch)?
        .ok_or(DpopError::NonceRequired)?;
    let request = DpopRequest::new("GET", &target)?.with_nonce(&current);
    let proof = DpopProofBuilder::new(&signer, &clock, &ids).build(&request)?;
    assert_eq!(
        proof_nonce(proof.as_header_value())?,
        Some(rotated.as_header_value().to_owned())
    );
    Ok(())
}

#[test]
fn random_nonce_generator_has_expected_entropy_encoding_shape() -> Result<(), DpopError> {
    let generator = RandomNonceGenerator;
    let mut values = std::collections::HashSet::new();
    for _ in 0..256 {
        let nonce = generator.generate().map_err(|_| DpopError::NonceMismatch)?;
        assert_eq!(nonce.as_header_value().len(), 22);
        assert!(!nonce.as_header_value().contains('='));
        values.insert(nonce.as_header_value().to_owned());
    }
    assert_eq!(values.len(), 256);
    Ok(())
}

#[test]
fn replay_store_reports_process_local_security_metadata() -> Result<(), DpopError> {
    let store = InMemoryReplayStore::new(FixedClock(1_700_000_000), 32)?;
    let metadata = store.metadata();
    assert_eq!(metadata.capacity(), 32);
    assert_eq!(
        metadata.topology(),
        keylix_dpop::StateStoreTopology::SingleProcess
    );
    assert_eq!(
        metadata.consistency(),
        keylix_dpop::StateStoreConsistency::ProcessLocalAtomic
    );
    Ok(())
}
