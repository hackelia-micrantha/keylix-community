//! Stateful replay, nonce, and diagnostic conformance cases.

use std::sync::{Arc, Barrier};

use keylix_dpop::{
    AwsLcP256Signer, ClientNonceStore, Clock, DpopError, DpopNonce, DpopPortError,
    DpopProofBuilder, DpopRequest, DpopVerifier, EffectiveRequestTarget, InMemoryClientNonceStore,
    InMemoryReplayStore, InMemoryServerNonceStore, NonceContext, NonceGenerator, NonceNamespace,
    ProofId, ProofIdGenerator, ReplayStatus, ReplayStore, ServerNonceStore, UnverifiedDpopProof,
    VerificationPolicy,
};

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
        DpopNonce::new(format!("conformance-nonce-{value}")).map_err(|_| DpopPortError)
    }
}

struct FailingReplayStore;

impl ReplayStore for FailingReplayStore {
    fn check_and_record(
        &self,
        _key: &keylix_dpop::ReplayKey,
        _expires_at_unix: i64,
    ) -> Result<ReplayStatus, DpopPortError> {
        Err(DpopPortError)
    }
}

#[test]
fn kx_dpop_014_concurrent_replay_admits_exactly_one_fresh_request() -> Result<(), DpopError> {
    const THREADS: usize = 12;

    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = ConstantId("conformance-replay-jti");
    let target = EffectiveRequestTarget::parse("https://api.example.com/replay")?;
    let request = DpopRequest::new("GET", &target)?;
    let proof = DpopProofBuilder::new(&signer, &clock, &ids).build(&request)?;
    let proof = Arc::new(proof.as_header_value().to_owned());
    let store = Arc::new(InMemoryReplayStore::new(clock, 32)?);
    let barrier = Arc::new(Barrier::new(THREADS));

    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let proof = Arc::clone(&proof);
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || -> Result<bool, DpopError> {
            let parsed = UnverifiedDpopProof::parse(&proof)?;
            let target = EffectiveRequestTarget::parse("https://api.example.com/replay")?;
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

    let mut accepted = 0;
    for handle in handles {
        accepted += usize::from(
            handle
                .join()
                .map_err(|_| DpopError::ReplayStoreUnavailable)??,
        );
    }
    assert_eq!(
        accepted, 1,
        "KX-DPOP-014: concurrent replay admitted more than one request"
    );
    Ok(())
}

#[test]
fn kx_dpop_014_replay_backend_failure_fails_closed() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = ConstantId("store-failure-jti");
    let target = EffectiveRequestTarget::parse("https://api.example.com/failure")?;
    let request = DpopRequest::new("GET", &target)?;
    let proof = DpopProofBuilder::new(&signer, &clock, &ids).build(&request)?;
    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

    assert!(
        matches!(
            verifier.verify(&parsed, &request, &FailingReplayStore),
            Err(DpopError::ReplayStoreUnavailable)
        ),
        "KX-DPOP-014: replay backend failure did not fail closed"
    );
    Ok(())
}

#[test]
fn kx_dpop_010_build_005_nonce_namespaces_and_rotation_are_isolated() -> Result<(), DpopError> {
    let client = InMemoryClientNonceStore::new(8)?;
    let server = InMemoryServerNonceStore::new(SequenceNonceGenerator::default(), 8)?;
    let as_context = NonceContext::new(NonceNamespace::AuthorizationServer, "server-a")?;
    let rs_context = NonceContext::new(NonceNamespace::ResourceServer, "server-a")?;
    let other_rs = NonceContext::new(NonceNamespace::ResourceServer, "server-b")?;

    let issued = server
        .issue_nonce(&rs_context)
        .map_err(|_| DpopError::NonceMismatch)?;
    client
        .record_challenge(&rs_context, &issued)
        .map_err(|_| DpopError::NonceMismatch)?;

    assert_eq!(
        client
            .nonce_for(&as_context)
            .map_err(|_| DpopError::NonceMismatch)?,
        None,
        "KX-DPOP-010: RS nonce leaked into AS namespace"
    );
    assert_eq!(
        client
            .nonce_for(&other_rs)
            .map_err(|_| DpopError::NonceMismatch)?,
        None,
        "KX-DPOP-010: nonce leaked across resource servers"
    );

    let rotated = server
        .issue_nonce(&rs_context)
        .map_err(|_| DpopError::NonceMismatch)?;
    client
        .record_success(&rs_context, Some(&rotated))
        .map_err(|_| DpopError::NonceMismatch)?;
    assert_eq!(
        client
            .nonce_for(&rs_context)
            .map_err(|_| DpopError::NonceMismatch)?,
        Some(rotated),
        "KX-BUILD-005: successful-response nonce was not retained"
    );
    Ok(())
}

#[test]
fn kx_obs_001_debug_surfaces_do_not_reflect_credentials() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = ConstantId("distinctive-secret-jti");
    let nonce = DpopNonce::new("distinctive-secret-nonce")?;
    let target = EffectiveRequestTarget::parse("https://secret.example/distinctive-secret-path")?;
    let request = DpopRequest::new("POST", &target)?
        .with_access_token(b"distinctive-secret-token")
        .with_nonce(&nonce);
    let proof = DpopProofBuilder::new(&signer, &clock, &ids).build(&request)?;

    let combined = format!("{request:?} {proof:?} {nonce:?} {signer:?}");
    for forbidden in [
        "distinctive-secret-jti",
        "distinctive-secret-nonce",
        "distinctive-secret-token",
        "secret.example",
        "distinctive-secret-path",
        proof.as_header_value(),
    ] {
        assert!(
            !combined.contains(forbidden),
            "KX-OBS-001: ordinary Debug output reflected credential material"
        );
    }
    Ok(())
}
