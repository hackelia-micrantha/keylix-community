//! Stale-nonce rejection across server-side nonce rotation.

use std::sync::atomic::{AtomicU64, Ordering};

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopNonce, DpopPortError, DpopProofBuilder, DpopRequest,
    DpopVerifier, EffectiveRequestTarget, InMemoryReplayStore, InMemoryServerNonceStore,
    NonceContext, NonceGenerator, NonceNamespace, RandomProofIdGenerator, ServerNonceStore,
    UnverifiedDpopProof, VerificationPolicy,
};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

#[derive(Default)]
struct SequenceNonceGenerator(AtomicU64);

impl NonceGenerator for SequenceNonceGenerator {
    fn generate(&self) -> Result<DpopNonce, DpopPortError> {
        let value = self.0.fetch_add(1, Ordering::SeqCst);
        DpopNonce::new(format!("server-nonce-{value}")).map_err(|_| DpopPortError)
    }
}

#[test]
fn stale_nonce_after_server_rotation_is_rejected() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let server = InMemoryServerNonceStore::new(SequenceNonceGenerator::default(), 4)?;
    let context = NonceContext::new(NonceNamespace::ResourceServer, "server-a")?;
    let target = EffectiveRequestTarget::parse("https://server-a.example/resource")?;

    let first = server
        .issue_nonce(&context)
        .map_err(|_| DpopError::NonceMismatch)?;
    let stale_request = DpopRequest::new("GET", &target)?.with_nonce(&first);
    let stale_proof = DpopProofBuilder::new(&signer, &clock, &ids).build(&stale_request)?;

    let current = server
        .issue_nonce(&context)
        .map_err(|_| DpopError::NonceMismatch)?;
    let verify_request = DpopRequest::new("GET", &target)?.with_nonce(&current);
    let parsed = UnverifiedDpopProof::parse(stale_proof.as_header_value())?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

    assert!(matches!(
        verifier.verify(&parsed, &verify_request, &replay),
        Err(DpopError::NonceMismatch)
    ));
    Ok(())
}
