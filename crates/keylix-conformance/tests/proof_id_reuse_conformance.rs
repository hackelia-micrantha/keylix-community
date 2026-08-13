//! Replay evidence for an intentionally reused proof identifier.

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopPortError, DpopProofBuilder, DpopRequest, DpopVerifier,
    EffectiveRequestTarget, InMemoryReplayStore, ProofId, ProofIdGenerator, UnverifiedDpopProof,
    VerificationPolicy,
};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

struct ReusedProofId {
    value: ProofId,
}

impl ProofIdGenerator for ReusedProofId {
    fn generate(&self) -> Result<ProofId, DpopPortError> {
        Ok(self.value.clone())
    }
}

#[test]
fn kx_build_001_injected_reused_jti_is_detected_by_replay_state()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let generator = ReusedProofId {
        value: ProofId::new("intentionally-reused-proof-id")?,
    };
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let request = DpopRequest::new("POST", &target)?;
    let builder = DpopProofBuilder::new(&signer, &clock, &generator);
    let first = builder.build(&request)?;
    let second = builder.build(&request)?;

    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());
    let replay = InMemoryReplayStore::new(clock, 8)?;
    let first = UnverifiedDpopProof::parse(first.as_header_value())?;
    let second = UnverifiedDpopProof::parse(second.as_header_value())?;

    verifier.verify(&first, &request, &replay)?;
    assert!(matches!(
        verifier.verify(&second, &request, &replay),
        Err(DpopError::ReplayDetected)
    ));
    Ok(())
}
