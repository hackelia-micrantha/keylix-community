//! Deterministic regressions promoted from AI-assisted adversarial discovery.

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopPortError, DpopProofBuilder, DpopRequest, DpopVerifier,
    EffectiveRequestTarget, InMemoryReplayStore, RandomProofIdGenerator, UnverifiedDpopProof,
    VerificationPolicy,
};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

#[test]
fn ai_promoted_query_parameter_reordering_preserves_normalized_dpop_target_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let proof_target = EffectiveRequestTarget::parse("https://api.example.test/resource?a=1&b=2")?;
    let reordered_target =
        EffectiveRequestTarget::parse("https://api.example.test/resource?b=2&a=1")?;
    assert_eq!(proof_target, reordered_target);

    let proof_request = DpopRequest::new("GET", &proof_target)?;
    let proof =
        DpopProofBuilder::new(&signer, &clock, &RandomProofIdGenerator).build(&proof_request)?;
    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let verification_request = DpopRequest::new("GET", &reordered_target)?;
    let replay = InMemoryReplayStore::new(clock, 8)?;

    DpopVerifier::new(&clock, VerificationPolicy::default()).verify(
        &parsed,
        &verification_request,
        &replay,
    )?;
    Ok(())
}
