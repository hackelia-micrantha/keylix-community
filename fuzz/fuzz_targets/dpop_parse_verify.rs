#![no_main]

use keylix_dpop::{
    Clock, DpopPortError, DpopRequest, DpopVerifier, EffectiveRequestTarget, InMemoryReplayStore,
    UnverifiedDpopProof, VerificationPolicy,
};
use libfuzzer_sys::fuzz_target;

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(1_700_000_000)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = UnverifiedDpopProof::parse(input) else {
        return;
    };
    let Ok(target) = EffectiveRequestTarget::parse("https://api.example.com/resource") else {
        return;
    };
    let Ok(request) = DpopRequest::new("GET", &target) else {
        return;
    };
    let Ok(store) = InMemoryReplayStore::new(FixedClock, 16) else {
        return;
    };
    let verifier = DpopVerifier::new(&FixedClock, VerificationPolicy::default());
    let _ = verifier.verify(&parsed, &request, &store);
});
