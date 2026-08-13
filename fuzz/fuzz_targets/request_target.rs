#![no_main]

use keylix_dpop::EffectiveRequestTarget;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8 * 1024 {
        return;
    }
    if let Ok(input) = std::str::from_utf8(data) {
        let _ = EffectiveRequestTarget::parse(input);
    }
});
