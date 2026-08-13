#![no_main]

use keylix_core::PublicP256Jwk;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    if let Ok(input) = std::str::from_utf8(data) {
        let _ = PublicP256Jwk::from_json(input);
    }
});
