//! Deterministic property-style sweeps over public Keylix APIs.

use std::collections::HashSet;

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopPortError, DpopProofBuilder, DpopRequest, DpopSigner,
    DpopVerifier, EffectiveRequestTarget, InMemoryReplayStore, RandomProofIdGenerator,
    UnverifiedDpopProof, VerificationPolicy,
};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

#[test]
fn property_kx_jwk_003_generated_thumbprints_are_stable_fixed_shape() -> Result<(), DpopError> {
    let mut observed = HashSet::new();

    for _ in 0..64 {
        let signer = AwsLcP256Signer::generate()?;
        let first = signer.public_jwk().thumbprint();
        let second = signer.public_jwk().thumbprint();
        let encoded = first.to_base64url();

        assert_eq!(
            first, second,
            "KX-JWK-003: repeated thumbprint calculation was not deterministic"
        );
        assert_eq!(
            first.as_bytes().len(),
            32,
            "KX-JWK-003: SHA-256 thumbprint was not 32 bytes"
        );
        assert_eq!(
            encoded.len(),
            43,
            "KX-JWK-003: unpadded SHA-256 base64url shape changed"
        );
        assert!(
            !encoded.contains('='),
            "KX-JWK-003: thumbprint unexpectedly used base64 padding"
        );
        observed.insert(encoded);
    }

    assert_eq!(
        observed.len(),
        64,
        "KX-JWK-003: generated public-key identities unexpectedly collided"
    );
    Ok(())
}

#[test]
fn property_kx_build_002_dpop_008_public_round_trip_across_request_bindings()
-> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let cases = [
        ("GET", "https://api.example.com/"),
        ("POST", "https://api.example.com/v1/items"),
        ("PATCH", "https://api.example.com/v1/items/7?ignored=yes"),
        ("DELETE", "HTTPS://API.EXAMPLE.COM:443/v1/items/7#ignored"),
    ];

    for (method, raw_target) in cases {
        let target = EffectiveRequestTarget::parse(raw_target)?;
        let request = DpopRequest::new(method, &target)?;
        let proof = DpopProofBuilder::new(&signer, &clock, &ids).build(&request)?;
        let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
        let replay = InMemoryReplayStore::new(clock, 4)?;
        let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

        verifier.verify(&parsed, &request, &replay)?;

        let wrong_method = if method == "GET" { "POST" } else { "GET" };
        let wrong_request = DpopRequest::new(wrong_method, &target)?;
        let wrong_store = InMemoryReplayStore::new(clock, 4)?;
        assert!(
            matches!(
                verifier.verify(&parsed, &wrong_request, &wrong_store),
                Err(DpopError::MethodMismatch)
            ),
            "KX-DPOP-008: proof moved across HTTP methods"
        );
    }
    Ok(())
}

#[test]
fn property_kx_dpop_009_normalization_is_idempotent_across_equivalent_forms()
-> Result<(), DpopError> {
    let forms = [
        "https://EXAMPLE.com:443/",
        "HTTPS://example.COM/",
        "https://example.com/a/./b/../c",
        "https://example.com/a/c?query=ignored",
        "https://example.com/%7Euser",
        "https://example.com/~user",
        "http://example.com:80/a",
        "http://EXAMPLE.COM/a#fragment",
    ];

    for raw in forms {
        let first = EffectiveRequestTarget::parse(raw)?;
        let second = EffectiveRequestTarget::parse(first.as_str())?;
        assert_eq!(
            first.as_str(),
            second.as_str(),
            "KX-DPOP-009: normalized request target changed after reparsing"
        );
    }
    Ok(())
}
