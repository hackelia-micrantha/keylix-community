//! Deterministic RFC-level conformance tests that use Keylix public APIs only.

use keylix_core::{JwkError, PublicP256Jwk};
use keylix_dpop::{
    Clock, DpopError, DpopPortError, DpopRequest, DpopVerifier, EffectiveRequestTarget,
    InMemoryReplayStore, UnverifiedDpopProof, VerificationPolicy,
};

const RFC_7515_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const RFC_7515_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
const RFC_7638_THUMBPRINT: &str = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U";

// Generated independently with Python cryptography backed by OpenSSL from a
// fixed P-256 private scalar. Keylix only receives the public JWK and compact
// JWS fixture, providing an implementation-independent ES256 cross-check.
const INDEPENDENT_ES256_PROOF: &str = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiUUU4N05qUzR3QnBpXzBTdWFiT0xqRlN4S1VZenNHdy1lRWFXS256RkJydyIsInkiOiJWU3hDeERKcF9wRWNaTjdyNzlIdHdNODYzSWlyZHdqUnZTNjVZcGg1WWhNIn19.eyJqdGkiOiJpbmRlcGVuZGVudC1vcGVuc3NsLXZlY3RvciIsImh0bSI6IkdFVCIsImh0dSI6Imh0dHBzOi8vYXBpLmV4YW1wbGUuY29tL3Jlc291cmNlIiwiaWF0IjoxNzAwMDAwMDAwfQ.VXYfCjM-l-VQGZumJK0bujjM32d7YhqGtQ9x6yzSE4dEPV6rb0IaWjz2RmBbVmj9sUWfZCTM-PUf19i1eQtT1g";

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

fn rfc_public_jwk(extra: &str) -> String {
    format!(r#"{{"kty":"EC","crv":"P-256","x":"{RFC_7515_X}","y":"{RFC_7515_Y}"{extra}}}"#)
}

#[test]
fn kx_jwk_001_rfc7638_thumbprint_vector() -> Result<(), JwkError> {
    let jwk = PublicP256Jwk::from_json(&rfc_public_jwk(""))?;
    assert_eq!(
        jwk.thumbprint().to_base64url(),
        RFC_7638_THUMBPRINT,
        "KX-JWK-001: RFC 7638 thumbprint mismatch"
    );
    Ok(())
}

#[test]
fn kx_jwk_001_optional_metadata_and_member_order_are_identity_neutral() -> Result<(), JwkError> {
    let canonical = PublicP256Jwk::from_json(&rfc_public_jwk(""))?;
    let decorated = PublicP256Jwk::from_json(&rfc_public_jwk(
        r#", "kid":"conformance", "alg":"ES256", "use":"sig""#,
    ))?;
    let reordered = PublicP256Jwk::from_json(&format!(
        "{{\n \"y\":\"{RFC_7515_Y}\", \"x\":\"{RFC_7515_X}\", \"crv\":\"P-256\", \"kty\":\"EC\"\n}}"
    ))?;

    assert_eq!(
        canonical.thumbprint(),
        decorated.thumbprint(),
        "KX-JWK-001: optional metadata changed key identity"
    );
    assert_eq!(
        canonical.thumbprint(),
        reordered.thumbprint(),
        "KX-JWK-001: JSON member order changed key identity"
    );
    Ok(())
}

#[test]
fn kx_jwk_002_004_public_jwk_boundary_rejects_ambiguous_or_private_input() {
    let duplicate = format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{RFC_7515_X}","x":"{RFC_7515_X}","y":"{RFC_7515_Y}"}}"#
    );
    let private = rfc_public_jwk(r#", "d":"forbidden""#);
    let wrong_curve =
        format!(r#"{{"kty":"EC","crv":"P-384","x":"{RFC_7515_X}","y":"{RFC_7515_Y}"}}"#);
    let padded = format!(r#"{{"kty":"EC","crv":"P-256","x":"{RFC_7515_X}=","y":"{RFC_7515_Y}"}}"#);

    assert_eq!(
        PublicP256Jwk::from_json(&duplicate),
        Err(JwkError::InvalidJson),
        "KX-JWK-002: duplicate required member accepted"
    );
    assert_eq!(
        PublicP256Jwk::from_json(&private),
        Err(JwkError::PrivateKeyMaterial),
        "KX-JWK-004: private material crossed public-key boundary"
    );
    assert_eq!(
        PublicP256Jwk::from_json(&wrong_curve),
        Err(JwkError::UnsupportedCurve),
        "KX-JWK-002: unsupported curve accepted"
    );
    assert!(
        matches!(
            PublicP256Jwk::from_json(&padded),
            Err(JwkError::InvalidCoordinateEncoding { coordinate: "x" })
        ),
        "KX-JWK-002: non-canonical coordinate encoding accepted"
    );
}

#[test]
fn kx_dpop_006_independent_openssl_es256_fixture_verifies() -> Result<(), DpopError> {
    let clock = FixedClock(1_700_000_000);
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let request = DpopRequest::new("GET", &target)?;
    let parsed = UnverifiedDpopProof::parse(INDEPENDENT_ES256_PROOF)?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

    verifier.verify(&parsed, &request, &replay)?;
    Ok(())
}

#[test]
fn kx_dpop_002_compact_jws_parser_rejects_malformed_corpus() {
    let oversized = "a".repeat(8_193);
    for proof in [
        "",
        "a",
        "a.b",
        "a.b.c.d",
        "*.e30.AA",
        "e30=.e30.AA",
        "e30.e30.AA",
        oversized.as_str(),
    ] {
        assert!(
            UnverifiedDpopProof::parse(proof).is_err(),
            "KX-DPOP-002: malformed compact proof unexpectedly parsed: {proof}"
        );
    }
}

#[test]
fn kx_dpop_009_request_target_normalization_is_idempotent() -> Result<(), DpopError> {
    let cases = [
        (
            "HTTPS://Example.COM:443/a/./b/../%7ec?ignored=1#fragment",
            "https://example.com/a/~c",
        ),
        ("http://EXAMPLE.com:80", "http://example.com/"),
        (
            "https://[2001:0DB8:0:0:0:0:0:1]:443/a",
            "https://[2001:db8::1]/a",
        ),
        ("https://example.com/a%2fb", "https://example.com/a%2Fb"),
    ];

    for (input, expected) in cases {
        let normalized = EffectiveRequestTarget::parse(input)?;
        assert_eq!(
            normalized.as_str(),
            expected,
            "KX-DPOP-009: unexpected normalization"
        );
        let reparsed = EffectiveRequestTarget::parse(normalized.as_str())?;
        assert_eq!(
            reparsed.as_str(),
            normalized.as_str(),
            "KX-DPOP-009: normalization was not idempotent"
        );
    }
    Ok(())
}

#[test]
fn kx_dpop_009_ambiguous_targets_fail_closed() {
    for input in [
        "ftp://example.com/a",
        "https://user@example.com/a",
        "https://example.com/%zz",
        "https://example.com:99999/a",
        "https://2001:db8::1/a",
        "https://[not-an-ip]/a",
    ] {
        assert!(
            EffectiveRequestTarget::parse(input).is_err(),
            "KX-DPOP-009: ambiguous or unsupported target accepted: {input}"
        );
    }
}
