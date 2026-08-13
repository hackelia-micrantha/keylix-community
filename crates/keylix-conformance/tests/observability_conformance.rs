//! Safe-observability and explicit-evidence conformance for ADR-0011.

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopNonce, DpopPortError, DpopProofBuilder, DpopRequest, DpopSigner,
    DpopVerifier, EffectiveRequestTarget, InMemoryReplayStore, RandomProofIdGenerator,
    UnverifiedDpopProof, VerificationPolicy,
};
use keylix_http::ForwardingHeaders;
use keylix_oauth::{HostValidatedToken, TokenValidationSource, compose_sender_binding};
use keylix_observe::{
    EvidenceError, EvidenceKeyPolicy, FailureClass, Operation, SenderBindingEvidence,
    TelemetryEvent,
};

const ACCESS_TOKEN: &[u8] = b"kx-secret-access-token-OBS-001";
const NONCE_VALUE: &str = "kx-secret-nonce-OBS-001";
const ATTACKER_HEADER: &str = "kx-attacker-forwarded-value-OBS-001";

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

fn sender_binding()
-> Result<(keylix_oauth::VerifiedSenderBinding, String), Box<dyn std::error::Error>> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let target = EffectiveRequestTarget::parse("https://resource.example/items")?;
    let request = DpopRequest::new("GET", &target)?.with_access_token(ACCESS_TOKEN);
    let proof = DpopProofBuilder::new(&signer, &clock, &ids).build(&request)?;
    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    let verified = DpopVerifier::new(&clock, VerificationPolicy::default())
        .verify(&parsed, &request, &replay)?;
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    let validated = HostValidatedToken::from_host_validated_jwt(ACCESS_TOKEN, Some(&jkt))?;
    let binding = compose_sender_binding(&verified, ACCESS_TOKEN, &validated)?;
    Ok((binding, jkt))
}

#[test]
fn kx_obs_001_ordinary_diagnostics_do_not_reflect_seeded_sensitive_values()
-> Result<(), Box<dyn std::error::Error>> {
    let (binding, jkt) = sender_binding()?;
    let nonce = DpopNonce::new(NONCE_VALUE)?;
    let forwarded = ForwardingHeaders::new().with_forwarded(ATTACKER_HEADER);
    let invalid_target = EffectiveRequestTarget::parse("https://example.com/%ZZ")
        .err()
        .ok_or_else(|| std::io::Error::other("malformed percent encoding unexpectedly accepted"))?;
    let telemetry = TelemetryEvent::failure(Operation::ProofVerify, FailureClass::MalformedInput);
    let evidence =
        SenderBindingEvidence::from_binding(&binding, 1_700_000_001, EvidenceKeyPolicy::Include)?;

    let ordinary = format!(
        "binding={binding:?} nonce={nonce:?} forwarded={forwarded:?} error={invalid_target} telemetry={telemetry:?} labels={:?} evidence={evidence:?}",
        telemetry.labels(),
    );

    for forbidden in [
        String::from_utf8(ACCESS_TOKEN.to_vec())?,
        NONCE_VALUE.to_owned(),
        ATTACKER_HEADER.to_owned(),
        jkt,
        "%ZZ".to_owned(),
    ] {
        assert!(
            !ordinary.contains(&forbidden),
            "KX-OBS-001: ordinary diagnostics exposed seeded sensitive/attacker-controlled material"
        );
    }
    Ok(())
}

#[test]
fn kx_obs_002_telemetry_schema_is_bounded_and_has_no_sender_identifier()
-> Result<(), Box<dyn std::error::Error>> {
    let (_binding, jkt) = sender_binding()?;
    let success = TelemetryEvent::success(Operation::OAuthSenderBinding);
    let failure = TelemetryEvent::failure(Operation::McpServer, FailureClass::TokenBindingFailure);

    let success_labels = success.labels();
    assert_eq!(success_labels.mechanism(), "dpop");
    assert_eq!(success_labels.algorithm(), "es256-p256");
    assert_eq!(success_labels.operation(), "oauth-sender-binding");
    assert_eq!(success_labels.result(), "success");
    assert_eq!(success_labels.failure_class(), None);

    let failure_labels = failure.labels();
    assert_eq!(failure_labels.result(), "failure");
    assert_eq!(
        failure_labels.failure_class(),
        Some("token-binding-failure")
    );

    let rendered = format!("{success:?} {success_labels:?} {failure:?} {failure_labels:?}");
    assert!(!rendered.contains(&jkt));
    assert!(!rendered.contains("access-token"));
    assert!(!rendered.contains("nonce"));
    assert!(!rendered.contains("jti"));
    Ok(())
}

#[test]
fn kx_obs_003_evidence_omits_key_by_default_and_includes_it_only_explicitly()
-> Result<(), Box<dyn std::error::Error>> {
    let (binding, jkt) = sender_binding()?;

    let omitted =
        SenderBindingEvidence::from_binding(&binding, 1_700_000_001, EvidenceKeyPolicy::default())?;
    assert_eq!(omitted.key_thumbprint(), None);
    assert_eq!(
        omitted.validation_source(),
        TokenValidationSource::ValidatedJwt
    );
    assert_eq!(omitted.proof_issued_at_unix(), 1_700_000_000);
    assert_eq!(omitted.verified_at_unix(), 1_700_000_001);
    assert!(omitted.replay_checked());

    let included =
        SenderBindingEvidence::from_binding(&binding, 1_700_000_001, EvidenceKeyPolicy::Include)?;
    let explicit = included
        .key_thumbprint()
        .ok_or_else(|| std::io::Error::other("explicit evidence key policy omitted sender key"))?
        .to_base64url();
    assert_eq!(explicit, jkt);

    let ordinary_debug = format!("omitted={omitted:?} included={included:?}");
    assert!(!ordinary_debug.contains(&jkt));
    assert!(!ordinary_debug.contains("access-token"));
    assert!(!ordinary_debug.contains(NONCE_VALUE));
    assert!(!ordinary_debug.contains("jti"));

    assert!(matches!(
        SenderBindingEvidence::from_binding(&binding, 0, EvidenceKeyPolicy::Omit),
        Err(EvidenceError::InvalidVerificationTime)
    ));
    Ok(())
}
