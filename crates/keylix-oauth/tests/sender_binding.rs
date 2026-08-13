//! Server-side OAuth validation + `DPoP` sender-binding composition tests.

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopPortError, DpopProofBuilder, DpopRequest, DpopSigner,
    DpopVerifier, EffectiveRequestTarget, InMemoryReplayStore, RandomProofIdGenerator,
    UnverifiedDpopProof, VerificationPolicy, VerifiedDpopProof,
};
use keylix_oauth::{
    HostValidatedToken, OAuthDpopError, TokenValidationSource, compose_sender_binding,
};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

fn verify_for_token(
    signer: &AwsLcP256Signer,
    token: &[u8],
) -> Result<VerifiedDpopProof, DpopError> {
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let target = EffectiveRequestTarget::parse("https://resource.example/items")?;
    let request = DpopRequest::new("GET", &target)?.with_access_token(token);
    let proof = DpopProofBuilder::new(signer, &clock, &ids).build(&request)?;
    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    DpopVerifier::new(&clock, VerificationPolicy::default()).verify(&parsed, &request, &replay)
}

fn verify_without_token(signer: &AwsLcP256Signer) -> Result<VerifiedDpopProof, DpopError> {
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let target = EffectiveRequestTarget::parse("https://issuer.example/token")?;
    let request = DpopRequest::new("POST", &target)?;
    let proof = DpopProofBuilder::new(signer, &clock, &ids).build(&request)?;
    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    DpopVerifier::new(&clock, VerificationPolicy::default()).verify(&parsed, &request, &replay)
}

#[test]
fn kx_dpop_013_oauth_003_validated_jwt_composes_sender_binding() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let token = b"access-token-a";
    let proof = verify_for_token(&signer, token)?;
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    let validated = HostValidatedToken::from_host_validated_jwt(token, Some(&jkt))?;

    let binding = compose_sender_binding(&proof, token, &validated)?;
    assert_eq!(
        binding.key_thumbprint(),
        signer.public_jwk().thumbprint(),
        "KX-DPOP-013: composed key differs from validated proof/token key"
    );
    assert_eq!(
        binding.validation_source(),
        TokenValidationSource::ValidatedJwt
    );
    Ok(())
}

#[test]
fn kx_oauth_003_authenticated_active_introspection_composes() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let token = b"opaque-access-token";
    let proof = verify_for_token(&signer, token)?;
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    let validated =
        HostValidatedToken::from_host_authenticated_introspection(token, true, Some(&jkt))?;

    let binding = compose_sender_binding(&proof, token, &validated)?;
    assert_eq!(
        binding.validation_source(),
        TokenValidationSource::AuthenticatedIntrospection
    );
    Ok(())
}

#[test]
fn kx_oauth_003_inactive_introspection_never_enters_trusted_boundary() -> Result<(), DpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    assert!(matches!(
        HostValidatedToken::from_host_authenticated_introspection(
            b"inactive-token",
            false,
            Some(&jkt),
        ),
        Err(OAuthDpopError::TokenInactive)
    ));
    Ok(())
}

#[test]
fn kx_oauth_002_token_a_validation_cannot_bind_token_b() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let token_a = b"access-token-a";
    let token_b = b"access-token-b";
    let proof_b = verify_for_token(&signer, token_b)?;
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    let validated_a = HostValidatedToken::from_host_validated_jwt(token_a, Some(&jkt))?;

    assert!(matches!(
        compose_sender_binding(&proof_b, token_b, &validated_a),
        Err(OAuthDpopError::TokenIdentityMismatch)
    ));
    Ok(())
}

#[test]
fn kx_dpop_013_proof_key_must_match_trusted_token_confirmation() -> Result<(), OAuthDpopError> {
    let proof_signer = AwsLcP256Signer::generate()?;
    let token_signer = AwsLcP256Signer::generate()?;
    let token = b"access-token-a";
    let proof = verify_for_token(&proof_signer, token)?;
    let wrong_jkt = token_signer.public_jwk().thumbprint().to_base64url();
    let validated = HostValidatedToken::from_host_validated_jwt(token, Some(&wrong_jkt))?;

    assert!(matches!(
        compose_sender_binding(&proof, token, &validated),
        Err(OAuthDpopError::TokenBindingMismatch)
    ));
    Ok(())
}

#[test]
fn kx_dpop_013_missing_or_malformed_confirmation_fails_closed() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let token = b"access-token-a";
    let proof = verify_for_token(&signer, token)?;
    let unbound = HostValidatedToken::from_host_validated_jwt(token, None)?;

    assert!(matches!(
        compose_sender_binding(&proof, token, &unbound),
        Err(OAuthDpopError::TokenBindingMissing)
    ));
    assert!(matches!(
        HostValidatedToken::from_host_validated_jwt(token, Some("decoded-but-untrusted-cnf")),
        Err(OAuthDpopError::TokenBindingMalformed)
    ));
    Ok(())
}

#[test]
fn kx_dpop_015_tokenless_verified_proof_cannot_become_sender_binding() -> Result<(), OAuthDpopError>
{
    let signer = AwsLcP256Signer::generate()?;
    let token = b"access-token-a";
    let proof = verify_without_token(&signer)?;
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    let validated = HostValidatedToken::from_host_validated_jwt(token, Some(&jkt))?;

    assert!(matches!(
        compose_sender_binding(&proof, token, &validated),
        Err(OAuthDpopError::ProofNotAccessTokenBound)
    ));
    Ok(())
}

#[test]
fn kx_obs_001_binding_debug_does_not_emit_token_or_jkt() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let token = b"distinctive-secret-access-token";
    let proof = verify_for_token(&signer, token)?;
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    let validated = HostValidatedToken::from_host_validated_jwt(token, Some(&jkt))?;
    let binding = compose_sender_binding(&proof, token, &validated)?;
    let debug = format!("{validated:?} {binding:?}");

    assert!(!debug.contains("distinctive-secret-access-token"));
    assert!(!debug.contains(&jkt));
    Ok(())
}
