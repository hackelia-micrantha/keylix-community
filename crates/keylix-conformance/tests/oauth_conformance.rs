//! OAuth-level `DPoP` conformance over the public Keylix integration API.

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopNonce, DpopPortError, DpopProofBuilder, DpopRequest,
    DpopSigner, DpopVerifier, EffectiveRequestTarget, InMemoryClientNonceStore,
    InMemoryReplayStore, NonceContext, NonceNamespace, RandomProofIdGenerator, UnverifiedDpopProof,
    VerificationPolicy,
};
use keylix_oauth::{
    DpopRequiredClient, HostValidatedToken, NonceRetryBudget, OAuthDpopError,
    compose_sender_binding,
};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

fn verified_proof(
    signer: &AwsLcP256Signer,
    token: &[u8],
) -> Result<keylix_dpop::VerifiedDpopProof, DpopError> {
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;
    let request = DpopRequest::new("GET", &target)?.with_access_token(token);
    let proof = DpopProofBuilder::new(signer, &clock, &ids).build(&request)?;
    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    DpopVerifier::new(&clock, VerificationPolicy::default()).verify(&parsed, &request, &replay)
}

#[test]
fn kx_oauth_001_required_mode_has_no_bearer_success_path() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(4)?;
    let client = DpopRequiredClient::new(&signer, &clock, &ids, &nonces);
    let context = NonceContext::new(NonceNamespace::AuthorizationServer, "issuer")?;
    let endpoint = EffectiveRequestTarget::parse("https://issuer.example/token")?;

    let proof = client.token_request(&context, &endpoint)?;
    assert!(
        UnverifiedDpopProof::parse(proof.dpop_header_value()).is_ok(),
        "KX-OAUTH-001: token request did not carry a parseable DPoP proof"
    );
    assert!(
        matches!(
            client.accept_token_response("Bearer", "access-token-a".to_owned(), None),
            Err(OAuthDpopError::TokenTypeNotDpop)
        ),
        "KX-OAUTH-001: DPoP-required mode accepted a Bearer token"
    );
    client.accept_token_response("DPoP", "access-token-a".to_owned(), None)?;
    Ok(())
}

#[test]
fn kx_oauth_002_003_exact_token_and_trusted_confirmation_are_both_required()
-> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let other = AwsLcP256Signer::generate()?;
    let token_a = b"access-token-a";
    let token_b = b"access-token-b";
    let proof = verified_proof(&signer, token_b)?;
    let signer_jkt = signer.public_jwk().thumbprint().to_base64url();
    let other_jkt = other.public_jwk().thumbprint().to_base64url();

    let token_a_validation =
        HostValidatedToken::from_host_validated_jwt(token_a, Some(&signer_jkt))?;
    assert!(
        matches!(
            compose_sender_binding(&proof, token_b, &token_a_validation),
            Err(OAuthDpopError::TokenIdentityMismatch)
        ),
        "KX-OAUTH-002: token-A validation metadata composed with token-B bytes"
    );

    let wrong_key_validation =
        HostValidatedToken::from_host_validated_jwt(token_b, Some(&other_jkt))?;
    assert!(
        matches!(
            compose_sender_binding(&proof, token_b, &wrong_key_validation),
            Err(OAuthDpopError::TokenBindingMismatch)
        ),
        "KX-OAUTH-003: trusted cnf.jkt mismatch was accepted"
    );

    let valid = HostValidatedToken::from_host_validated_jwt(token_b, Some(&signer_jkt))?;
    compose_sender_binding(&proof, token_b, &valid)?;
    Ok(())
}

#[test]
fn kx_oauth_004_resource_auth_uses_dpop_and_fresh_proof() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(4)?;
    let client = DpopRequiredClient::new(&signer, &clock, &ids, &nonces);
    let tokens = client.accept_token_response("DPoP", "access-token-a".to_owned(), None)?;
    let context = NonceContext::new(NonceNamespace::ResourceServer, "resource")?;
    let target = EffectiveRequestTarget::parse("https://api.example.com/resource")?;

    let first = client.protected_resource(&context, "GET", &target, tokens.access_token())?;
    let second = client.protected_resource(&context, "GET", &target, tokens.access_token())?;
    assert_eq!(
        first.authorization_header_value(),
        "DPoP access-token-a",
        "KX-OAUTH-004: protected resource did not use the DPoP authorization scheme"
    );
    assert_ne!(
        first.dpop_header_value(),
        second.dpop_header_value(),
        "KX-OAUTH-004: proof-bearing protected-resource decoration was reused"
    );
    Ok(())
}

#[test]
fn kx_oauth_005_refresh_relationship_is_key_pinned() -> Result<(), OAuthDpopError> {
    let signer_a = AwsLcP256Signer::generate()?;
    let signer_b = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(4)?;
    let first_client = DpopRequiredClient::new(&signer_a, &clock, &ids, &nonces);
    let tokens = first_client.accept_token_response(
        "DPoP",
        "access-token-a".to_owned(),
        Some("refresh-token-a".to_owned()),
    )?;
    let refresh = tokens
        .refresh_token()
        .ok_or(OAuthDpopError::InvalidCredential)?;
    let context = NonceContext::new(NonceNamespace::AuthorizationServer, "issuer")?;
    let endpoint = EffectiveRequestTarget::parse("https://issuer.example/token")?;

    first_client.refresh_token_request(&context, &endpoint, refresh)?;

    let second_client = DpopRequiredClient::new(&signer_b, &clock, &ids, &nonces);
    assert!(
        matches!(
            second_client.refresh_token_request(&context, &endpoint, refresh),
            Err(OAuthDpopError::ProofKeyContinuityMismatch)
        ),
        "KX-OAUTH-005: refresh relationship silently moved to another proof key"
    );
    Ok(())
}

#[test]
fn kx_oauth_006_nonce_retry_is_fresh_scoped_and_bounded() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(4)?;
    let client = DpopRequiredClient::new(&signer, &clock, &ids, &nonces);
    let context = NonceContext::new(NonceNamespace::AuthorizationServer, "issuer")?;
    let endpoint = EffectiveRequestTarget::parse("https://issuer.example/token")?;

    let first = client.token_request(&context, &endpoint)?;
    let nonce = DpopNonce::new("challenge-nonce")?;
    let mut budget = NonceRetryBudget::single_retry();
    client.record_nonce_challenge(&context, &nonce, &mut budget)?;
    let retry = client.token_request(&context, &endpoint)?;
    assert_ne!(
        first.dpop_header_value(),
        retry.dpop_header_value(),
        "KX-OAUTH-006: nonce retry reused the original proof"
    );
    assert!(
        matches!(
            client.record_nonce_challenge(&context, &nonce, &mut budget),
            Err(OAuthDpopError::NonceRetryLimitExceeded)
        ),
        "KX-OAUTH-006: nonce challenge could drive an unbounded retry loop"
    );

    let parsed = UnverifiedDpopProof::parse(retry.dpop_header_value())?;
    let expected = DpopRequest::new("POST", &endpoint)?.with_nonce(&nonce);
    let replay = InMemoryReplayStore::new(clock, 4)?;
    DpopVerifier::new(&clock, VerificationPolicy::default()).verify(&parsed, &expected, &replay)?;
    Ok(())
}
