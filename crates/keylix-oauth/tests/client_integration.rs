//! Transport-agnostic DPoP-required OAuth client integration tests.

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopNonce, DpopPortError, DpopRequest, DpopVerifier,
    EffectiveRequestTarget, InMemoryClientNonceStore, InMemoryReplayStore, NonceContext,
    NonceNamespace, RandomProofIdGenerator, UnverifiedDpopProof, VerificationPolicy,
};
use keylix_oauth::{DpopRequiredClient, NonceRetryBudget, OAuthDpopError};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

#[test]
fn kx_oauth_001_token_request_is_fresh_and_bearer_response_is_rejected()
-> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(8)?;
    let client = DpopRequiredClient::new(&signer, &clock, &ids, &nonces);
    let context = NonceContext::new(NonceNamespace::AuthorizationServer, "issuer-a")?;
    let endpoint = EffectiveRequestTarget::parse("https://issuer.example/token")?;

    let first = client.token_request(&context, &endpoint)?;
    let second = client.token_request(&context, &endpoint)?;
    assert_ne!(
        first.dpop_header_value(),
        second.dpop_header_value(),
        "KX-OAUTH-001: token-request proof was reused"
    );
    assert!(matches!(
        client.accept_token_response("Bearer", "access-token-a".to_owned(), None),
        Err(OAuthDpopError::TokenTypeNotDpop)
    ));
    client.accept_token_response("DPoP", "access-token-a".to_owned(), None)?;
    Ok(())
}

#[test]
fn kx_oauth_006_as_nonce_challenge_causes_one_fresh_bounded_retry() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(8)?;
    let client = DpopRequiredClient::new(&signer, &clock, &ids, &nonces);
    let context = NonceContext::new(NonceNamespace::AuthorizationServer, "issuer-a")?;
    let endpoint = EffectiveRequestTarget::parse("https://issuer.example/token")?;

    let initial = client.token_request(&context, &endpoint)?;
    let nonce = DpopNonce::new("as-challenge-nonce")?;
    let mut budget = NonceRetryBudget::single_retry();
    client.record_nonce_challenge(&context, &nonce, &mut budget)?;
    assert!(!budget.can_retry());
    let retry = client.token_request(&context, &endpoint)?;
    assert_ne!(initial.dpop_header_value(), retry.dpop_header_value());
    assert!(matches!(
        client.record_nonce_challenge(&context, &nonce, &mut budget),
        Err(OAuthDpopError::NonceRetryLimitExceeded)
    ));

    let parsed = UnverifiedDpopProof::parse(retry.dpop_header_value())?;
    let expected = DpopRequest::new("POST", &endpoint)?.with_nonce(&nonce);
    let replay = InMemoryReplayStore::new(clock, 8)?;
    DpopVerifier::new(&clock, VerificationPolicy::default()).verify(&parsed, &expected, &replay)?;
    Ok(())
}

#[test]
fn kx_oauth_004_resource_request_uses_dpop_scheme_and_fresh_proof() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(8)?;
    let client = DpopRequiredClient::new(&signer, &clock, &ids, &nonces);
    let token_set = client.accept_token_response(
        "DPoP",
        "access-token-a".to_owned(),
        Some("refresh token,visible".to_owned()),
    )?;
    let context = NonceContext::new(NonceNamespace::ResourceServer, "resource-a")?;
    let target = EffectiveRequestTarget::parse("https://api.example.com/items")?;

    let first = client.protected_resource(&context, "GET", &target, token_set.access_token())?;
    let second = client.protected_resource(&context, "GET", &target, token_set.access_token())?;
    assert_eq!(first.authorization_header_value(), "DPoP access-token-a");
    assert!(!first.authorization_header_value().starts_with("Bearer "));
    assert_ne!(first.dpop_header_value(), second.dpop_header_value());

    let parsed = UnverifiedDpopProof::parse(first.dpop_header_value())?;
    let expected = DpopRequest::new("GET", &target)?.with_access_token(b"access-token-a");
    let replay = InMemoryReplayStore::new(clock, 8)?;
    DpopVerifier::new(&clock, VerificationPolicy::default()).verify(&parsed, &expected, &replay)?;
    Ok(())
}

#[test]
fn kx_oauth_006_rs_nonce_challenge_and_success_rotation_apply_to_next_attempt()
-> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(8)?;
    let client = DpopRequiredClient::new(&signer, &clock, &ids, &nonces);
    let token_set = client.accept_token_response("DPoP", "access-token-a".to_owned(), None)?;
    let context = NonceContext::new(NonceNamespace::ResourceServer, "resource-a")?;
    let target = EffectiveRequestTarget::parse("https://api.example.com/items")?;

    let challenged = DpopNonce::new("rs-challenge-nonce")?;
    let mut budget = NonceRetryBudget::single_retry();
    client.record_nonce_challenge(&context, &challenged, &mut budget)?;
    let first = client.protected_resource(&context, "GET", &target, token_set.access_token())?;

    let rotated = DpopNonce::new("rs-success-nonce")?;
    client.record_success_nonce(&context, Some(&rotated))?;
    let second = client.protected_resource(&context, "GET", &target, token_set.access_token())?;
    assert_ne!(first.dpop_header_value(), second.dpop_header_value());

    let first_parsed = UnverifiedDpopProof::parse(first.dpop_header_value())?;
    let first_expected = DpopRequest::new("GET", &target)?
        .with_access_token(b"access-token-a")
        .with_nonce(&challenged);
    let first_replay = InMemoryReplayStore::new(clock, 8)?;
    DpopVerifier::new(&clock, VerificationPolicy::default()).verify(
        &first_parsed,
        &first_expected,
        &first_replay,
    )?;

    let second_parsed = UnverifiedDpopProof::parse(second.dpop_header_value())?;
    let second_expected = DpopRequest::new("GET", &target)?
        .with_access_token(b"access-token-a")
        .with_nonce(&rotated);
    let second_replay = InMemoryReplayStore::new(clock, 8)?;
    DpopVerifier::new(&clock, VerificationPolicy::default()).verify(
        &second_parsed,
        &second_expected,
        &second_replay,
    )?;
    Ok(())
}

#[test]
fn kx_oauth_005_bound_refresh_relationship_preserves_k1_and_rejects_k2()
-> Result<(), OAuthDpopError> {
    let signer_a = AwsLcP256Signer::generate()?;
    let signer_b = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(8)?;
    let client_a = DpopRequiredClient::new(&signer_a, &clock, &ids, &nonces);
    let token_set = client_a.accept_token_response(
        "DPoP",
        "access-token-a".to_owned(),
        Some("refresh-token-a".to_owned()),
    )?;
    let refresh = token_set
        .refresh_token()
        .ok_or(OAuthDpopError::InvalidCredential)?;
    let as_context = NonceContext::new(NonceNamespace::AuthorizationServer, "issuer-a")?;
    let endpoint = EffectiveRequestTarget::parse("https://issuer.example/token")?;
    let rs_context = NonceContext::new(NonceNamespace::ResourceServer, "resource-a")?;
    let resource = EffectiveRequestTarget::parse("https://api.example.com/items")?;

    client_a.refresh_token_request(&as_context, &endpoint, refresh)?;

    let client_b = DpopRequiredClient::new(&signer_b, &clock, &ids, &nonces);
    assert!(matches!(
        client_b.refresh_token_request(&as_context, &endpoint, refresh),
        Err(OAuthDpopError::ProofKeyContinuityMismatch)
    ));
    assert!(matches!(
        client_b.protected_resource(&rs_context, "GET", &resource, token_set.access_token()),
        Err(OAuthDpopError::ProofKeyContinuityMismatch)
    ));
    Ok(())
}

#[test]
fn kx_oauth_006_nonce_context_roles_cannot_cross() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(8)?;
    let client = DpopRequiredClient::new(&signer, &clock, &ids, &nonces);
    let as_context = NonceContext::new(NonceNamespace::AuthorizationServer, "same")?;
    let rs_context = NonceContext::new(NonceNamespace::ResourceServer, "same")?;
    let endpoint = EffectiveRequestTarget::parse("https://issuer.example/token")?;
    let resource = EffectiveRequestTarget::parse("https://api.example.com/items")?;
    let tokens = client.accept_token_response("DPoP", "access-token-a".to_owned(), None)?;

    assert!(matches!(
        client.token_request(&rs_context, &endpoint),
        Err(OAuthDpopError::NonceContextMismatch)
    ));
    assert!(matches!(
        client.protected_resource(&as_context, "GET", &resource, tokens.access_token()),
        Err(OAuthDpopError::NonceContextMismatch)
    ));
    Ok(())
}

#[test]
fn kx_obs_001_client_debug_surfaces_redact_all_credentials() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(8)?;
    let client = DpopRequiredClient::new(&signer, &clock, &ids, &nonces);
    let tokens = client.accept_token_response(
        "DPoP",
        "distinctive-secret-access-token".to_owned(),
        Some("distinctive secret refresh token".to_owned()),
    )?;
    let context = NonceContext::new(NonceNamespace::ResourceServer, "resource-a")?;
    let target = EffectiveRequestTarget::parse("https://api.example.com/items")?;
    let decorated = client.protected_resource(&context, "GET", &target, tokens.access_token())?;
    let debug = format!("{client:?} {tokens:?} {decorated:?}");

    assert!(!debug.contains("distinctive-secret-access-token"));
    assert!(!debug.contains("distinctive secret refresh token"));
    assert!(!debug.contains(decorated.dpop_header_value()));
    Ok(())
}
