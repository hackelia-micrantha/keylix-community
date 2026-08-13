//! Token-endpoint proof binding coverage for the experimental MCP `DPoP` profile.

use std::sync::Arc;

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopPortError, DpopRequest, DpopSigner, DpopVerifier,
    EffectiveRequestTarget, InMemoryClientNonceStore, InMemoryReplayStore, RandomProofIdGenerator,
    UnverifiedDpopProof, VerificationPolicy, parse_dpop_header_values,
};
use keylix_mcp::McpDpopClient;
use keylix_oauth::{DpopRequiredClient, HostValidatedToken, OAuthDpopError};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

#[test]
fn kx_mcp_002_token_request_proof_establishes_bound_token_key()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = Arc::new(AwsLcP256Signer::generate()?);
    let clock = Arc::new(FixedClock(1_700_000_000));
    let proof_ids = Arc::new(RandomProofIdGenerator);
    let nonces = Arc::new(InMemoryClientNonceStore::new(8)?);
    let mcp = McpDpopClient::new(
        Arc::clone(&signer),
        Arc::clone(&clock),
        Arc::clone(&proof_ids),
        Arc::clone(&nonces),
        "https://issuer.example",
        "https://mcp.example",
    )?;
    let token_endpoint = EffectiveRequestTarget::parse("https://issuer.example/token")?;

    let attempt = mcp.token_endpoint_attempt(&token_endpoint)?;
    let proof = UnverifiedDpopProof::parse(attempt.dpop_header_value())?;
    let expected_request = DpopRequest::new("POST", &token_endpoint)?;
    let replay = InMemoryReplayStore::new(*clock, 8)?;
    let verified = DpopVerifier::new(clock.as_ref(), VerificationPolicy::default()).verify(
        &proof,
        &expected_request,
        &replay,
    )?;

    let issued_token = "issued-mcp-access-token".to_owned();
    let issued_token_jkt = verified.key_thumbprint().to_base64url();
    let _trusted_token = HostValidatedToken::from_host_validated_jwt(
        issued_token.as_bytes(),
        Some(&issued_token_jkt),
    )?;

    let oauth = DpopRequiredClient::new(
        signer.as_ref(),
        clock.as_ref(),
        proof_ids.as_ref(),
        nonces.as_ref(),
    );
    let tokens = oauth.accept_token_response("DPoP", issued_token, None)?;
    assert_eq!(
        tokens.access_token().proof_key(),
        verified.key_thumbprint(),
        "KX-MCP-002: accepted bound-token state did not retain the token-request proof key"
    );
    assert_eq!(
        verified.key_thumbprint(),
        signer.public_jwk().thumbprint(),
        "KX-MCP-002: authorization server derived a different sender key"
    );
    Ok(())
}

#[test]
fn kx_mcp_002_missing_token_request_proof_or_bearer_response_fails_required_profile()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        parse_dpop_header_values(&[]),
        Err(DpopError::MissingProof)
    ));

    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let proof_ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(4)?;
    let oauth = DpopRequiredClient::new(&signer, &clock, &proof_ids, &nonces);
    assert!(matches!(
        oauth.accept_token_response("Bearer", "unbound-token".to_owned(), None),
        Err(OAuthDpopError::TokenTypeNotDpop)
    ));
    Ok(())
}
