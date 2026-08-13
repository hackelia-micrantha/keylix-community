//! Server-side MCP `DPoP` verification and OAuth sender-binding integration tests.

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopNonce, DpopPortError, DpopProofBuilder, DpopRequest,
    DpopSigner, EffectiveRequestTarget, InMemoryReplayStore, RandomProofIdGenerator,
    VerificationPolicy,
};
use keylix_mcp::{McpDpopServer, McpDpopServerError, McpHttpRequest};
use keylix_oauth::{HostValidatedToken, OAuthDpopError};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

fn proof_for(
    signer: &AwsLcP256Signer,
    clock: FixedClock,
    method: &str,
    target: &EffectiveRequestTarget,
    token: &[u8],
    nonce: Option<&DpopNonce>,
) -> Result<String, DpopError> {
    let ids = RandomProofIdGenerator;
    let mut request = DpopRequest::new(method, target)?.with_access_token(token);
    if let Some(nonce) = nonce {
        request = request.with_nonce(nonce);
    }
    Ok(DpopProofBuilder::new(signer, &clock, &ids)
        .build(&request)?
        .as_header_value()
        .to_owned())
}

#[test]
fn kx_mcp_001_server_returns_only_verified_sender_binding_before_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let clock = FixedClock(1_700_000_000);
    let signer = AwsLcP256Signer::generate()?;
    let target = EffectiveRequestTarget::parse("https://mcp.example/rpc")?;
    let token = b"mcp-bound-access-token";
    let nonce = DpopNonce::new("resource-nonce")?;
    let proof = proof_for(&signer, clock, "POST", &target, token, Some(&nonce))?;
    let headers = [proof.as_str()];
    let request = McpHttpRequest::new("POST", &target, token, &headers).with_nonce(&nonce);
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    let validated = HostValidatedToken::from_host_validated_jwt(token, Some(&jkt))?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    let server = McpDpopServer::new(&clock, VerificationPolicy::default(), &replay);

    let binding = server.verify(&request, &validated)?;
    assert_eq!(binding.key_thumbprint(), signer.public_jwk().thumbprint());
    assert!(binding.nonce_enforced());
    assert!(binding.replay_checked());
    Ok(())
}

#[test]
fn kx_mcp_001_stolen_bound_token_without_proof_key_fails_sender_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let clock = FixedClock(1_700_000_000);
    let token_key = AwsLcP256Signer::generate()?;
    let attacker_key = AwsLcP256Signer::generate()?;
    let target = EffectiveRequestTarget::parse("https://mcp.example/rpc")?;
    let token = b"stolen-bound-token";
    let proof = proof_for(&attacker_key, clock, "POST", &target, token, None)?;
    let headers = [proof.as_str()];
    let request = McpHttpRequest::new("POST", &target, token, &headers);
    let token_jkt = token_key.public_jwk().thumbprint().to_base64url();
    let validated = HostValidatedToken::from_host_validated_jwt(token, Some(&token_jkt))?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    let server = McpDpopServer::new(&clock, VerificationPolicy::default(), &replay);

    assert!(matches!(
        server.verify(&request, &validated),
        Err(McpDpopServerError::SenderBinding(
            OAuthDpopError::TokenBindingMismatch
        ))
    ));
    Ok(())
}

#[test]
fn kx_mcp_001_replayed_proof_fails_before_mcp_dispatch() -> Result<(), Box<dyn std::error::Error>> {
    let clock = FixedClock(1_700_000_000);
    let signer = AwsLcP256Signer::generate()?;
    let target = EffectiveRequestTarget::parse("https://mcp.example/rpc")?;
    let token = b"replay-bound-token";
    let proof = proof_for(&signer, clock, "DELETE", &target, token, None)?;
    let headers = [proof.as_str()];
    let request = McpHttpRequest::new("DELETE", &target, token, &headers);
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    let validated = HostValidatedToken::from_host_validated_jwt(token, Some(&jkt))?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    let server = McpDpopServer::new(&clock, VerificationPolicy::default(), &replay);

    server.verify(&request, &validated)?;
    assert!(matches!(
        server.verify(&request, &validated),
        Err(McpDpopServerError::Proof(DpopError::ReplayDetected))
    ));
    Ok(())
}

#[test]
fn kx_mcp_001_oauth_exact_token_failure_remains_distinct_from_proof_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let clock = FixedClock(1_700_000_000);
    let signer = AwsLcP256Signer::generate()?;
    let target = EffectiveRequestTarget::parse("https://mcp.example/rpc")?;
    let presented = b"presented-token";
    let validated_token_bytes = b"different-validated-token";
    let proof = proof_for(&signer, clock, "GET", &target, presented, None)?;
    let headers = [proof.as_str()];
    let request = McpHttpRequest::new("GET", &target, presented, &headers);
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    let validated = HostValidatedToken::from_host_validated_jwt(validated_token_bytes, Some(&jkt))?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    let server = McpDpopServer::new(&clock, VerificationPolicy::default(), &replay);

    assert!(matches!(
        server.verify(&request, &validated),
        Err(McpDpopServerError::SenderBinding(
            OAuthDpopError::TokenIdentityMismatch
        ))
    ));
    Ok(())
}

#[test]
fn kx_mcp_001_ambiguous_dpop_headers_fail_at_http_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let clock = FixedClock(1_700_000_000);
    let signer = AwsLcP256Signer::generate()?;
    let target = EffectiveRequestTarget::parse("https://mcp.example/rpc")?;
    let token = b"ambiguous-header-token";
    let proof = proof_for(&signer, clock, "POST", &target, token, None)?;
    let headers = [proof.as_str(), proof.as_str()];
    let request = McpHttpRequest::new("POST", &target, token, &headers);
    let jkt = signer.public_jwk().thumbprint().to_base64url();
    let validated = HostValidatedToken::from_host_validated_jwt(token, Some(&jkt))?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    let server = McpDpopServer::new(&clock, VerificationPolicy::default(), &replay);

    assert!(matches!(
        server.verify(&request, &validated),
        Err(McpDpopServerError::Proof(DpopError::AmbiguousProof))
    ));
    Ok(())
}
