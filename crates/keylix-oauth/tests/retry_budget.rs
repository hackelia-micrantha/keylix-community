//! Nonce retry-budget state-mutation regression tests.

use keylix_dpop::{
    AwsLcP256Signer, ClientNonceStore, Clock, DpopNonce, DpopPortError, InMemoryClientNonceStore,
    NonceContext, NonceNamespace, RandomProofIdGenerator,
};
use keylix_oauth::{DpopRequiredClient, NonceRetryBudget, OAuthDpopError};

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(1_700_000_000)
    }
}

#[test]
fn exhausted_retry_budget_does_not_replace_established_nonce() -> Result<(), OAuthDpopError> {
    let signer = AwsLcP256Signer::generate()?;
    let ids = RandomProofIdGenerator;
    let nonces = InMemoryClientNonceStore::new(4)?;
    let client = DpopRequiredClient::new(&signer, &FixedClock, &ids, &nonces);
    let context = NonceContext::new(NonceNamespace::AuthorizationServer, "issuer-a")?;
    let first = DpopNonce::new("first-nonce")?;
    let second = DpopNonce::new("second-nonce")?;
    let mut budget = NonceRetryBudget::single_retry();

    client.record_nonce_challenge(&context, &first, &mut budget)?;
    assert!(matches!(
        client.record_nonce_challenge(&context, &second, &mut budget),
        Err(OAuthDpopError::NonceRetryLimitExceeded)
    ));

    let stored = nonces
        .nonce_for(&context)
        .map_err(|_| OAuthDpopError::NonceStateUnavailable)?;
    assert_eq!(stored, Some(first));
    Ok(())
}
