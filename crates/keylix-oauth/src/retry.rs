use core::fmt;

use crate::OAuthDpopError;

/// Explicit nonce-retry budget for one logical `OAuth` `HTTP` operation.
///
/// RFC 9449 nonce challenges require a fresh proof retry, but an untrusted or
/// misconfigured peer must not be able to drive an unbounded automatic retry
/// loop. The v0.1 client permits one nonce-triggered retry per logical operation.
pub struct NonceRetryBudget {
    remaining: u8,
}

impl NonceRetryBudget {
    /// Creates the v0.1 single nonce-retry budget.
    #[must_use]
    pub const fn single_retry() -> Self {
        Self { remaining: 1 }
    }

    /// Returns whether one nonce retry can still be consumed.
    #[must_use]
    pub const fn can_retry(&self) -> bool {
        self.remaining > 0
    }

    pub(crate) fn consume(&mut self) -> Result<(), OAuthDpopError> {
        if self.remaining == 0 {
            return Err(OAuthDpopError::NonceRetryLimitExceeded);
        }
        self.remaining -= 1;
        Ok(())
    }
}

impl Default for NonceRetryBudget {
    fn default() -> Self {
        Self::single_retry()
    }
}

impl fmt::Debug for NonceRetryBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonceRetryBudget")
            .field("remaining", &self.remaining)
            .finish()
    }
}
