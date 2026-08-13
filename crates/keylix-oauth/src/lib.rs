//! `OAuth` integration for Keylix sender-constrained authorization.
//!
//! This crate composes already-verified `DPoP` proofs with explicit host `OAuth`
//! validation results and provides transport-agnostic `DPoP`-required client
//! decorators. It does not validate `JWTs`, introspection authenticity, issuer,
//! audience, scope, or application authorization policy.

#![forbid(unsafe_code)]

mod binding;
mod client;
mod error;
mod retry;

pub use binding::{
    HostValidatedToken, TokenFingerprint, TokenValidationSource, VerifiedSenderBinding,
    compose_sender_binding,
};
pub use client::{
    BoundAccessToken, BoundRefreshToken, BoundTokenSet, DpopRequiredClient,
    ProtectedResourceAuthorization, TokenEndpointDpop,
};
pub use error::OAuthDpopError;
pub use retry::NonceRetryBudget;
