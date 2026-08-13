//! OAuth 2.0 Demonstrating Proof of Possession (`DPoP`) support.
//!
//! This crate owns RFC 9449 proof construction, strict proof verification, and
//! protocol-level replay/nonce state abstractions plus bounded single-process
//! reference stores. OAuth token validity and trusted `cnf.jkt` composition
//! remain in `keylix-oauth`, and MCP transport behavior remains downstream.

#![forbid(unsafe_code)]

mod error;
mod ports;
mod proof;
mod request;
mod state;

pub use error::{DpopError, DpopPortError};
pub use ports::{
    AwsLcP256Signer, Clock, DpopNonce, DpopSigner, ProofId, ProofIdGenerator,
    RandomProofIdGenerator, ReplayKey, ReplayStatus, ReplayStore, SystemClock,
};
pub use proof::{
    DpopProof, DpopProofBuilder, DpopVerifier, UnverifiedDpopProof, VerificationPolicy,
    VerifiedDpopProof, parse_dpop_header_values,
};
pub use request::{DpopRequest, EffectiveRequestTarget};
pub use state::{
    ClientNonceStore, InMemoryClientNonceStore, InMemoryReplayStore, InMemoryServerNonceStore,
    NonceContext, NonceGenerator, NonceNamespace, RandomNonceGenerator, ServerNonceStore,
    StateStoreConsistency, StateStoreMetadata, StateStoreTopology,
};
