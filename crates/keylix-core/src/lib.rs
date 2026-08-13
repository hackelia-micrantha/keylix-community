//! Core types for Keylix.
//!
//! This crate owns protocol-independent key representation and `JWK`
//! thumbprint primitives. OAuth, `DPoP` request semantics, and MCP integration
//! remain in downstream crates.

#![forbid(unsafe_code)]

mod error;
mod jwk;
mod thumbprint;

pub use error::JwkError;
pub use jwk::PublicP256Jwk;
pub use thumbprint::JwkThumbprint;
