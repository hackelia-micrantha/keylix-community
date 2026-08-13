# Standards and Design References

Keylix's normative behavior should be derived from primary specifications rather than secondary tutorials.

## Core standards

- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- RFC 7638 — JSON Web Key (JWK) Thumbprint
- RFC 7515 — JSON Web Signature (JWS)
- RFC 7517 — JSON Web Key (JWK)
- RFC 7518 — JSON Web Algorithms (JWA)
- RFC 8725 — JSON Web Token Best Current Practices
- RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax
- RFC 9110 — HTTP Semantics
- RFC 9728 — OAuth 2.0 Protected Resource Metadata
- RFC 8707 — Resource Indicators for OAuth 2.0
- RFC 8414 — OAuth 2.0 Authorization Server Metadata

## MCP

- Model Context Protocol 2026-07-28 — Authorization
- `modelcontextprotocol/ext-auth` — official MCP authorization extensions
- MCP conformance work associated with SEP-1932 — DPoP support

## Source-of-truth policy

When an MCP integration detail conflicts with RFC 9449 DPoP semantics, do not modify `keylix-dpop` merely for compatibility. Treat the mismatch as an integration/profile/version question in `keylix-mcp`.

When the MCP DPoP extension becomes stable, update the MCP adapter and conformance tests while preserving the protocol-independent DPoP core unless the RFC/profile actually requires new generic behavior.
