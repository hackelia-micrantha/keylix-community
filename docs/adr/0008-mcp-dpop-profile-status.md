# ADR-0008: Treat MCP DPoP integration as an experimental profile until standardized

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

RFC 9449 protected-resource access uses `Authorization: DPoP <token>` plus a `DPoP` proof header.

The MCP 2026-07-28 core authorization specification still describes Bearer token usage. SEP-1932 remains an upstream standards-track Draft for DPoP behavior rather than a stable MCP authorization profile.

Implementing MCP DPoP as if it were already stable would risk baking temporary negotiation/profile behavior into Keylix APIs.

## Decision

`keylix-mcp` treats DPoP integration as experimental/profile-based until the official MCP authorization extension is published at an appropriate stability level.

The adapter:

- reuses standards-correct `keylix-oauth`/`keylix-dpop` behavior;
- does not modify MCP JSON-RPC messages to carry DPoP state;
- requires the explicit profile identifier `sep-1932-draft`;
- exposes the targeted upstream profile status, `rmcp` release, and MCP specification generation;
- does not silently fall back to Bearer when DPoP is required;
- isolates temporary MCP profile details from `keylix-core` and `keylix-dpop`.

## Implemented profile boundary

The current adapter targets:

- SEP: `SEP-1932`;
- profile identifier: `sep-1932-draft`;
- profile status: Draft;
- official Rust MCP SDK: `rmcp` 3.0.1;
- MCP specification generation: `2026-07-28`.

Client-side integration wraps the official `rmcp::StreamableHttpClient` extension point. Each MCP HTTP attempt receives `Authorization: DPoP <token>` and a fresh `DPoP` proof; pre-existing authorization/proof headers are rejected instead of merged or downgraded. Authorization-server and resource-server nonce state remain separately scoped and use the bounded retry behavior owned by `keylix-oauth`.

Server-side integration runs before MCP method dispatch. The host supplies the trusted effective HTTP target and an already validated exact-token result; `keylix-mcp` verifies DPoP request binding, nonce/freshness/replay state, and then composes the verified proof with trusted OAuth `cnf.jkt` metadata. Only `VerifiedSenderBinding` crosses the dispatch boundary.

This implementation does **not** turn Draft coverage into a claim of stable MCP conformance. Profile drift belongs in `keylix-mcp`; RFC 9449 and OAuth trust semantics remain upstream of it.

## Consequences

### Positive

- Keylix can experiment/interoperate with SEP-1932 work without claiming stable MCP conformance prematurely.
- later extension changes should be localized to `keylix-mcp`.
- RFC 9449 behavior stays standards-correct.
- official SDK integration does not require an MCP SDK fork.

### Negative

- the first MCP adapter may change more rapidly than the core crates;
- users need to understand that MCP DPoP interoperability depends on the peer's profile/version support.

## Revisit condition

Revisit when MCP publishes a stable/draft DPoP authorization extension with normative discovery/negotiation and conformance requirements that supersede the current SEP-1932 draft contract.
