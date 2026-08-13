# ADR-0001: Keep DPoP core protocol-independent

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

Keylix is motivated partly by DPoP support for MCP, but RFC 9449 is an OAuth/HTTP mechanism and is useful outside MCP. Coupling proof construction or verification directly to an MCP SDK would make protocol conformance depend on an unrelated application protocol and would make reuse harder.

## Decision

`keylix-core` and `keylix-dpop` remain independent of MCP SDKs and concrete OAuth providers.

Dependency direction is:

```text
keylix-core <- keylix-dpop <- keylix-oauth <- keylix-mcp
```

`keylix-conformance` may depend on public crates as a black-box consumer but should not become a production dependency.

## Consequences

### Positive

- RFC 9449 behavior can be tested independently.
- OAuth, MCP, gateway, and non-MCP consumers share one implementation.
- MCP specification changes do not force changes into cryptographic core APIs.
- integrations can be replaced without changing proof semantics.

### Negative

- additional adapter types are required between HTTP/MCP frameworks and the verifier.
- some convenience must live outside the core crate.

## Guardrail

No MCP type should appear in a public `keylix-core` or `keylix-dpop` API.
