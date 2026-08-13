# Keylix

> **Public community repository.** This repository is the public development, review, and distribution surface for Keylix. Canonical internal development occurs in the private `hackelia-micrantha/keylix` repository. Security semantics, public APIs, conformance behavior, and releasable implementation remain inspectable here.


**Sender-constrained authorization and proof-of-possession primitives for OAuth, DPoP, MCP, and agentic workloads.**

Keylix is a security-focused Rust project for building and verifying cryptographic sender constraints. Its first target is [OAuth 2.0 Demonstrating Proof of Possession (DPoP), RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), with MCP integration kept as a thin adapter over a protocol-independent core.

> **Status:** v0.1 design baseline accepted; implementation is pre-release. APIs and security properties are not yet stable. Do not use Keylix to protect production credentials until a tagged release explicitly states otherwise.

## Why Keylix?

Bearer credentials can be replayed by anyone who obtains them. DPoP binds OAuth tokens to a key pair and requires a fresh signed proof when the token is used, reducing the value of a stolen token without the corresponding private key.

The name combines **key** with **calyx**, the protective botanical structure surrounding a flower bud: cryptographic key binding as a protective boundary around authorization.

## Design

Security behavior is specified before implementation:

- [Design baseline](docs/DESIGN.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security architecture](docs/SECURITY_ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Requirements and test traceability](docs/REQUIREMENTS.md)
- [Integration architecture](docs/INTEGRATIONS.md)
- [Protocol flows](docs/PROTOCOL_FLOWS.md)
- [Design review gate](docs/DESIGN_REVIEW.md)
- [Architecture Decision Records](docs/adr/README.md)

The accepted v0.1 design includes ES256/P-256 only, explicit effective-request-target trust, two-stage DPoP/OAuth sender binding, atomic replay state, AS/RS nonce support, a capability-based signer API, `aws-lc-rs` as the default native crypto backend, and safe telemetry/evidence boundaries.

## Scope

Keylix aims to provide:

- RFC 9449 DPoP proof generation and verification
- JWK handling and RFC 7638 thumbprints
- access-token `ath` verification and trusted OAuth key-binding composition
- nonce handling and replay protection interfaces
- strict HTTP method and target-URI validation
- OAuth client and resource-server integration points
- MCP adapters that do not couple the core implementation to an MCP SDK
- conformance vectors, property tests, fuzzing, and adversarial test cases

Keylix does **not** treat proof-of-possession as authentication or authorization by itself. Policy, identity, token validity, scopes, audience restrictions, TLS, and other authorization controls remain separate concerns.

## Architecture

```text
keylix-core
    ^
    |
keylix-dpop
    ^
    |
keylix-oauth
    ^
    |
keylix-mcp

keylix-conformance --> black-box/public protocol behavior
```

Dependency direction is intentional:

- `keylix-core` owns public JWK/thumbprint primitives, shared value types, and signing capability abstractions.
- `keylix-dpop` owns RFC 9449 proof construction/verification and produces `VerifiedDpopProof`.
- `keylix-oauth` composes that proof with trusted validation of the exact presented token and produces `VerifiedSenderBinding`.
- `keylix-mcp` adapts the OAuth/DPoP boundary to MCP HTTP transports and remains experimental while SEP-1932 is unstable.
- `keylix-conformance` exercises externally observable standards behavior independently of implementation internals.

## Security principles

- **Fail closed.** Malformed, ambiguous, stale, replayed, downgraded, or unverifiable input is rejected.
- **No custom cryptography.** Use reviewed cryptographic primitives and explicit algorithm/key policy.
- **Protocol correctness over convenience.** RFC validation rules belong in typed APIs and `KX-*` requirement tests.
- **Keep private keys opaque.** Signing capability is primary; extraction is not required.
- **Treat replay state as a security boundary.** Replay prevention has explicit atomicity/topology semantics.
- **No silent downgrade.** DPoP-required flows do not fall back to Bearer automatically.
- **Separate proof from token validity.** DPoP proof verification and trusted OAuth validation compose only at the `VerifiedSenderBinding` boundary.
- **Safe observability.** Credentials/proofs/nonces/raw identifiers stay out of ordinary logs and metric labels.
- **Keep MCP optional.** Sender-constrained OAuth is independently useful beyond MCP.
- **Defense in depth.** DPoP complements TLS and authorization policy; it does not replace them.

## Roadmap

1. ~~Complete/review design, threat model, ADRs, integrations, and test traceability.~~
2. Implement JWK and RFC 7638 thumbprint primitives (#3).
3. Implement RFC 9449 proof construction and strict verification (#4).
4. Add nonce/replay reference implementations (#5).
5. Build RFC conformance, adversarial, property, and fuzz suites (#6).
6. Add OAuth composition/client integration (#7).
7. Add an experimental Rust MCP SEP-1932 adapter (#8).
8. Evaluate additional sender constraints only after DPoP is complete and well-tested.

Implementation PRs should reference affected IDs in [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) and land corresponding positive + negative/adversarial tests.

## Development

Keylix is organized as a Cargo workspace. The baseline quality gate includes formatting, Clippy, tests, documentation checks, dependency/security auditing, and eventually fuzz targets for parser/verifier boundaries.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

## Standards

- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 7638 — JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
- [RFC 7518 — JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518)
- [Model Context Protocol — Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
