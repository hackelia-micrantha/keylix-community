# Keylix

> **Public community repository.** This repository is the public development, review, and distribution surface for Keylix. Canonical internal development occurs in the private `hackelia-micrantha/keylix` repository. Security semantics, public APIs, conformance behavior, and releasable implementation remain inspectable here.

**Sender-constrained authorization and proof-of-possession primitives for OAuth, DPoP, MCP, and agentic workloads.**

Keylix is a security-focused Rust project for building and verifying cryptographic sender constraints. Its first target is [OAuth 2.0 Demonstrating Proof of Possession (DPoP), RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), with MCP integration kept as a thin adapter over a protocol-independent core.

> **Status:** the v0.1 implementation and conformance baseline is complete, but Keylix remains pre-release. APIs and security properties are not yet stable. Do not use Keylix to protect production credentials until a tagged release explicitly states otherwise.

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
- [Conformance](docs/CONFORMANCE.md)
- [Observability and security evidence](docs/OBSERVABILITY.md)
- [Integration architecture](docs/INTEGRATIONS.md)
- [Protocol flows](docs/PROTOCOL_FLOWS.md)
- [Design review gate](docs/DESIGN_REVIEW.md)
- [Architecture Decision Records](docs/adr/README.md)

The accepted v0.1 design includes ES256/P-256 only, explicit effective-request-target trust, two-stage DPoP/OAuth sender binding, atomic replay state, AS/RS nonce support, a capability-based signer API, `aws-lc-rs` as the default native crypto backend, and safe telemetry/evidence boundaries.

## Scope

Keylix provides or defines:

- RFC 9449 DPoP proof generation and strict verification
- JWK handling and RFC 7638 thumbprints
- access-token `ath` verification and trusted OAuth key-binding composition
- nonce handling and replay protection interfaces and reference stores
- trusted HTTP request-target/proxy adapters
- OAuth client and resource-server integration points
- an experimental MCP HTTP adapter for the current SEP-1932 draft profile
- bounded operational telemetry and explicit sender-binding security evidence
- conformance vectors, property tests, fuzzing, and adversarial test cases

Keylix does **not** treat proof-of-possession as authentication or authorization by itself. Policy, identity, token validity, scopes, audience restrictions, TLS, and other authorization controls remain separate concerns.

## Architecture

```text
keylix-mcp ------> keylix-oauth ------> keylix-dpop ------> keylix-core
                       ^                   ^
                       |                   |
keylix-observe --------+        keylix-http+

keylix-conformance --> black-box/public protocol behavior across the stack
```

Arrows point toward dependencies. `keylix-observe` also uses selected protocol-independent types from `keylix-core`.

Dependency direction is intentional:

- `keylix-core` owns public JWK/thumbprint primitives, shared value types, and signing capability abstractions.
- `keylix-dpop` owns RFC 9449 proof construction/verification and produces `VerifiedDpopProof`.
- `keylix-oauth` composes that proof with trusted validation of the exact presented token and produces `VerifiedSenderBinding`.
- `keylix-http` reconstructs trusted effective HTTP targets without moving proxy trust into the DPoP core.
- `keylix-mcp` adapts the OAuth/DPoP boundary to MCP HTTP transports and remains experimental while SEP-1932 is unstable.
- `keylix-observe` exposes bounded telemetry values and explicit sender-binding evidence without introducing a logging stack.
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

The v0.1 implementation baseline now includes:

- [x] design, threat model, ADRs, integrations, and requirement traceability
- [x] P-256 JWK validation and RFC 7638 thumbprints
- [x] RFC 9449 proof construction and strict verification
- [x] nonce and atomic replay reference state
- [x] OAuth sender-binding composition and client integration
- [x] trusted HTTP request-target/proxy adaptation
- [x] RFC/adversarial/property/fuzz conformance and safe evidence boundaries
- [x] experimental Rust MCP SEP-1932 draft adapter

Next-stage work is API stabilization, release/security gates, interoperability and external review, tracking MCP profile evolution, and only then evaluating additional sender-constraint mechanisms.

Implementation PRs should reference affected IDs in [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) and land corresponding positive and negative/adversarial tests.

## Development

Keylix is organized as a Cargo workspace. The baseline quality gate includes locked dependency resolution, formatting, Clippy, tests, documentation checks, dependency/security auditing, and bounded fuzz targets for parser/verifier boundaries.

```bash
cargo fetch --locked
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
```

## Standards

- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 7638 — JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
- [RFC 7518 — JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518)
- [Model Context Protocol — Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
