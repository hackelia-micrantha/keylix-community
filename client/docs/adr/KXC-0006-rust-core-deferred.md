# ADR KXC-0006: Rust Core Cross-Compilation Deferred

## Status

Accepted

## Context

Keylix is a Rust workspace. Cross-compiling `keylix-core` + `keylix-dpop` to mobile targets via FFI (uniffi, JNI, C ABI) is technically feasible and would eliminate proof-logic duplication across platforms. However, it adds significant build complexity, FFI overhead, and ABI-stability concerns.

## Decision

Native implementations (Kotlin, Swift, TypeScript) are built first using platform crypto APIs. The Rust FFI path is **deferred** until:
1. The native implementations prove the API shape and security model.
2. The conformance corpus is established.
3. A clear need emerges (e.g., a platform that needs the exact same Rust verifier).

The `adapters/rust-core/` directory holds the deferred design for this path.

## Consequences

- Positive: native implementations are simpler to debug, profile, and ship.
- Positive: platform-specific UX (async patterns, error types, lifecycle) is discovered first.
- Negative: proof logic is duplicated across native implementations.
- Negative: each implementation must independently achieve RFC 9449 conformance.
- Negative: conformance testing must run against each implementation.
