# ADR KXC-0003: KMP expect/actual as the Core Abstraction Mechanism

## Status

Accepted

## Context

Keylix Client targets Kotlin (native Android), Swift (native iOS), Kotlin Multiplatform (shared core), React Native (TypeScript + native bridges), Web (TypeScript), and CLI. The core proof-builder and token-binding logic must be shared without forcing all platforms to use KMP.

## Decision

The core logic lives in a KMP module with `expect`/`actual` for the `SecureSigner` port. Platform-specific SDKs (Android native, iOS Swift, React Native) wrap or delegate to the KMP core or implement the same contract natively.

For Swift and TypeScript (non-KMP platforms), the same contract is expressed as a protocol / interface. The Rust FFI path is a separate, deferred track.

## Consequences

- Positive: Kotlin and KMP share the core without duplication.
- Positive: Swift and TypeScript implement the same contract shape independently.
- Positive: the KMP contract serves as the reference shape for all platforms.
- Negative: contract drift between KMP and Swift/TS is possible; requires cross-platform API review.
- Negative: KMP/Native iOS interop (if KMP iOS is used) adds build complexity.
