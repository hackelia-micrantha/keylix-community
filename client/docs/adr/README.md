# Architecture Decision Records

ADRs document key architectural decisions that shape Keylix Client. Each ADR records the context, decision, and consequences.

| ID | Title | Status |
|----|-------|--------|
| [KXC-0001](KXC-0001-platform-secure-hardware-only.md) | Platform-Secure-Hardware-Only Key Generation | Accepted |
| [KXC-0002](KXC-0002-p256-es256-only.md) | P-256 / ES256 Only for v1 | Accepted |
| [KXC-0003](KXC-0003-kmp-core-abstraction.md) | KMP expect/actual as the Core Abstraction Mechanism | Accepted |
| [KXC-0004](KXC-0004-optional-attestation.md) | Attestation as an Optional, Policy-Driven Layer | Accepted |
| [KXC-0005](KXC-0005-hardware-fallback-consent.md) | Hardware-Unavailable Fallback Requires Explicit Consent | Accepted |
| [KXC-0006](KXC-0006-rust-core-deferred.md) | Rust Core Cross-Compilation Deferred | Accepted |

## Adding New ADRs

1. Create a new file `KXC-NNNN-title-kebab-case.md` in this directory.
2. Add an entry to the table above.
3. Link from the relevant design document.
4. Status values: `Proposed`, `Accepted`, `Superseded`.
