# Architecture Decision Records

Keylix uses ADRs for decisions that materially constrain security behavior or public architecture.

## Status values

- **Proposed** — design under review; implementation should avoid hard-coding the choice.
- **Accepted** — implementation should conform unless superseded.
- **Superseded** — retained for history with a link to the replacement ADR.

## Records

- [ADR-0001: Keep DPoP core protocol-independent](0001-protocol-independent-core.md) — Accepted
- [ADR-0002: Require explicit DPoP mode and prohibit silent Bearer downgrade](0002-no-silent-bearer-downgrade.md) — Accepted
- [ADR-0003: Model replay prevention as atomic state](0003-atomic-replay-state.md) — Accepted
- [ADR-0004: Use capability-based private signing keys](0004-capability-based-signing-keys.md) — Accepted
- [ADR-0005: Initial DPoP signing algorithm policy](0005-initial-algorithm-policy.md) — Accepted
- [ADR-0006: Effective HTTP target and trusted-proxy boundary](0006-effective-http-target.md) — Accepted
- [ADR-0007: Accept token binding only from validated OAuth results](0007-validated-token-binding-boundary.md) — Accepted
- [ADR-0008: Treat MCP DPoP integration as an experimental profile until standardized](0008-mcp-dpop-profile-status.md) — Accepted
- [ADR-0009: Proof lifetime, replay, and nonce policy](0009-proof-lifetime-replay-and-nonce-policy.md) — Accepted
- [ADR-0010: Crypto and JOSE backend architecture](0010-crypto-and-jose-backend.md) — Accepted
- [ADR-0011: Safe observability and security evidence](0011-observability-and-security-evidence.md) — Accepted

The initial v0.1 security architecture is now sufficiently constrained for implementation. Normative behavior and test obligations are tracked in [`../REQUIREMENTS.md`](../REQUIREMENTS.md). New security-sensitive decisions should receive an ADR rather than being introduced as implicit library defaults.