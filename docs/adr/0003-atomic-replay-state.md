# ADR-0003: Model replay prevention as atomic state

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

RFC 9449 permits servers to track DPoP proof `jti` values during the proof acceptance window to reject reuse. A naive cache API using `contains` followed by `insert` is vulnerable to concurrent replay races, especially across multiple server instances.

## Decision

Keylix models strict replay prevention around one atomic semantic operation:

```text
check_and_record(replay_key, expires_at) -> Fresh | Replay
```

A backend claiming strict replay protection must make that operation atomic for the topology in which it is deployed.

The in-memory reference backend is explicitly single-process unless proven otherwise. Distributed deployments need shared state or an equivalent deployment guarantee.

Replay-store unavailability in a strict replay-enforcement mode fails closed rather than silently degrading to freshness-only validation.

## Consequences

### Positive

- concurrency requirements are explicit in the port itself.
- backends cannot accidentally implement an obviously racy two-step contract.
- deployment documentation can distinguish single-process from distributed guarantees.

### Negative

- some cache backends require transactions/scripts/unique constraints to satisfy the interface correctly.
- strict multi-instance replay protection adds latency and an availability dependency.

## Guardrails

- accepted `jti` size is bounded to limit memory-amplification attacks;
- backends may store a digest rather than raw `jti` values;
- TTL covers the entire proof acceptance window including configured skew;
- a backend's consistency semantics are part of its documented security contract.
