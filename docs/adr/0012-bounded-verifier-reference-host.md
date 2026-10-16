# ADR-0012: Package a bounded verifier host around existing sender-binding libraries

- **Status:** Accepted
- **Date:** 2026-09-25
- **Issue:** #44

## Context

Keylix already owns protocol-independent DPoP verification, trusted effective-request-target adaptation, exact-token sender-binding composition, atomic replay interfaces/reference stores, nonce semantics, safe observability, and conformance coverage.

Downstream systems such as Dubnium need a packaged server-side verification artifact without importing private workspace paths or reimplementing RFC 9449 semantics.

A production-capable verifier needs process lifetime and an explicitly granted replay/nonce state capability. A one-shot stdin/stdout verifier cannot honestly claim replay protection across independent requests unless that state is delegated to an external atomic backend.

Keylix must preserve its architecture boundary: sender-binding verification is not complete application authentication or semantic authorization; token validity, issuer/audience/scope policy, principal mapping, and application authorization remain host-owned.

## Decision

Keylix will provide a **host library plus a bounded reference verifier server adapter**.

The host library owns a transport-neutral request/result application contract and composes existing Keylix verification primitives. The reference server is a thin process adapter over that contract.

### Application boundary

Conceptually:

    trusted host/transport adapter
      -> versioned VerifierRequest
           - effective HTTP method
           - trusted effective request target
           - exact presented token bytes
           - DPoP proof/header value
           - no caller-controlled nonce-enforcement decision
           - host-validated token-binding input
      -> verifier application service
           -> keylix-dpop
           -> injected Clock
           -> injected atomic ReplayStore
           -> keylix-oauth exact-token composition
      -> versioned VerifierResult
           -> VerifiedSenderBinding evidence
           -> stable failure class

The verifier request does not accept caller-supplied actor, workspace, session, role, capability, or nonce-enforcement values as trusted authority.

### Transport

The first reference host should support a **local Unix-domain socket** boundary by default. The socket is an authenticated local IPC boundary, not merely a filesystem path: the server must create it in a service-owned directory with restrictive ownership/mode and verify the connecting peer identity (for example Linux peer credentials) against an explicit allowlist before deserializing wire claims into trusted host-attested types. Unauthorized or unverifiable peers are rejected before proof/token composition.

A bounded HTTP adapter may be added only as an explicit deployment profile with equivalent request-size, timeout, concurrency, target-trust, and secret-handling guarantees. Network exposure is not required for the first packaged artifact.

The reference host must not infer trusted effective request targets from untrusted forwarding headers. The host adapter supplies already-normalized trusted request-target input according to ADR-0006.

### Replay and nonce state

Replay protection is a required explicit capability. The server process receives an injected replay backend satisfying the existing Keylix atomic replay contract.

The initial single-process reference profile may use the existing in-memory atomic store only when documentation clearly states that it is process-local and not safe for multi-instance deployment. Multi-instance deployment requires shared atomic state or equivalent routing semantics.

Nonce enforcement is server-owned state. The verifier derives the canonical role/server nonce context from trusted configuration and/or the trusted effective request target, loads the expected nonce from the injected nonce capability, and applies sticky enforcement according to ADR-0009. A wire request cannot disable nonce enforcement, choose a fresh nonce namespace, or supply an authoritative enforcement context. No transport adapter may silently downgrade from challenged nonce enforcement to nonce-less verification.

### Token/application authentication boundary

The packaged verifier verifies sender binding only. Protected-resource callers provide a host-validated token result conforming to the existing HostValidatedToken trust boundary.

The reference host does not construct application principals, authorize semantic capabilities, or interpret request metadata as authenticated identity. Success returns sender-binding evidence for composition by a consuming host such as Dubnium's ValidatedCredential + VerifiedSenderBinding -> CallerIdentity boundary.

### Failure contract

The application contract exposes stable failure classes, not debug strings. It must distinguish malformed/unsupported envelope, invalid or ambiguous proof, method/target mismatch, stale/future proof, nonce mismatch, replay, replay-backend indeterminacy, token-hash mismatch, confirmation-key mismatch, unsupported version/profile, and internal failure. Backend/state indeterminacy fails closed.

### Resource and secret bounds

The reference host must define/test request size, concurrency, processing timeout, response size, protocol/version rejection, authenticated IPC peer admission, and secret-safe diagnostics. It needs no ambient signer/private-key capability and no arbitrary filesystem/network access beyond configured listener/state needs.

Access tokens, proofs, nonces, jti, private JWK material, authorization headers, and equivalent credentials must not enter ordinary logs or public evidence.

### Publication

The verifier is a real component-owned artifact and may be projected to the public/community repository only through the reviewed canonical-to-community release boundary. Packaging does not imply production readiness.

## Alternatives considered

### One-shot stdin/stdout verifier

Useful for deterministic conformance, but insufficient as the primary production artifact because replay/nonce semantics need process lifetime or an external atomic state service. It may exist later as an explicitly stateless/conformance-only tool.

### Standalone HTTP service owning token validation and application identity

Rejected. It would collapse sender-binding verification, OAuth identity validation, and application authorization into Keylix, contradicting ADR-0007 and the Keylix/Dubnium composition boundary.

### Reuse keylix-mcp as the generic verifier host

Rejected as the general architecture. keylix-mcp is intentionally an experimental SEP-1932 adapter. The generic verifier host must not make MCP draft semantics the owner of the reusable server contract.

### Library only, no packaged host

Rejected for the first downstream use case. Dubnium needs a separately consumable runtime artifact without linking private canonical workspace internals.

## Consequences

Existing protocol logic remains authoritative; downstreams gain a narrow packaged service; replay/nonce semantics remain explicit capabilities; transport stays replaceable; application identity/authorization stays outside Keylix.

The tradeoff is a small application-contract layer plus process/state packaging and operational lifecycle concerns.

## Required implementation follow-up

1. Define versioned request/result and stable failure schemas/types.
2. Add a transport-neutral verifier application service over existing Keylix crates.
3. Add an injected replay/nonce capability boundary.
4. Implement the Unix-socket reference host.
5. Add deterministic positive/adversarial fixtures.
6. Add request-size/concurrency/timeout and secret-safe diagnostics tests.
7. Package the executable through Cargo/Nix and validate the installed artifact.
8. Project reviewed public contract/artifact metadata through the community boundary.
9. Demonstrate Dubnium can consume the artifact without importing private Keylix paths.

## Security invariants retained

This ADR does not supersede ADR-0003, ADR-0006, ADR-0007, ADR-0009, or ADR-0011. Those decisions remain authoritative for replay, target reconstruction, validated-token composition, proof/nonce policy, and observability.
