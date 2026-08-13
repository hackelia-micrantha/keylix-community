# ADR-0004: Use capability-based private signing keys

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

Every DPoP proof requires a signature, but callers do not inherently need access to private-key bytes. Exposing raw private material through the primary API makes accidental logging, serialization, cloning, and extraction easier and prevents natural integration with non-extractable OS keystores, TPMs, HSMs, and similar signers.

## Decision

The primary client-side key abstraction is a signing capability with access to its corresponding public JWK/thumbprint.

Conceptually:

```text
SigningKey
- public_jwk()
- algorithm()
- sign(message)
```

It does not require an `export_private_key()` capability.

Concrete test/example implementations may use in-memory extractable keys internally, but extractability is not part of the common contract.

## Consequences

### Positive

- non-extractable key backends fit naturally.
- the public API reduces secret-handling surface.
- key custody and DPoP protocol logic remain separate responsibilities.
- application/runtime compromise has fewer trivial exfiltration paths when a protected backend is used.

### Negative

- async/external signers may require an asynchronous signing interface or adapter.
- serialization/backup of client state becomes backend-specific.
- some crypto libraries expose raw key types more conveniently than signer abstractions.

## Guardrails

- private-key material must not appear in normal `Debug`/error output;
- token/proof builders depend on signing behavior rather than specific private-key structs;
- key rotation semantics must respect refresh-token binding and cannot be hidden behind a transparent signer swap.
