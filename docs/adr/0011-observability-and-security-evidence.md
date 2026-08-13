# ADR-0011: Safe observability and security evidence

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

Keylix sits on a credential-use path. Operational diagnostics are necessary, but naive logging can leak access/refresh tokens, proofs, nonces, key material, or stable public-key identifiers. An RFC 7638 JWK thumbprint is derived from public key material rather than a secret, yet it is a stable correlator that can link activity across requests or systems.

Downstream governance/audit systems may legitimately need durable proof-of-possession evidence, while ordinary logs and metrics generally do not.

## Decision

Keylix separates **operational telemetry** from **security evidence**.

### Never emit through normal diagnostics

Normal errors, `Debug`, tracing fields, log messages, and metric labels must not contain:

- access tokens;
- refresh tokens;
- authorization codes;
- private JWK parameters or private signing-key bytes;
- full DPoP proofs;
- raw server nonces;
- raw `jti` values;
- Authorization/DPoP header values.

Secret-bearing wrapper types must use redacted `Debug` behavior or avoid `Debug` entirely as appropriate.

### Public JWK thumbprints

A proof-key RFC 7638 thumbprint (`jkt`) is treated as **security-sensitive correlating metadata**, not as a secret.

Default logs and metric labels do not include the raw `jkt`. Metrics use bounded low-cardinality dimensions such as result category, mechanism, algorithm profile, adapter, and failure class.

Debug/trace logging should prefer an ephemeral per-process correlation identifier when request correlation is needed.

### Explicit security evidence

A caller may opt into a separate structured evidence interface after successful verification, conceptually:

```text
SenderBindingEvidence
- mechanism: DPoP
- key_thumbprint: jkt
- algorithm: ES256
- target/resource identifier chosen by the host
- verification time
- nonce_enforced: bool
- replay_checked: bool
```

The evidence interface:

- is not enabled merely by increasing log verbosity;
- never includes access-token bytes, raw proof JWT, nonce, private key, or raw `jti`;
- makes retention/export the caller's explicit responsibility;
- documents that `key_thumbprint` is a stable pseudonymous correlator;
- can be mapped into audit/provenance systems such as a gateway or governance layer without exposing credential material.

A deployment that does not need key-level attribution may omit the thumbprint from exported evidence.

### Errors

Public/protocol errors reveal only what the relevant OAuth/DPoP protocol requires. Internal errors retain structured machine-readable failure categories without embedding attacker-controlled proof/token fields.

Example internal categories include:

```text
MalformedProof
UnsupportedAlgorithm
InvalidSignature
RequestBindingMismatch
ProofExpired
NonceRequired
NonceMismatch
ReplayDetected
ReplayStoreUnavailable
TokenBindingMissing
TokenBindingMismatch
```

## Consequences

### Positive

- reduces accidental credential leakage through diagnostics;
- avoids unbounded/high-cardinality metric labels;
- preserves an explicit path for Anthesis/Invokrum-style provenance and audit evidence;
- makes the privacy tradeoff of stable key identifiers visible.

### Negative

- troubleshooting cannot rely on dumping raw proofs/tokens;
- evidence consumers must make their own retention/privacy decisions;
- some debugging requires controlled local reproduction rather than production log inspection.

## Required tests

- secret wrapper `Debug`/error snapshots contain no raw credentials;
- malformed attacker-controlled input is not reflected into logs/errors;
- metric label schemas contain no token/proof/nonce/`jti`/raw `jkt` fields;
- default verified-result tracing omits raw `jkt`;
- explicit evidence output contains only the documented compact fields;
- evidence can be configured to omit the key thumbprint.