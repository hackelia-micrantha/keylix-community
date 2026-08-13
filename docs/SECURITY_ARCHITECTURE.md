# Security Architecture

This document defines Keylix's security boundaries and v0.1 posture. `SECURITY.md` describes vulnerability reporting; this document describes how the system is intended to be secure.

## Security objective

Given a presented access token and a trusted OAuth validation result for that exact token, Keylix establishes proof-of-possession evidence that the current HTTP request carries a valid, fresh DPoP proof signed by the bound private key and tied to the request method, target URI, and token value.

This is not authentication, authorization, workload identity, or policy approval.

## Trust boundaries

```text
untrusted HTTP / compact JWS / JWK
              |
              v
trusted HTTP adapter
- actual method
- EffectiveRequestTarget
- explicit proxy policy
              |
              v
keylix-dpop
- strict compact-JWS parsing
- ES256/P-256 policy
- signature
- htm / htu
- freshness / nonce
- ath
- atomic replay
              |
              v
VerifiedDpopProof
              |
              | + trusted OAuth validation result
              |   correlated to exact token bytes
              v
keylix-oauth
- cnf.jkt / proof-key match
              |
              v
VerifiedSenderBinding
              |
              v
application / gateway / policy / governance
```

## Attacker model

Assume an attacker can steal tokens without the proof key, capture/replay proofs, create arbitrary JOSE/JWK input, choose `alg` values, substitute tokens or key metadata, race replicas, manipulate URI spellings/forwarded headers, exploit clock skew, exhaust replay state, trigger state outages, observe ordinary logs/metrics, and compromise neighboring components independently.

DPoP does not replace TLS or defend a fully compromised client runtime that can invoke the legitimate signing capability.

## JOSE and key policy

ADR-0005 fixes v0.1 to:

```text
alg = ES256
kty = EC
crv = P-256
```

`none`, MAC algorithms, RSA, other curves, other signature algorithms, private JWK parameters, malformed points, and key/algorithm mismatches are rejected. Untrusted `alg` never expands policy.

ADR-0010 selects `aws-lc-rs` as the default native P-256/SHA-256 backend. Keylix owns a narrow, size-bounded compact-JWS parser rather than delegating DPoP trust semantics to a generic JWT decoder. Signature verification uses the original encoded header/payload segments and the RFC 7518 fixed 64-byte ES256 `R || S` representation.

Private-key APIs are signing-capability-based so software, keystore, HSM, TPM, KMS, or PKCS#11 implementations do not need to expose raw private key bytes.

RFC 7638 thumbprints use only `crv`, `kty`, `x`, and `y` in lexicographic member-name order, SHA-256, base64url without padding.

## Request binding

Per ADR-0006, `keylix-dpop` consumes a trusted `EffectiveRequestTarget`; it never trusts `Forwarded` or `X-Forwarded-*` directly.

```text
trusted external URI -> strip query/fragment -> RFC3986 normalization
proof htu            -> strip query/fragment -> RFC3986 normalization
                                           -> exact comparison
```

Proxy-aware adapters require explicit trust configuration and fail closed on ambiguous external-target reconstruction.

## Token binding

Sender binding is deliberately two-stage.

`keylix-dpop` verifies `ath` against the exact presented access-token bytes and produces `VerifiedDpopProof`.

`keylix-oauth` then consumes a trusted host OAuth validation result for that exact token and verifies that its `cnf.jkt` (or equivalent trusted confirmation value) equals the verified proof-key thumbprint before producing `VerifiedSenderBinding`.

Decoded-but-unvalidated JWT claims, unauthenticated introspection output, arbitrary `jkt` strings, and token-A-validation/token-B-presentation combinations cannot satisfy this boundary (ADR-0007).

## Freshness, replay, and nonce

ADR-0009 defines the visible/configurable default:

```text
max proof age   = 300 seconds
max future skew = 300 seconds
```

Replay enforcement is atomic:

```text
check_and_record(replay_key, expiry)
    -> Fresh | Replay | StoreFailure
```

The replay identity is derived from proof key thumbprint + canonical HTTP method + normalized `htu` + `jti`, preferably stored as a fixed-size digest. `ath` is intentionally excluded.

Logical expiry is `iat + max_proof_age`. A future-dated proof accepted at the default skew boundary can require up to 600 seconds of remaining replay-store TTL. Strict replay-store failure fails closed. Multi-instance strict replay protection requires shared atomic state or equivalent routing semantics; process-local state is not cluster-safe.

Clients support both authorization-server and resource-server nonce challenges. Nonces are scoped to the issuing server, retries create fresh proofs/new `jti`, and server nonce enforcement is supported but opt-in. Once challenged, nonce enforcement cannot silently downgrade to nonce-less acceptance.

## Downgrade resistance

A DPoP-required token flow rejects a non-`DPoP` token type. A DPoP-bound protected-resource request uses `Authorization: DPoP` and never silently retries as Bearer.

Per ADR-0008, `keylix-mcp` remains an explicit draft/profile adapter while SEP-1932 is unstable; MCP profile uncertainty cannot weaken RFC 9449 behavior.

## Key lifecycle

Bound refresh-token/proof-key continuity is explicit. A public client's active DPoP-bound refresh-token relationship is not transparently moved to a newly rotated local key.

Non-extractable keys reduce exfiltration risk but do not prevent malicious in-process code from invoking the signer while the runtime is compromised.

## Observability and evidence

ADR-0011 separates ordinary telemetry from explicit security evidence.

Normal logs/errors/metrics do not contain access/refresh tokens, authorization secrets, private key material, full proofs, raw nonces, raw `jti`, HTTP credential-header values, or raw JWK thumbprints. Metrics use bounded low-cardinality failure/result dimensions.

An explicitly configured security-evidence sink may emit a compact verified sender-binding record, optionally including the public-key thumbprint for audit/provenance. Increasing log verbosity does not enable that evidence path.

## Failure categories

Internal failures are structured enough for safe operations without reflecting sensitive attacker-controlled values:

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
TokenIdentityMismatch
TokenBindingMismatch
```

Protocol adapters expose only the information required by the relevant OAuth/DPoP behavior.

## Dependency and supply-chain posture

- no custom cryptographic algorithms;
- narrow JOSE parsing and explicit algorithm policy;
- pinned/tested MSRV and lockfile;
- dependency advisory/update automation;
- fuzzing of all untrusted compact-JWS/JWK/verifier boundaries;
- independent ES256 interoperability testing;
- review of native/crypto transitive dependencies before a production-ready release.

## Release security gates

A production-ready release requires:

- reconciled threat model and accepted ADRs;
- all in-scope `KX-*` requirements implemented and covered;
- RFC 7638 and RFC 9449 positive/negative coverage;
- replay race/state-failure tests;
- nonce retry/downgrade tests;
- parser/verifier fuzzing with useful corpora and no known crashes;
- diagnostics-leakage tests;
- no unsafe code unless a future ADR explicitly changes workspace policy;
- dependency audit or documented exceptions;
- MCP tests clearly separated from RFC-level DPoP conformance and labeled with the draft/stable profile they exercise.
