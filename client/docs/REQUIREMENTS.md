# Requirements and Test Traceability

> **Keylix Client scope.** Tracks mobile/desktop SDK requirements under the `KXM-*` scheme. The canonical protocol-level requirements (scheme `KX-*`) live in the public [`keylix-community`](https://github.com/hackelia-micrantha/keylix-community) repository: [docs/REQUIREMENTS.md](https://github.com/hackelia-micrantha/keylix-community/blob/main/docs/REQUIREMENTS.md). On any conflict, the public canonical source governs.

**Status:** design phase — initial baseline.

This document defines Keylix Client's executable requirements with IDs (`KXM-*`) and maps each to its verification method. Implementation PRs should reference affected IDs and land corresponding positive and negative tests.

## Requirement Categories

| Prefix | Domain |
|--------|--------|
| KXM-CORE | Core proof generation and lifecycle |
| KXM-KEY | Key generation and secure storage |
| KXM-BIND | Token binding and request binding |
| KXM-NONCE | Nonce handling |
| KXM-ATTEST | Attestation integration |
| KXM-API | Public API contract |
| KXM-ERR | Error handling and observability |
| KXM-SEC | Security invariants |

## KXM-CORE: Core Proof Generation

| ID | Requirement | Verification |
|----|-------------|-------------|
| KXM-CORE-01 | The SDK generates DPoP proof JWTs conformant to RFC 9449 Section 4 | Conformance vector test: generated proof verifies against `keylix-dpop` |
| KXM-CORE-02 | Every proof contains a unique `jti` from a CSPRNG | Unit test: generate N proofs, assert all `jti` distinct |
| KXM-CORE-03 | The `iat` claim is derived from an injected `Clock` | Unit test: inject fixed clock, assert `iat` matches |
| KXM-CORE-04 | The `htm` claim is the exact HTTP method (uppercase) | Unit test: GET, POST, PUT, DELETE, PATCH |
| KXM-CORE-05 | The `htu` claim is the normalized request URI (no query, no fragment) | Unit test: URL with query/fragment is stripped |
| KXM-CORE-06 | The proof header contains a full EC JWK (`kty`, `crv`, `x`, `y`) | Unit test: parse header, assert all four fields present |
| KXM-CORE-07 | The JWS `alg` is always `ES256` | Unit test: assert header.alg == "ES256" |
| KXM-CORE-08 | The signature is raw R||S (64 bytes), not DER | Unit test: decode signature, assert length == 64 |
| KXM-CORE-09 | The proof builder never holds private-key bytes | Code review: no `PrivateKey` material in proof builder scope |
| KXM-CORE-10 | Proof construction is deterministic given fixed inputs (clock, jti, key) | Property test: same inputs → same proof |

## KXM-KEY: Key Generation and Secure Storage

| ID | Requirement | Verification |
|----|-------------|-------------|
| KXM-KEY-01 | Keys are generated inside platform secure hardware | Platform test: generate key, attempt export, assert failure |
| KXM-KEY-02 | The SDK returns a key reference (alias), not key material | Unit test: assert return type is `KeyReference` |
| KXM-KEY-03 | Public key is exportable as RFC 7517 JWK | Unit test: export JWK, validate against RFC 7517 schema |
| KXM-KEY-04 | RFC 7638 thumbprint is derivable from the public key | Unit test: compute thumbprint, compare with known vector |
| KXM-KEY-05 | Key deletion removes the key from secure storage | Unit test: delete key, attempt sign, assert `keyNotFound` |
| KXM-KEY-06 | iOS: keys use Secure Enclave (`kSecAttrTokenIDSecureEnclave`) | iOS test: inspect key attributes |
| KXM-KEY-07 | Android: keys use AndroidKeyStore with StrongBox when available | Android test: check `isInsideSecureHardware()` / StrongBox |
| KXM-KEY-08 | Web: keys are non-extractable (`extractable=false`) | Web test: attempt `exportKey`, assert rejection |
| KXM-KEY-09 | Hardware-unavailable fallback requires explicit user consent | Integration test: mock hardware failure, assert consent prompt |
| KXM-KEY-10 | Importing pre-existing keys is NOT supported in v1 | API review: no import API exists |

## KXM-BIND: Token and Request Binding

| ID | Requirement | Verification |
|----|-------------|-------------|
| KXM-BIND-01 | The `ath` claim is `base64url(sha256(access_token))` | Unit test: known token → known ath |
| KXM-BIND-02 | `ath` is computed by the SDK, not the caller | API review: no `ath` parameter in public API |
| KXM-BIND-03 | `ath` is omitted when no access token is provided | Unit test: proof without token has no `ath` |
| KXM-BIND-04 | Token-request proof decoration adds the proof to the `DPoP` header | Integration test: token request includes `DPoP` header |
| KXM-BIND-05 | Resource-request proof includes `ath` for the presented token | Integration test: resource request proof contains correct `ath` |
| KXM-BIND-06 | `htu` normalization follows RFC 3986 (scheme/host lowercase, default ports stripped) | Unit test: various URL forms → canonical form |

## KXM-NONCE: Nonce Handling

| ID | Requirement | Verification |
|----|-------------|-------------|
| KXM-NONCE-01 | AS nonce and RS nonce are stored separately | Unit test: set both, assert independent retrieval |
| KXM-NONCE-02 | A nonce challenge triggers a fresh proof with new `jti` | Unit test: nonce retry → new `jti` |
| KXM-NONCE-03 | The nonce is echoed verbatim in the `nonce` claim | Unit test: set nonce, assert proof contains it |
| KXM-NONCE-04 | Nonce is cleared after a successful response without a new challenge | Unit test: success → nonce cleared |
| KXM-NONCE-05 | Retries never reuse the same `jti` | Unit test: multiple retries → distinct `jti` values |

## KXM-ATTEST: Attestation Integration

| ID | Requirement | Verification |
|----|-------------|-------------|
| KXM-ATTEST-01 | Attestation is optional and policy-driven | API review: attestation is a separate config flag |
| KXM-ATTEST-02 | Key is generated FIRST in secure hardware; attestation is then bound to that key; on DENY the key is deleted (never enters service) | Integration test (key-first, per ADR KXC-0004): key generated, attestation bound, DENY → key deleted; proof generation only after ALLOW |
| KXM-ATTEST-03 | Attestation verdict is authoritative from the Digitalis backend | Integration test: mock backend verdict, assert SDK behavior |
| KXM-ATTEST-04 | Attestation failure fails closed for high-assurance features | Integration test: attestation fail → bootstrap denied |
| KXM-ATTEST-05 | Attestation nonce binding prevents replay | Unit test: attestation nonce is single-use |

## KXM-API: Public API Contract

| ID | Requirement | Verification |
|----|-------------|-------------|
| KXM-API-01 | The public API is async (coroutines / async-await / Promise) | API review: all network/signing calls are async |
| KXM-API-02 | The API shape is consistent across Kotlin, Swift, TypeScript | Cross-platform review: compare API signatures |
| KXM-API-03 | The KMP `expect` contract matches all `actual` implementations | KMP test: compile all targets |
| KXM-API-04 | React Native delegates to native SDKs, does not reimplement crypto | Code review: RN module calls native bridge |
| KXM-API-05 | Bootstrap is a single entry point returning a structured result | API review: `bootstrap(config): BootstrapResult` |
| KXM-API-06 | The SDK is injectable for testing (clock, signer, rng) | Unit test: inject mocks, verify behavior |

## KXM-ERR: Error Handling and Observability

| ID | Requirement | Verification |
|----|-------------|-------------|
| KXM-ERR-01 | Errors are structured internally but lossy at SDK boundaries | Unit test: internal error → platform-idiomatic error |
| KXM-ERR-02 | No private key bytes in any error message or log | Log inspection test |
| KXM-ERR-03 | No access tokens in any error message or log | Log inspection test |
| KXM-ERR-04 | No raw `jti` or nonce values in logs | Log inspection test |
| KXM-ERR-05 | Bounded telemetry categories are emitted for state transitions | Unit test: assert telemetry events |
| KXM-ERR-06 | Increasing log verbosity does not enable the evidence path | Configuration test |

## KXM-SEC: Security Invariants

| ID | Requirement | Verification |
|----|-------------|-------------|
| KXM-SEC-01 | Private key bytes are never in application memory | Platform-specific export test |
| KXM-SEC-02 | Each proof has a unique `jti` | Property test |
| KXM-SEC-03 | `ath` binds the exact token bytes | Unit test: token change → different `ath` |
| KXM-SEC-04 | Nonce retry creates a new proof | Unit test |
| KXM-SEC-05 | Hardware-unavailable does not silently downgrade | Integration test: mock failure, assert explicit consent |
| KXM-SEC-06 | Attestation denial blocks high-assurance bootstrap | Integration test |
| KXM-SEC-07 | DPoP-required flow does not fall back to bearer | Integration test: missing proof → request rejected |
| KXM-SEC-08 | The SDK does not implement custom cryptography | Dependency review: only platform crypto APIs used |

## Traceability Matrix

```text
KXM-CORE  →  proof builder unit tests, conformance vectors
KXM-KEY   →  platform key generation tests, export-block tests
KXM-BIND  →  ath/htu/htm unit tests, integration tests
KXM-NONCE →  nonce store unit tests, retry integration tests
KXM-ATTEST→  attestation integration tests (optional)
KXM-API   →  cross-platform API review, KMP compile tests
KXM-ERR   →  log inspection tests, error mapping tests
KXM-SEC   →  security invariant tests, negative tests
```
