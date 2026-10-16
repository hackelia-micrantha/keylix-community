# Keylix Client Design

> **Keylix Client scope.** Covers the mobile/desktop SDK product design only. The canonical protocol-level design baseline lives in the public [`keylix-community`](https://github.com/hackelia-micrantha/keylix-community) repository: [docs/DESIGN.md](https://github.com/hackelia-micrantha/keylix-community/blob/main/docs/DESIGN.md). On any conflict, the public canonical source governs.

**Status:** design phase — initial baseline. Implementation should follow the decisions and invariants recorded here, in [`THREAT_MODEL.md`](THREAT_MODEL.md), [`REQUIREMENTS.md`](REQUIREMENTS.md), and the [ADRs](adr/README.md).

## Purpose

Keylix Client brings sender-constrained DPoP (RFC 9449) proof generation to mobile and client-side platforms, with platform-native secure storage for private keys as the non-negotiable root of trust. It provides a consistent cross-platform client API across Kotlin, Swift, React Native, KMP, Web, and CLI targets.

Keylix Client is deliberately **not** an authorization server, OAuth flow framework, token issuer, policy engine, or identity provider. Its job is narrower: generate DPoP-bound proof JWTs with keys that resist extraction, and compose those proofs with OAuth token lifecycle events.

## Design Goals

1. **Proof-correctness first.** RFC 9449 proof construction and wire format must be conformant before any platform-specific feature is added.
2. **Hardware-backed keys by default.** Private keys MUST be generated and stored in platform secure hardware (Secure Enclave, AndroidKeyStore with StrongBox, WebCrypto non-extractable). Software fallback is allowed only with explicit user consent and degraded-capability signaling.
3. **No key extraction.** Signing capability is primary. Raw private-key bytes MUST NOT be available to application code, even in "software fallback" mode.
4. **Unified cross-platform API.** Core proof-builder / nonce-store / token-binding interfaces are shared across platforms via expect/actual (KMP), FFI bridges, or shared Rust core.
5. **Fail-closed.** Attestation failure, key generation failure, or secure-storage unavailability fails the bootstrap — never silently downgrades to bearer.
6. **Composable with Keylix.** Mobile-generated proofs MUST be verifiable by the Rust `keylix-dpop` verifier. Mobile verifiers SHOULD consume `keylix-dpop` where a Rust runtime exists.
7. **Defense in depth.** DPoP complements TLS, attestation (Digitalis), and authorization policy; it does not replace them.

## Scope

Keylix Client provides or defines:

- DPoP proof generation (RFC 9449) with platform-native secure key storage
- Non-extractable signing-capability abstraction (mirrors Keylix `DpopSigner`)
- JWK thumbprint (RFC 7638) derivation from the public key
- OAuth token-binding composition helpers (proof decoration on token request, `ath` for resource requests)
- Nonce and replay-state management for the client side
- Platform attestation integration point (Digitalis) for high-assurance bootstrap
- Cross-platform API contract (KMP expect/actual shape, or equivalent)
- Language-specific SDKs: Android (Kotlin), iOS (Swift), KMP, React Native (TypeScript)
- Adapters for Web (WebCrypto) and CLI (OS keychain)
- Optional Rust core cross-compilation path via `uniffi` / JNI

Keylix Client does **not** provide:

- A general OAuth / OIDC client implementation
- Authorization server logic
- Token issuance or JWT validation
- Identity provider integration
- Logging/metrics infrastructure (bounded telemetry only)

## System Context

```text
                 +---------------------------+
                 | Authorization Server / IdP |
                 | OAuth metadata + tokens    |
                 +-------------+-------------+
                               |
                  token request + DPoP proof
                               |
+--------------------+         |         +------------------------------+
| Mobile Application |---------+-------->| Keylix Client SDK     |
| (Kotlin/Swift/RN)  |                   | proof gen + nonce + token    |
+--------------------+                   +------------+--------+--------+
                                                      |        |
                                                      | proof  | signing
                                                      |        |
                                                      v        v
                                          +---------------+  +--------------------+
                                          | OAuth         |  | Platform Secure    |
                                          | Composition   |  | Hardware / Keystore |
                                          +---------------+  +--------------------+
                                                      |
                                                      | Digitalis attestation (optional)
                                                      v
                                          +--------------------+
                                          | Digitalis Backend  |
                                          | (app attest / play |
                                          |  integrity)        |
                                          +--------------------+
```

## Layering

```text
Keylix Client Public API
       ^
       |  shared contract (KMP expect / actual or Rust FFI)
       |
Keylix Client Core
       |
       +---> Proof Builder      (RFC 9449 proof JWT construction)
       +---> Token Binding      (OAuth token-request decoration + ath)
       +---> Nonce Store        (AS/RS nonce handling, fresh proof per retry)
       +---> Key Reference      (signing-capability handle, NOT raw key)
       |
       +---> Secure Storage Port (platform abstraction)
               |
               +-- iOS:       Secure Enclave (CryptoKit / SecKey)
               +-- Android:   AndroidKeyStore + StrongBox
               +-- KMP:       expect/actual delegating to above
               +-- Web:       CryptoKey (non-extractable)
               +-- CLI:      OS keychain (keychain-rs / keyring)
               +-- Rust FFI:  keylix-core via uniffi
```

Dependencies point inward. The public API depends on the core. The core depends on the secure-storage port. Platform implementations depend on the port. No layer reaches sideways to another platform.

## Verified-State Model

Mirrors Keylix's trust-state distinctions, adapted for client-side:

```text
raw key handle / signing capability
          |
          v
 UnverifiedProofIntent  (caller intent: method, url, iat, nonce, access_token?)
          |
          |  sign + build (RFC 9449)
          v
 SerializedDpopProof    (a conformant DPoP proof JWT, ready for the wire)
```

On the verification side (e.g. a gateway or local resource validation):

```text
raw DPoP header bytes
          |
          v
 UnverifiedDpopProof
          |
          |  verify(policy, effective_request, access_token, state)
          v
   VerifiedDpopProof    (or equivalent from keylix-dpop)
```

## Ports and Adapters

### Client-side ports

| Port | Responsibility |
|------|---------------|
| `SecureSigner` | Exposes ES256 signing capability and public JWK; never exposes private-key bytes. Mirrors Keylix `DpopSigner`. |
| `ProofIdGenerator` | Cryptographically strong fresh `jti` generation (CSPRNG, UUID v4 acceptable). |
| `NonceStore` | Stores and returns the latest AS nonce and RS nonce separately. |
| `Clock` | Injectable clock for `iat` and proof-lifetime calculations. |
| `AttestationProvider` | Optional platform attestation integration (Digitalis). |
| `TokenStore` | Stores DPoP-bound access/refresh tokens and associated key references. |

### Platform secure-storage adapters

| Platform | Adapter | Non-extractable guarantee |
|----------|---------|--------------------------|
| iOS | `SecureEnclaveSigner` (CryptoKit `SecureEnclave.P256.Signing.PrivateKey` or `SecKey` with `kSecAttrTokenIDSecureEnclave`) | Hardware-isolated; key material never enters application memory |
| Android | `AndroidKeyStoreSigner` (`KeyGenParameterSpec` with `setIsStrongBoxBacked(true)` where available, `setUserAuthenticationRequired` optional) | TEE/StrongBox; key export blocked by OS |
| KMP | `ExpectActualSigner` delegating to the above via source sets | Platform-specific |
| Web | `CryptoKeySigner` (`crypto.subtle.generateKey` with `extractable=false`) | Browser-enforced non-extractable |
| CLI | `KeychainSigner` (via `keyring` crate or OS-specific APIs) | OS keychain; software fallback allowed |
| Rust FFI | `KeylixDpopSigner` (wraps `keylix-dpop` via `uniffi`) | Configurable: software or HSM |

## Algorithm and Crypto Policy

Baseline (matches Keylix v0.1 profile):

```text
JWS alg = ES256
JWK kty = EC
JWK crv = P-256
```

Only P-256 / ES256 is supported in the initial profile. Proof header embeds a full JWK (RFC 9449 Section 4.2) with `kty`, `crv`, `x`, `y`. The JWK thumbprint follows RFC 7638.

All proof construction uses the narrow, shared JWK/thumbprint serialization. Platforms MUST NOT invent their own JOSE framing.

## State Model

### Replay / Nonce

Client-side nonce handling tracks two independent namespaces:

```text
authorization server nonce != resource server nonce
```

- Stored nonces are scoped to their issuing server.
- Each retry creates a **fresh proof with a new `jti`** — never re-signs with the same `jti` after a nonce challenge.

### Key lifecycle

- A DPoP-bound refresh-token relationship stays bound to the same proof key for the lifetime of that relationship.
- Transparent local key rotation MUST NOT silently move an active bound refresh token to another key.
- App reinstall or explicit key-reset starts a new key-pair + new OAuth session.

## Error Model

Structured internal errors, intentionally lossy at SDK boundaries:

> Note: the canonical, complete error taxonomy is docs/API_CONTRACT.md §1.5 (adds the `Storage` category and variants such as `BIOMETRIC_LOCKED`, `NETWORK_ERROR`, `clockSkewExceeded`, `invalidAccessToken`). This section is a subset; new code should follow §1.5.

```text
KeyGenerationError
  - secureHardwareUnavailable
  - algorithmUnsupported
  - userCancellation

SigningError
  - keyLocked (auth required, not provided)
  - hardwareFailure

ProofError
  - invalidTarget
  - nonceRequired
  - nonceStale

AttestationError
  - providerUnavailable
  - verdictDenied
  - integrityCompromised
```

External SDK surfaces map these to platform-idiomatic errors without exposing key material or raw proof contents.

## Attestation Integration

High-assurance applications MAY integrate [Digitalis attestation](https://github.com/hackelia-micrantha/digitalis/blob/main/docs/attest_sdk_v_1_control_contract.md):

1. On bootstrap, the SDK generates the DPoP proof key in secure hardware.
2. The SDK obtains a platform attestation (Apple App Attest or Google Play Integrity) **bound to that key** — the attestation evidence includes the DPoP key's public key.
3. The attestation token is sent to the Digitalis backend for verification.
4. If verdict = ALLOW, the key becomes active and the SDK continues.
5. If verdict = DENY, the SDK **deletes the DPoP proof key** from secure hardware and fails closed.
6. The attestation can bind to the key's public attestation record (Android key attestation certificate chain, iOS App Attest assertion over the DPoP public key).

This is optional and policy-driven. Without attestation, the SDK still operates with secure hardware.

## Conformance Strategy

1. Mobile-generated proof JWTs MUST verify against `keylix-dpop` test vectors.
2. A shared conformance corpus (JSON fixtures) lives in `tests/consumed/` and is executed by both native SDKs and the Keylix Rust verifier.
3. Platform-specific roundtrip tests assert: key generation → public JWK → thumbprint → proof → verification.
4. Negative tests cover: malformed URL, wrong `ath`, stale `iat`, missing nonce, algorithm mismatch.

## Delivery Sequence

```text
Design / ADRs / Requirements (this document)
              |
              v
KMP core + Android implementation (first buildable target)
              |
              v
iOS (Swift) SDK
              |
              v
React Native bridge
              |
              v
Web adapter
              |
              v
CLI adapter
              |
              v
Rust core cross-compilation (uniffi)
```

## Future Evolution

- Additional signature algorithms (e.g. EdDSA / Ed25519 if DPoP ecosystem adopts them)
- Framework-specific React Native / Flutter plugin wrappers
- Device-bound passkey integration (FIDO2) for DPoP key protection
- Distributed nonce/replay state for multi-device apps
- Rich provenance evidence via `keylix-observe`
