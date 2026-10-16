# Security Architecture

> **Keylix Client scope.** Covers mobile/desktop SDK security invariants only. The canonical protocol-level security architecture lives in the public [`keylix-community`](https://github.com/hackelia-micrantha/keylix-community) repository: [docs/SECURITY_ARCHITECTURE.md](https://github.com/hackelia-micrantha/keylix-community/blob/main/docs/SECURITY_ARCHITECTURE.md). On any conflict, the public canonical source governs.

**Status:** design phase — initial baseline.

Defines Keylix Client's security boundaries, invariants, and v1 posture.

## Security Objective

Given a mobile application that holds an OAuth access token, Keylix Client generates DPoP proof JWTs signed by a key that resists extraction, binds each proof to the exact HTTP method, URL, and token value, and ensures the proof key is anchored in platform secure hardware.

This is not authentication, authorization, identity, or policy. It is proof-of-possession key management and proof lifecycle on mobile clients.

## Trust Boundaries

```text
Untrusted application code / process memory
              |
              | (invokes SDK API)
              v
+-----------------------------------+
| Keylix Client Public API          |
| (KeylixClient.createProof)        |
+----------------+------------------+
                 |
                 | proof request (method, url, token, nonce)
                 v
+-----------------------------------+
| Core Proof Builder                |
| (RFC 9449 construction)          |
+----------------+------------------+
                 |
                 | signing input (JWS Signing Input)
                 v
+-----------------------------------+
| Secure Storage Port               |
| (platform abstraction)            |
+----------------+------------------+
                 |
                 | cryptographic operation
                 v
+-----------------------------------+
| Hardware Boundary                 |
| Secure Enclave | StrongBox | TEE |
| (key gen + sign inside silicon)   |
+-----------------------------------+
```

## Key Policy

### v1 Profile (matches Keylix v0.1)

```text
JWS alg = ES256
JWK kty = EC
JWK crv = P-256
ES256 signature: raw R||S (64 bytes), NOT DER-encoded
```

Only P-256/ES256 is supported in the initial profile. No RSA, no other curves, no `none`, no MAC.

### Non-Extractable Mandate

Private key bytes MUST NEVER be accessible to application code. The SDK operates entirely through signing-capability handles:

| Platform | API | Guarantee |
|----------|-----|-----------|
| iOS | `SecureEnclave.P256.Signing.PrivateKey` | Hardware-enforced; key material in Secure Enclave coprocessor |
| Android | `KeyPairGenerator` with `AndroidKeyStore` provider | OS-enforced; `PrivateKey` object cannot export key material |
| Web | `crypto.subtle.generateKey({extractable: false})` | Browser-enforced |
| CLI | OS keychain (Keychain / DPAPI / libsecret) | OS-enforced; software fallback with user consent only |
| Rust FFI | `keylix-core` `DpopSigner` trait | Configurable; HSM/keystore backends available |

### Key Generation

Keys MUST be generated inside the secure hardware. Importing pre-existing keys into secure storage is NOT supported in v1 — it would require exposing private-key bytes.

```text
generateKeyPair(alias):
  1. request secure hardware to generate P-256 key pair
  2. store public JWK derivation (x, y) for later thumbprint
  3. return KeyReference (alias) — NOT the key material
```

## Proof Construction Invariants

1. **Fresh `jti`.** Every proof has a unique `jti` from a CSPRNG.
2. **`iat` from injected clock.** Not from device system time directly (testability + skew control).
3. **`htm` is the exact HTTP method** (uppercase, as sent on the wire).
4. **`htu` is the exact request URI** — scheme + host + port + path; no query, no fragment, RFC 3986 normalized.
5. **`ath` when access token present** — `base64url(SHA-256(access_token_bytes))`.
6. **`nonce` when provided** — the server's DPoP nonce echoed verbatim.
7. **Public JWK in header.** The DPoP header contains the full EC public key (`kty`, `crv`, `x`, `y`) — this is standard RFC 9449 behavior and NOT a secret.

## Nonce Handling

```text
AS nonce != RS nonce  (separate namespaces)

On "use_dpop_nonce" challenge:
  1. extract nonce from response header
  2. store in NonceStore (scoped to server)
  3. generate a FRESH proof with NEW jti + the nonce
  4. retry the request

Retries MUST NOT:
  - reuse the same jti
  - skip the nonce
  - use the old signature
```

## Token Binding

The `ath` claim binds the DPoP proof to a specific access token:

```text
ath = base64url(SHA-256(access_token_bytes))
```

This is computed by the SDK from the exact access-token bytes the caller presents. The caller MUST NOT pre-compute `ath`; the SDK takes the raw token string.

## Key Attestation Details

Key attestation allows the backend to verify that a DPoP key was generated in genuine platform hardware. This is OPTIONAL and policy-driven.

### Android Key Attestation

Android provides a certificate chain proving that a key resides in hardware. The DPoP proof key is generated FIRST, with the attestation challenge bound to it during generation.

```text
Flow (correct order):
  1. Call KeyGenParameterSpec.Builder.setAttestationChallenge(challenge)
     during DPoP proof key generation
  2. Generate the key — the AndroidKeyStore creates a certificate chain
     that includes the DPoP key's public key as the leaf subject
  3. Retrieve the chain via KeyStore.getCertificateChain(alias)
  4. The leaf certificate contains the key's attributes (hardware-backed, purpose, etc.)
  5. The chain is signed by Google's root attestation certificate
  6. Backend verifies: chain validity, challenge match, root certificate,
     key attributes, AND that the leaf public key matches the presented DPoP key thumbprint

Certificate chain:
  Leaf (key attestation cert, subject = DPoP public key) → Intermediate → Root (Google hardware attestation root)

Verification checks:
  - Chain signatures valid
  - Root is in the trusted root set (Google's published roots)
  - Challenge matches the value the backend provided
  - Key is marked hardware-backed (not software)
  - Key purpose includes SIGN
  - Key algorithm is EC P-256
  - Leaf public key == the DPoP proof key (prevents key substitution)

On DENY: KeyStore.deleteEntry(alias) — the DPoP key is destroyed

Attestation verification roots:
  - https://developer.android.com/training/articles/security-key-attestation#root_certificate
```

**StrongBox vs TEE:** The attestation certificate includes a security level field. `StrongBox` indicates a dedicated hardware security module; `TEE` indicates a trusted execution environment within the main processor. Both are acceptable, but StrongBox provides stronger guarantees.

### iOS App Attest Integration

Apple's App Attest integrates with Digitalis for device integrity verification. The DPoP proof key is generated FIRST in Secure Enclave, then App Attest creates an assertion over that specific key.

```text
Flow (correct order):
  1. Generate the DPoP proof key in Secure Enclave
     (SecureEnclave.P256.Signing.PrivateKey)
  2. Export the DPoP public key (x963Representation)
  3. Compute clientDataHash = SHA-256(DPoP public key)
     This binds the assertion to the DPoP proof key
  4. DCAppAttestService.shared.generateAssertion(keyId, clientDataHash) → assertion
     (keyId is from a one-time App Attest key, NOT the DPoP key)
  5. Send assertion + DPoP key thumbprint to Digitalis backend
  6. Digitalis verifies with Apple servers:
     - Assertion signature (signed by the device)
     - Certificate chain (device → Apple)
     - Challenge nonce (matches the one issued)
     - App identity (bundle ID, team ID)
     - clientDataHash corresponds to the presented DPoP key
  7. Returns verdict: ALLOW / DENY

Important: App Attest keyId and DPoP proof key are DIFFERENT keys:
  - App Attest key: one-time setup key for generating assertions
    (created via DCAppAttestService.generateKey(), stored in Secure Enclave)
  - DPoP proof key: the signing key for DPoP proofs
    (created via SecureEnclave.P256.Signing.PrivateKey())
  - They are linked by: clientDataHash = SHA-256(DPoP public key)
    so the assertion proves "the DPoP key exists in this genuine device"

On DENY: SecItemDelete(dpopKeyRef) — the DPoP key is destroyed
```

### Binding Attestation to DPoP Key

The DPoP key is generated FIRST. Attestation is then bound to that key. This is the only correct ordering — the attestation must prove "this specific key was generated in genuine hardware."

```text
Android (correct order):
  1. Generate P-256 key pair in AndroidKeyStore (the DPoP proof key)
  2. Export the public key
  3. Call setAttestationChallenge(publicKeyBytes) — this creates an
     attestation certificate chain that includes the DPoP key's public key
  4. Submit the attestation chain to Digitalis
  5. Digitalis verifies: chain validity + key in cert == presented key thumbprint
  6. If DENY → deleteKey(alias); key is destroyed, cannot be used for DPoP

iOS (correct order):
  1. Generate P-256 key pair in Secure Enclave (the DPoP proof key)
  2. Export the public key
  3. Compute clientDataHash = SHA-256(publicKey)
  4. Call DCAppAttestService.generateAssertion(keyId, clientDataHash)
  5. Submit the assertion to Digitalis
  6. Digitalis verifies: assertion signature + key matches thumbprint
  7. If DENY → deleteKey(alias); key is destroyed

Key point: the key is created BEFORE attestation so the attestation evidence
references it. If attestation fails, the key is deleted — it never becomes
active for DPoP proof generation.
```

## Downgrade Resistance

- A DPoP-required token flow does not silently fall back to bearer.
- A DPoP-bound protected-resource request does not retry without a proof.
- Hardware-unavailable fallback requires explicit user consent + signaling to the backend.
- Nonce enforcement, once established by the server, cannot be downgraded.

## Key Lifecycle Security

### Key Generation
- MUST happen inside secure hardware.
- No import of existing keys (would expose private bytes).
- Key alias is the only stored reference.

### Key Usage
- Signing requires user authentication if biometric gating is configured.
- Failed auth attempts are rate-limited by the platform.
- Key cannot be exported — only signing capability is exposed.

### Key Deletion
- `deleteKey()` removes the key from secure hardware.
- After deletion, any DPoP proofs signed by that key become unusable.
- Deletion is immediate and irreversible.

### Key Rotation
- DPoP key rotation requires a new OAuth session (new authorization code flow).
- The bound refresh-token relationship stays with the original key.
- Transparent mid-session key rotation is NOT supported (would break token binding).

## Memory Security

| Concern | Mitigation |
|---------|------------|
| Private key in memory | Never in app memory (hardware signing) |
| Access token in memory | Short-lived; cleared after proof generation |
| Proof JWT in memory | Cleared after request is sent |
| Nonce in memory | In-memory store; cleared on logout |
| JWS signing input in memory | Ephemeral; exists only during proof construction |

The SDK does NOT provide explicit memory-zeroing beyond what the platform provides. This is a defense-in-depth measure that is difficult to guarantee in managed languages (Kotlin/Swift/JS). The primary protection is hardware isolation of the private key.

## Secure Storage Persistence

| Platform | Where key reference is stored | Where private key lives |
|----------|------------------------------|------------------------|
| iOS | Keychain (app-scoped) | Secure Enclave (hardware) |
| Android | App's SharedPreferences / DataStore | AndroidKeyStore (TEE/StrongBox) |
| Web | IndexedDB (origin-scoped) | Browser crypto store (software, non-extractable) |
| CLI | OS keychain | OS keychain (software) |

## Observability and Evidence

Normal SDK operation does NOT log:
- Private key bytes (never accessible)
- Access or refresh tokens
- Full DPoP proofs
- Raw `jti` values
- Nonce values
- Biometric data

SDK operation MAY log (bounded, low-cardinality):
- Result categories: `proof_generated`, `nonce_challenged`, `attestation_failed`
- Error categories: `key_generation_failed`, `signing_error` (no sensitive payloads)
- Public-key thumbprint (only if explicitly enabled for correlation)
- Timing: bootstrap duration, proof generation duration (no payload data)

An explicitly configured security-evidence sink may carry the public-key thumbprint for provenance/audit. Increasing log verbosity does not enable this evidence path.

## Failure Categories

> Note: the canonical error taxonomy is docs/API_CONTRACT.md §1.5. This section is consistent with it (including `StorageError`); prefer §1.5 as the single source of truth for new code.

```text
KeyGenerationError
  - secureHardwareUnavailable
  - algorithmUnsupported
  - userCancelledAuthentication
  - hardwareFailure

SigningError
  - keyLocked (biometric auth required, not provided)
  - hardwareFailure
  - keyNotFound

ProofError
  - invalidTarget (malformed URL)
  - nonceRequired
  - clockSkewExceeded
  - invalidAccessToken

AttestationError
  - providerUnavailable
  - verdictDenied
  - integrityCompromised
  - versionMismatch

StorageError
  - keychainFull
  - keychainLocked
  - storageCorrupted
```

External SDK surfaces map these to platform-idiomatic error types without leaking sensitive details.

## Platform-Specific Security Notes

### iOS

- Secure Enclave keys are created with `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave`.
- `SecureEnclave.P256.Signing.PrivateKey` is the preferred CryptoKit API.
- For biometric-gated signing, attach `SecAccessControl` with `userPresence` or `biometryCurrentSet`.
- Keys persist across app launches; tied to the device, not the app (unless `kSecAttrAccessGroup` is scoped).
- Keychain items can be configured to require device passcode.
- Face ID / Touch ID authentication is enforced by the Secure Enclave itself — the app cannot bypass it.
- Keychain access control: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` ensures keys don't migrate to other devices.

### Android

- Use `KeyGenAlgorithmSpec` with `setIsStrongBoxBacked(true)` on Android 9+.
- Without StrongBox, TEE-backed key generation is the fallback.
- `setUserAuthenticationRequired(true)` binds signing to biometric/PIN auth; `setUserAuthenticationValiditySeconds` controls the timeout.
- `setAttestationChallenge()` enables key attestation — the certificate chain can be verified by the Digitalis backend.
- AndroidKeyStore keys are app-scoped by default (UID-bound).
- `BiometricPrompt` is the recommended UI for user authentication.
- Android 11+ provides `setUnlockedDeviceRequired(true)` to require the device to be unlocked.

### Web

- `crypto.subtle.generateKey({extractable: false})` prevents `exportKey`.
- Keys live in the browser's secure storage, scoped to the origin.
- No hardware guarantee — security is browser-dependent.
- Non-extractable CryptoKey objects cannot be serialized or read by application code.
- Consider using `SubtleCrypto` in a Service Worker for additional isolation.
- The Web adapter does NOT support attestation — no web attestation equivalent for DPoP.

## Supply-Chain Posture

- No custom cryptography. Standard platform APIs only (CryptoKit, AndroidKeyStore, WebCrypto).
- Dependencies audited before any release build.
- Lockfile / dependency resolution committed.
- No unreviewed install scripts.

## Release Security Gates

A production-ready release requires:

1. All in-scope `KXM-*` requirements implemented and covered.
2. Proof JWTs verify against `keylix-dpop` conformance vectors.
3. Platform-specific roundtrip tests pass (key gen → JWK → thumbprint → proof → verify).
4. Negative tests for: malformed URL, wrong `ath`, stale `iat`, missing nonce, hardware unavailable.
5. Attestation integration tests (if attestation is enabled for the build).
6. No key material leakage in logs / crash reports.
7. Dependency audit clean or documented exceptions.
