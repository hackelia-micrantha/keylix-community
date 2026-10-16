# Architecture

> **Keylix Client scope.** Covers the mobile/desktop SDK only — per-platform secure storage, ports/adapters, and client-side data flows. The canonical protocol-level architecture lives in the public [`keylix-community`](https://github.com/hackelia-micrantha/keylix-community) repository: [docs/ARCHITECTURE.md](https://github.com/hackelia-micrantha/keylix-community/blob/main/docs/ARCHITECTURE.md). On any conflict, the public canonical source governs.

**Status:** design phase — initial baseline.

This document defines Keylix Client's layering, ports, per-platform mapping, and the Rust cross-compilation path. It mirrors the structure of [Keylix's architecture](https://github.com/hackelia-micrantha/keylix-community/blob/main/docs/ARCHITECTURE.md) adapted for mobile and client-side.

See also: [Design baseline](DESIGN.md), [Threat model](THREAT_MODEL.md), [Security](SECURITY.md), [Requirements](REQUIREMENTS.md), [Protocol flows](PROTOCOL_FLOWS.md), [API contract](API_CONTRACT.md), [ADRs](adr/README.md).

## System Boundary

Keylix Client owns **mobile-side DPoP proof generation and token-binding lifecycle** with platform-native secure storage.

It does not own token issuance, OAuth flow framework, policy engine, authorization decisions, identity, or audit retention.

```text
Mobile Application (Kotlin / Swift / TS)
      |
      | DPoP-bound API calls (access token + proof)
      v
+-----------------------------------+
| Keylix Client                     |
| proof generation / token binding  |
| nonce handling / key lifecycle    |
| attestation integration point     |
+-----------------------------------+
      |
      | signing capability (non-extractable)
      v
+-----------------------------------+
| Platform Secure Storage           |
| Secure Enclave / StrongBox /     |
| WebCrypto / Keychain              |
+-----------------------------------+
      |
      | optional attestation
      v
+-----------------------------------+
| Digitalis Attestation Backend     |
+-----------------------------------+
```

## Dependency Rule

Dependencies point inward. The public API depends on the core. The core depends on the secure-storage port. Platform implementations depend on the port. No layer reaches sideways to another platform.

```text
                      +------------------+
                      | Public Client API|
                      +--------+---------+
                               |
                               v
                      +------------------+
                      | Core (KMP expect |
                      | / Rust FFI / TS) |
                      +--+------+------+-+
                         |      |      |
              +----------+      |      +----------+
              |                 |                 |
              v                 v                 v
   +--------------+   +----------------+   +-------------+
   | SecureStore  |   | Proof/Nonce    |   | Attestation |
   | Port         |   | Builder        |   | Port        |
   +------+-------+   +----------------+   +------+----------+
          |                                       |
          v                                       v
   Platform impls                          Digitalis backend
   (iOS/Android/Web/CLI)
```

## Internal Module Dependency Map

```text
                  +-----------------+
                  |  KeylixClient   |  (public API, per-platform)
                  +-------+---------+
                          |
                          v
                  +-----------------+
                  |  CoreModule     |  (shared logic)
                  |  ProofBuilder   |
                  |  NonceStore     |
                  |  TokenBinding   |
                  |  Thumbprint     |
                  +--+------+------+
                     |      |
          +----------+      +-----------+
          |                               |
          v                               v
   +--------------+              +----------------+
   | SecureSigner |              |    Internal    |
   | (port)       |              |    JwsCodec    |
   +------+-------+              |    JwkCodec    |
          |                      |    Errors      |
          v                      +----------------+
   +------------------+
   | Platform Signer  |  (per-target actual)
   +------------------+
```

## Data Flow Diagram

### Proof Generation (per-request)

```text
                        Application Code
                               |
                               | ProofRequest(method, url, accessToken, nonce)
                               v
                    +---------------------+
                    |  KeylixClient       |
                    |  .createProof()     |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    |  ProofBuilder       |
                    |                     |
                    |  1. validate URL    |
                    |  2. normalize htu   |
                    |  3. generate jti    |
                    |  4. compute iat     |
                    |  5. compute ath     |<--- accessToken
                    |  6. build header    |
                    |  7. build payload   |
                    |  8. encode + join   |
                    +----------+----------+
                               |
                               | JWS Signing Input (header.payload)
                               v
                    +---------------------+
                    |  SecureSigner.port  |
                    |  .sign(keyRef, data)|
                    +----------+----------+
                               |
                               | data to sign
                               v
                    +---------------------+
                    |  Platform Signer    |
                    |  (hardware/soft)    |
                    +----------+----------+
                               |
                               | raw R||S (64 bytes)
                               v
                    +---------------------+
                    |  ProofBuilder       |
                    |  .assemble()        |
                    |  header.payload.sig |
                    +----------+----------+
                               |
                               | proofJwt: String
                               v
                    +---------------------+
                    |  ProofResult.       |
                    |  Success(proofJwt)  |
                    +---------------------+
```

### Bootstrap (one-time setup)

```text
                        Application Code
                               |
                               | bootstrap(BootstrapConfig)
                               v
                    +---------------------+
                    |  KeylixClient       |
                    |  .bootstrap()       |
                    +----------+----------+
                               |
                    +----------+----------+
                    |                     |
                     |
                     v
            +----------------+
            | SecureSigner   |
            | .generateKey() |  ← DPoP key generated FIRST
            +-------+--------+
                    |
                    v
            +----------------+
            | Export public  |
            | key + compute  |
            | thumbprint     |
            +-------+--------+
                    |
         +----------+----------+
         |                     |
         v                     v
   +----------------+   +-----------------+
   | Attestation    |   |  No Attestation |
   | Required?      |   |  → TRUSTED_ACTIVE|
   +-------+--------+   +--------+--------+
               |                  |
               v                  |
      +-------------+             |
      | Digitalis   |             |
      | Attestation |             |
      | 1. get nonce|             |
      | 2. attest   |             |
      | 3. submit   |             |
      | 4. get      |             |
      |    verdict  |             |
      +---+---------+             |
          |                       |
     ALLOW|                  DENY |
          v                       v
   +-------------+       +---------+----------+
   |TRUSTED_     |       | deleteKey(alias)   |
   |ACTIVE       |       | Return FAILURE     |
   +-------------+       +--------------------+
```

## State Machines

### Bootstrap State Machine

(See [PROTOCOL_FLOWS.md §7](PROTOCOL_FLOWS.md) for the full diagram.)

States: `UNINITIALIZED` → `BOOTSTRAPPING` → `KEY_GENERATION` → `ATTESTING` → `VERIFYING` → `TRUSTED_ACTIVE`

Side states: `HARDWARE_UNAVAILABLE` → `DEGRADED_KEY` or `BOOT_FAILED`, `DENIED`

### Proof Generation State Machine

(See [PROTOCOL_FLOWS.md §8](PROTOCOL_FLOWS.md) for the full diagram.)

States: `IDLE` → `BUILDING` → `SIGNING` → `SERIALIZED` → `IDLE` (or `FAILED`)

### Nonce State

```text
NonceStore
  ├── as: Map<serverUrl, String>    // authorization server nonces
  └── rs: Map<serverUrl, String>    // resource server nonces
```

Operations:
- `setNonce(nonce, scope, serverUrl)` — stores nonce, replacing any previous value for that scope+server
- `getNonce(scope, serverUrl)` — returns current nonce or null
- `clearAll()` — clears all nonces (logout)
- `clear(scope, serverUrl)` — clears specific nonce

### Key State

```text
KeyStore (in-memory after bootstrap)
  ├── keyRef: KeyReference          // alias/handle to platform key
  ├── thumbprint: JwkThumbprint     // RFC 7638
  ├── hardwareBacked: Boolean
  └── createdAt: Long               // epoch millis
```

The `KeyReference` is NOT the private key material. It is an opaque handle (an alias string on iOS/Android, a CryptoKey reference on Web).

## Ports and Adapters

### Public Client API

The public client API is the application-facing surface. It is intentionally small. (See [API_CONTRACT.md](API_CONTRACT.md) for full type signatures.)

```kotlin
// Kotlin-pseudocode; shape mirrored across all platforms

interface KeylixClient {
    suspend fun createProof(request: ProofRequest): ProofResult
    suspend fun handleNonceChallenge(challenge: DpopChallenge): ProofResult
    fun getKeyThumbprint(): JwkThumbprint
    fun isHardwareBacked(): Boolean
    fun getPublicKeyJwk(): Jwk
    fun getAsNonce(): String?
    fun getRsNonce(): String?
    fun clearNonces()
}
```

### Core Layer Ports

| Port | Responsibility | Dependencies |
|------|---------------|--------------|
| `SecureSigner` | Exposes ES256 signing capability and public JWK | Platform keystore |
| `ProofIdGenerator` | Fresh `jti` via CSPRNG | Platform CSPRNG |
| `NonceStore` | Stores AS/RS nonces separately | In-memory or persistent storage |
| `Clock` | Injectable clock for `iat` | System clock (default) |
| `AttestationProvider` | Optional platform attestation | Digitalis backend |
| `TokenStore` | Stores DPoP-bound tokens and key refs | App storage |

### Secure Storage Port (Detailed)

```kotlin
// KMP expect / actual contract

/**
 * Platform-specific signing-capability abstraction.
 *
 * Non-negotiable contract:
 *   1. Private key bytes MUST NEVER be accessible through this interface.
 *   2. Signing returns raw R||S (64 bytes), NOT DER-encoded.
 *   3. Public key export returns a valid RFC 7517 JWK.
 */
internal interface SecureSigner {
    /** Generate a new P-256 key pair in secure hardware. Returns a key reference. */
    suspend fun generateKeyPair(alias: String): KeyReference

    /** Sign data (JWS signing input) using the referenced key. Returns raw R||S. */
    suspend fun sign(keyRef: KeyReference, data: ByteArray): ByteArray

    /** Export the public key as an RFC 7517 JWK object. */
    fun exportPublicKeyJwk(keyRef: KeyReference): Jwk

    /** Delete the key from secure storage. */
    fun deleteKey(keyRef: KeyReference): Boolean

    /** Check if a key exists for the given alias. */
    fun keyExists(alias: String): Boolean
}

data class KeyReference(val alias: String)
data class Jwk(val kty: String, val crv: String, val x: String, val y: String)
```

## Per-Platform SDK Structure

### Android (Kotlin, Native)

```
sdks/android/
  libkeylix/
    src/main/kotlin/com/micrantha/keylix/
      KeylixClient.kt              # public entry point
      config/
        BootstrapConfig.kt
        KeylixClientConfig.kt
      proof/
        ProofBuilder.kt            # RFC 9449 proof construction
        ProofRequest.kt
        ProofResult.kt
      oauth/
        TokenBinding.kt            # token-request decoration + ath
        NonceStore.kt              # AS/RS nonce handling
      storage/
        SecureSigner.kt            # interface (mirrors KMP contract)
        AndroidKeyStoreSigner.kt   # AndroidKeyStore implementation
        SecureStorageManager.kt    # key lifecycle
      attestation/
        DigitalisAttestation.kt    # optional Digitalis bridge
        AttestationResult.kt
      model/
        Jwk.kt
        JwkThumbprint.kt
        KeyReference.kt
        KeylixError.kt
      internal/
        JwsCodec.kt                # compact JWS serialization
        JwkCodec.kt                # JWK JSON handling
        Thumbprint.kt              # RFC 7638
    src/test/kotlin/
      ...                          # unit + roundtrip tests
    src/androidTest/kotlin/
      ...                          # instrumentation tests (key gen, signing)
  build.gradle.kts
  README.md
```

### iOS (Swift)

```
sdks/ios/
  Sources/Keylix/
    KeylixClient.swift             # public entry point
    Config/
      BootstrapConfig.swift
      KeylixClientConfig.swift
    Proof/
      ProofBuilder.swift           # RFC 9449 proof construction
      ProofRequest.swift
      ProofResult.swift
    OAuth/
      TokenBinding.swift           # token-request decoration + ath
      NonceStore.swift             # AS/RS nonce handling
    Storage/
      SecureSigner.swift           # protocol (mirrors KMP contract)
      SecureEnclaveSigner.swift    # Secure Enclave implementation
      SecureStorageManager.swift   # key lifecycle
    Attestation/
      DigitalisAttestation.swift   # optional Digitalis bridge
      AttestationResult.swift
    Model/
      Jwk.swift
      JwkThumbprint.swift
      KeyReference.swift
      KeylixError.swift
    Internal/
      JwsCodec.swift               # compact JWS serialization
      JwkCodec.swift               # JWK JSON handling
      Thumbprint.swift             # RFC 7638
  Tests/KeylixTests/
    ...                            # unit + roundtrip tests
  Package.swift
  README.md
```

### KMP (Kotlin Multiplatform)

```
sdks/kmp/
  src/
    commonMain/kotlin/com/micrantha/keylix/
      KeylixClient.kt              # shared public API
      SecureSigner.kt              # expect interface
      proof/
        ProofBuilder.kt            # shared proof construction
        ProofRequest.kt
        ProofResult.kt
      oauth/
        TokenBinding.kt            # shared token binding
        NonceStore.kt              # shared nonce handling
      model/
        Jwk.kt
        JwkThumbprint.kt
        KeyReference.kt
        KeylixError.kt
      internal/
        JwsCodec.kt
        JwkCodec.kt
        Thumbprint.kt
    androidMain/kotlin/com/micrantha/keylix/
      SecureSignerAndroid.kt       # actual → AndroidKeyStore
    iosMain/kotlin/com/micrantha/keylix/
      SecureSignerIos.kt           # actual → Secure Enclave (via cinterop or Swift bridge)
    commonTest/kotlin/
      ...                          # shared unit tests
    androidTest/kotlin/
      ...                          # Android-specific tests
    iosTest/kotlin/
      ...                          # iOS-specific tests
  build.gradle.kts
  README.md
```

### React Native (TypeScript + native)

```
sdks/react-native/
  src/
    index.ts                       # TypeScript public API
    KeylixClient.ts
    types.ts
    errors.ts
  android/
    src/main/java/com/micrantha/keylix/reactnative/
      KeylixModule.kt              # React Native bridge module
      KeylixPackage.kt
  ios/
    KeylixModule.swift             # React Native bridge module
    KeylixModuleBridge.m           # ObjC bridge
  __tests__/
    KeylixClient.test.ts           # JS unit tests (mock native)
  package.json
  tsconfig.json
  README.md
```

The React Native SDK delegates to the native platform SDKs via the bridge; it does not reimplement crypto.

## Platform Secure Storage Details

### iOS Secure Enclave Implementation

| Concern | Detail |
|---------|--------|
| Key generation | `SecureEnclave.P256.Signing.PrivateKey()` or `SecKeyCreateRandomKey` with `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave` |
| Non-extractable | Guaranteed by the Secure Enclave — the key material never enters application memory |
| Signing | `SecureEnclave.P256.Signing.PrivateKey.signature(for:)` or `SecKeyCreateSignature` |
| Public key export | `x963Representation` → split into `x` and `y` coordinates |
| Attestation | Apple App Attest (`DCAppAttestService`) integrated via Digitalis |
| Availability | iPhone 5s+ (Secure Enclave present on all modern iOS devices) |
| Signature format | DER-encoded → MUST convert to raw R||S (64 bytes) |
| Keychain persistence | Keys stored in Secure Enclave, NOT keychain; key reference stored in keychain |
| Biometric gating | `SecAccessControlCreateWithFlags` with `.biometryCurrentSet` or `.userPresence` |

### Android StrongBox Implementation

| Concern | Detail |
|---------|--------|
| Key generation | `KeyPairGenerator` with `KeyGenParameterSpec`, `setIsStrongBoxBacked(true)` where supported, else TEE fallback |
| Non-extractable | AndroidKeyStore provider blocks key export |
| Signing | `Signature.getInstance("SHA256withECDSA")` initialized with the AndroidKeyStore `PrivateKey` |
| Public key export | `ECPublicKey.getW()` → `x` and `y` coordinates |
| Attestation | `KeyGenParameterSpec.setAttestationChallenge()` → verify via Digitalis Google Play Integrity or Android key attestation certificate chain |
| Availability | TEE on Android 6.0+; StrongBox on Android 9.0+ (device-dependent) |
| Signature format | DER-encoded → MUST convert to raw R||S (64 bytes) |
| Biometric gating | `setUserAuthenticationRequired(true)`, `setUserAuthenticationValiditySeconds(0)` |

### Web Crypto Implementation

| Concern | Detail |
|---------|--------|
| Key generation | `crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign"])` with `extractable=false` |
| Non-extractable | Browser-enforced; `extractable=false` prevents `exportKey` |
| Signing | `crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, key, data)` |
| Public key export | `crypto.subtle.exportKey("jwk", key)` → JWK object |
| Availability | All modern browsers (Chrome 37+, Firefox 34+, Safari 11+) |
| Signature format | Raw R||S (WebCrypto outputs raw, not DER) |
| Storage | IndexedDB for key reference; CryptoKey is non-extractable |

### CLI / Desktop Implementation

| Concern | Detail |
|---------|--------|
| Key generation | OS keychain via `keyring` (Rust) or `keytar` (Node) or direct platform APIs |
| Signing | OS-specific cryptographic provider (macOS Security Framework, Windows NCrypt, Linux openssl/libselinux) |
| Availability | macOS Keychain, Windows Credential Manager, Linux libsecret |
| Signature format | Platform-dependent → convert to raw R||S if needed |

## Derinterop: Signature Format Conversion

Android and iOS both produce DER-encoded ECDSA signatures by default. The JOSE ES256 spec requires raw R||S (64 bytes). Every platform implementation MUST handle this conversion.

```
DER format:
  0x30 [total_len] 0x02 [r_len] [r_bytes] 0x02 [s_len] [s_bytes]

Raw format:
  [r_32_bytes] [s_32_bytes]   (64 bytes total)

Conversion algorithm:
  1. Parse DER structure
  2. Extract r and s as big-endian byte arrays
  3. If r or s has leading zero bytes for sign handling, strip them
  4. Pad r and s to exactly 32 bytes each (leading zeros)
  5. Concatenate: r || s → 64 bytes
```

## Concurrency Model

| Platform | Concurrency Pattern | Notes |
|----------|-------------------|-------|
| Kotlin (Android) | `suspend` functions + coroutines | Proof generation is suspend; signing runs on Dispatchers.IO |
| Kotlin (KMP) | `suspend` functions | Common API is `suspend`; platform impls dispatch appropriately |
| Swift | `async/await` | All SDK methods are `async` |
| TypeScript (RN) | `Promise`-based | Native bridge returns Promises |
| TypeScript (Web) | `Promise`-based | WebCrypto is async |
| Rust (FFI) | Blocking + callback | C-ABI functions are blocking; caller dispatches |

### Thread Safety

The SDK MUST be safe to call from any thread:
- `KeylixClient` is immutable after bootstrap (no mutable internal state).
- `NonceStore` uses platform-appropriate synchronization (e.g., `@volatile`/AtomicReference in Kotlin, `os_unfair_lock`/actor in Swift, `Mutex` in Rust).
- `SecureSigner` signing calls are serialized by the platform keystore (single key access is atomic).

## Error Recovery

| Error | Recovery |
|-------|----------|
| `KeyGenerationError.secureHardwareUnavailable` | Prompt user for software fallback consent |
| `SigningError.keyLocked` | Prompt user to authenticate (biometric/PIN); retry signing |
| `SigningError.hardwareFailure` | Retry once; if still failing, fail bootstrap |
| `ProofError.invalidTarget` | Fix the URL; this is an application bug |
| `ProofError.nonceRequired` | Call `handleNonceChallenge`; retry with new proof |
| `AttestationError.providerUnavailable` | Retry with backoff (max 3 attempts); then fail |
| `AttestationError.verdictDenied` | Fail closed; do not retry |

## Observability

The SDK emits bounded telemetry for operational monitoring. No sensitive data in telemetry.

| Event | When | Data |
|-------|------|------|
| `bootstrap_started` | Bootstrap begins | attestation_required, platform |
| `bootstrap_completed` | Bootstrap succeeds | hardware_backed, duration_ms |
| `bootstrap_failed` | Bootstrap fails | error_category (no sensitive data) |
| `proof_created` | Proof generated | hardware_backed, has_nonce, has_ath |
| `nonce_challenged` | Nonce challenge received | scope (AS/RS) |
| `attestation_submitted` | Attestation sent | provider (apple/google) |
| `attestation_verdict` | Verdict received | verdict (allow/deny/degraded) |

Telemetry is opt-in via configuration and never includes: tokens, proofs, nonces, private keys, JWK thumbprints (unless explicitly enabled for correlation).

## MCP Boundary

If a mobile app talks to an MCP server over HTTP, DPoP applies to the **HTTP request**, not the MCP JSON-RPC body. Keylix Client's `ProofRequest` produces the proof JWT that goes into the `DPoP` HTTP header. No DPoP claims enter the JSON-RPC layer.

## Future Mechanisms

Do not generalize the public API around a universal `SenderConstraint` trait until another mechanism (mTLS, workload identity, hardware attestation binding) has concrete mobile requirements. DPoP first.
