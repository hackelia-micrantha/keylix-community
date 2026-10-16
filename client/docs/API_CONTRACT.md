# API Contract

**Status:** design phase — initial baseline.

This document defines Keylix Client's public API contract across all platforms. Every SDK MUST implement these types and functions with the semantics described here. Where platform idioms differ, the semantics take precedence over exact naming.

---

## 1. Core Types

### 1.1 BootstrapConfig

The initial configuration for SDK bootstrap.

```kotlin
// Kotlin (KMP expect)
data class BootstrapConfig(
    val attestationRequired: Boolean = false,
    val attestationBackendUrl: String? = null,
    val attestationProjectId: String? = null,
    val keyAlias: String = "dpop-proof-key",
    val clock: Clock? = null,            // injected for testing; null → system clock
    val rng: SecureRandom? = null        // injected for testing; null → platform CSPRNG
)
```

```swift
// Swift
struct BootstrapConfig {
    var attestationRequired: Bool = false
    var attestationBackendURL: String? = nil
    var attestationProjectId: String? = nil
    var keyAlias: String = "dpop-proof-key"
}
```

```typescript
// TypeScript
interface BootstrapConfig {
  attestationRequired?: boolean;        // default false
  attestationBackendUrl?: string;
  attestationProjectId?: string;
  keyAlias?: string;                    // default "dpop-proof-key"
}
```

### 1.2 BootstrapResult

The outcome of a bootstrap attempt.

```kotlin
// Kotlin
sealed interface BootstrapResult {
    data class Success(
        val client: KeylixClient,
        val keyThumbprint: JwkThumbprint,
        val hardwareBacked: Boolean,
        val attestationVerdict: AttestationVerdict? = null
    ) : BootstrapResult

    data class HardwareUnavailable(
        val message: String,
        val platform: String
    ) : BootstrapResult

    data class Failure(val error: KeylixError) : BootstrapResult
}

sealed interface AttestationVerdict {
    data object Allow : AttestationVerdict
    data object Deny : AttestationVerdict
    data object Degraded : AttestationVerdict
}
```

```swift
// Swift
enum BootstrapResult {
    case success(client: KeylixClient, keyThumbprint: JwkThumbprint, hardwareBacked: Bool, attestationVerdict: AttestationVerdict?)
    case hardwareUnavailable(message: String, platform: String)
    case failure(error: KeylixError)
}

enum AttestationVerdict {
    case allow
    case deny
    case degraded
}
```

```typescript
// TypeScript
type BootstrapResult =
  | { kind: "success"; client: KeylixClient; keyThumbprint: JwkThumbprint; hardwareBacked: boolean; attestationVerdict?: AttestationVerdict }
  | { kind: "hardwareUnavailable"; message: string; platform: string }
  | { kind: "failure"; error: KeylixError };

type AttestationVerdict = "allow" | "deny" | "degraded";
```

### 1.3 ProofRequest

The input to `createProof`.

```kotlin
// Kotlin
data class ProofRequest(
    val method: String,             // HTTP method (GET, POST, etc.) — will be uppercased
    val url: String,                // full request URL
    val accessToken: String? = null, // access token for ath computation
    val nonce: String? = null,       // DPoP nonce from server
    val issuedAt: Instant? = null,   // override iat; null → Clock.now()
    val jti: String? = null          // override jti; null → CSPRNG
)
```

```swift
// Swift
struct ProofRequest {
    var method: String
    var url: String
    var accessToken: String? = nil
    var nonce: String? = nil
    var issuedAt: Date? = nil
    var jti: String? = nil
}
```

```typescript
// TypeScript
interface ProofRequest {
  method: string;
  url: string;
  accessToken?: string;
  nonce?: string;
  issuedAt?: Date;
  jti?: string;
}
```

### 1.4 ProofResult

The outcome of `createProof`.

```kotlin
// Kotlin
sealed interface ProofResult {
    data class Success(
        val proofJwt: String,          // the DPoP header value
        val thumbprint: JwkThumbprint  // public-key thumbprint for correlation
    ) : ProofResult

    data class NonceRequired(
        val nonce: String,             // server-provided nonce
        val error: String              // OAuth error code (e.g. "use_dpop_nonce")
    ) : ProofResult

    data class Failure(val error: KeylixError) : ProofResult
}
```

```swift
// Swift
enum ProofResult {
    case success(proofJwt: String, thumbprint: JwkThumbprint)
    case nonceRequired(nonce: String, error: String)
    case failure(error: KeylixError)
}
```

```typescript
// TypeScript
type ProofResult =
  | { kind: "success"; proofJwt: string; thumbprint: JwkThumbprint }
  | { kind: "nonceRequired"; nonce: string; error: string }
  | { kind: "failure"; error: KeylixError };
```

### 1.5 KeylixError

The error type surfaced to callers. Structured internally, lossy at boundaries.

```kotlin
// Kotlin
sealed interface KeylixError {
    val message: String              // safe for logging/display

    data class KeyGeneration(
        val reason: KeyGenReason,
        override val message: String
    ) : KeylixError

    data class Signing(
        val reason: SigningReason,
        override val message: String
    ) : KeylixError

    data class Proof(
        val reason: ProofReason,
        override val message: String
    ) : KeylixError

    data class Attestation(
        val reason: AttestationReason,
        override val message: String
    ) : KeylixError

    data class Storage(
        val reason: StorageReason,
        override val message: String
    ) : KeylixError
}

enum class KeyGenReason {
    SECURE_HARDWARE_UNAVAILABLE,
    ALGORITHM_UNSUPPORTED,
    USER_CANCELLED,
    HARDWARE_FAILURE,
    BIOMETRIC_LOCKED
}

enum class SigningReason {
    KEY_LOCKED,
    HARDWARE_FAILURE,
    KEY_NOT_FOUND,
    USER_CANCELLED
}

enum class ProofReason {
    INVALID_TARGET,
    NONCE_REQUIRED,
    CLOCK_SKEW_EXCEEDED,
    INVALID_ACCESS_TOKEN
}

enum class AttestationReason {
    PROVIDER_UNAVAILABLE,
    VERDICT_DENIED,
    INTEGRITY_COMPROMISED,
    VERSION_MISMATCH,
    NETWORK_ERROR
}

enum class StorageReason {
    KEYCHAIN_FULL,
    KEYCHAIN_LOCKED,
    STORAGE_CORRUPTED
}
```

```swift
// Swift
enum KeylixError: Error {
    case keyGeneration(reason: KeyGenReason, message: String)
    case signing(reason: SigningReason, message: String)
    case proof(reason: ProofReason, message: String)
    case attestation(reason: AttestationReason, message: String)
    case storage(reason: StorageReason, message: String)
}

enum KeyGenReason {
    case secureHardwareUnavailable
    case algorithmUnsupported
    case userCancelled
    case hardwareFailure
    case biometricLocked
}

enum SigningReason {
    case keyLocked
    case hardwareFailure
    case keyNotFound
    case userCancelled
}

enum ProofReason {
    case invalidTarget
    case nonceRequired
    case clockSkewExceeded
    case invalidAccessToken
}

enum AttestationReason {
    case providerUnavailable
    case verdictDenied
    case integrityCompromised
    case versionMismatch
    case networkError
}

enum StorageReason {
    case keychainFull
    case keychainLocked
    case storageCorrupted
}
```

```typescript
// TypeScript
type KeylixError =
  | { type: "keyGeneration"; reason: KeyGenReason; message: string }
  | { type: "signing"; reason: SigningReason; message: string }
  | { type: "proof"; reason: ProofReason; message: string }
  | { type: "attestation"; reason: AttestationReason; message: string }
  | { type: "storage"; reason: StorageReason; message: string };

type KeyGenReason =
  | "secureHardwareUnavailable"
  | "algorithmUnsupported"
  | "userCancelled"
  | "hardwareFailure"
  | "biometricLocked";

type SigningReason =
  | "keyLocked"
  | "hardwareFailure"
  | "keyNotFound"
  | "userCancelled";

type ProofReason =
  | "invalidTarget"
  | "nonceRequired"
  | "clockSkewExceeded"
  | "invalidAccessToken";

type AttestationReason =
  | "providerUnavailable"
  | "verdictDenied"
  | "integrityCompromised"
  | "versionMismatch"
  | "networkError";

type StorageReason =
  | "keychainFull"
  | "keychainLocked"
  | "storageCorrupted";
```

### 1.6 JwkThumbprint

The RFC 7638 thumbprint of the DPoP proof key.

```kotlin
// Kotlin
@JvmInline
value class JwkThumbprint(val value: String)  // base64url SHA-256
```

```swift
// Swift
struct JwkThumbprint: RawRepresentable, Hashable {
    let rawValue: String  // base64url SHA-256
    init(_ rawValue: String) { self.rawValue = rawValue }
}
```

```typescript
// TypeScript
type JwkThumbprint = string;  // base64url SHA-256
```

### 1.7 Jwk

```kotlin
// Kotlin
data class Jwk(
    val kty: String,     // "EC"
    val crv: String,     // "P-256"
    val x: String,       // base64url encoded
    val y: String        // base64url encoded
)
```

```swift
// Swift
struct Jwk: Codable {
    let kty: String   // "EC"
    let crv: String   // "P-256"
    let x: String     // base64url
    let y: String     // base64url
}
```

```typescript
// TypeScript
interface Jwk {
  kty: "EC";
  crv: "P-256";
  x: string;  // base64url
  y: string;  // base64url
}
```

### 1.8 DpopChallenge

Input to `handleNonceChallenge`.

```kotlin
// Kotlin
data class DpopChallenge(
    val nonce: String,
    val error: String,
    val originalRequest: ProofRequest
)
```

```swift
// Swift
struct DpopChallenge {
    var nonce: String
    var error: String
    var originalRequest: ProofRequest
}
```

```typescript
// TypeScript
interface DpopChallenge {
  nonce: string;
  error: string;
  originalRequest: ProofRequest;
}
```

---

## 2. KeylixClient Interface

The primary application-facing interface.

```kotlin
// Kotlin (KMP expect)
interface KeylixClient {
    /**
     * Generate a DPoP proof JWT for the given HTTP request.
     * Returns Success with the proof JWT, NonceRequired if the server
     * needs a fresh nonce, or Failure on error.
     */
    suspend fun createProof(request: ProofRequest): ProofResult

    /**
     * Handle a DPoP nonce challenge. Stores the nonce and generates
     * a fresh proof for retry.
     */
    suspend fun handleNonceChallenge(challenge: DpopChallenge): ProofResult

    /**
     * Get the RFC 7638 thumbprint of the current proof key.
     * This is the value that should match the token's cnf.jkt.
     */
    fun getKeyThumbprint(): JwkThumbprint

    /**
     * Whether the proof key is backed by secure hardware.
     * False for software fallback or WebCrypto.
     */
    fun isHardwareBacked(): Boolean

    /**
     * Get the public JWK of the proof key.
     * Safe to share — it is the public key.
     */
    fun getPublicKeyJwk(): Jwk

    /**
     * The current AS DPoP nonce (null if not received yet).
     */
    fun getAsNonce(): String?

    /**
     * The current RS DPoP nonce (null if not received yet).
     */
    fun getRsNonce(): String?

    /**
     * Clear stored nonces (e.g., on logout).
     */
    fun clearNonces()
}
```

```swift
// Swift
protocol KeylixClient {
    func createProof(request: ProofRequest) async throws -> ProofResult
    func handleNonceChallenge(challenge: DpopChallenge) async throws -> ProofResult
    func getKeyThumbprint() -> JwkThumbprint
    func isHardwareBacked() -> Bool
    func getPublicKeyJwk() -> Jwk
    func getAsNonce() -> String?
    func getRsNonce() -> String?
    func clearNonces()
}
```

```typescript
// TypeScript
interface KeylixClient {
  createProof(request: ProofRequest): Promise<ProofResult>;
  handleNonceChallenge(challenge: DpopChallenge): Promise<ProofResult>;
  getKeyThumbprint(): JwkThumbprint;
  isHardwareBacked(): boolean;
  getPublicKeyJwk(): Jwk;
  getAsNonce(): string | null;
  getRsNonce(): string | null;
  clearNonces(): void;
}
```

---

## 3. SecureSigner Interface (Internal)

The platform-specific signing-capability abstraction. Not exposed to application code.

```kotlin
// Kotlin (KMP expect)
internal interface SecureSigner {
    suspend fun generateKeyPair(alias: String): KeyReference
    suspend fun sign(keyRef: KeyReference, data: ByteArray): ByteArray  // raw R||S
    fun exportPublicKeyJwk(keyRef: KeyReference): Jwk
    fun deleteKey(keyRef: KeyReference): Boolean
    fun keyExists(alias: String): Boolean
}

data class KeyReference(val alias: String)
```

```swift
// Swift
internal protocol SecureSigner {
    func generateKeyPair(alias: String) async throws -> KeyReference
    func sign(keyRef: KeyReference, data: Data) async throws -> Data  // raw R||S
    func exportPublicKeyJwk(keyRef: KeyReference) throws -> Jwk
    func deleteKey(keyRef: KeyReference) throws -> Bool
    func keyExists(alias: String) -> Bool
}

struct KeyReference {
    let alias: String
}
```

```typescript
// TypeScript
internal interface SecureSigner {
  generateKeyPair(alias: string): Promise<KeyReference>;
  sign(keyRef: KeyReference, data: Uint8Array): Promise<Uint8Array>;  // raw R||S
  exportPublicKeyJwk(keyRef: KeyReference): Promise<Jwk>;
  deleteKey(keyRef: KeyReference): Promise<boolean>;
  keyExists(alias: string): boolean;
}

interface KeyReference {
  alias: string;
}
```

---

## 4. Proof Builder Specification

The proof builder constructs the DPoP proof JWT. Its behavior is normative:

```
Input: ProofRequest { method, url, accessToken?, nonce?, issuedAt?, jti? }
Output: compact JWS string

Algorithm:
  1. Validate URL is absolute with http/https scheme
  2. Normalize URL:
     a. Parse as URI
     b. Strip query and fragment
     c. Lowercase scheme and host
     d. Strip default ports (80 for http, 443 for https)
     e. Re-encode path with RFC 3986 normalization
  3. Generate jti:
     a. If request.jti provided, use it (testing override)
     b. Otherwise, generate UUID v4 or 16 random bytes as base64url
  4. Determine iat:
     a. If request.issuedAt provided, use it
     b. Otherwise, use Clock.now().epochSeconds
  5. Compute ath (if accessToken provided):
     ath = base64url(sha256(accessToken))
  6. Get public JWK from SecureSigner.exportPublicKeyJwk(keyRef)
  7. Construct header:
     { "typ": "dpop+jwt", "alg": "ES256", "jwk": { kty, crv, x, y } }
  8. Construct payload:
     {
       "jti": jti,
       "htm": method.uppercase(),
       "htu": normalizedUrl,
       "iat": iat,
       "nonce": nonce (if provided),
       "ath": ath (if accessToken provided)
     }
  9. Encode header and payload as base64url
  10. Construct signing input: header_b64url || "." || payload_b64url
  11. Sign: signature = SecureSigner.sign(keyRef, signing_input)
  12. Output: signing_input || "." || base64url(signature)

Proof JWT wire format:
  eyJ0eXAiOiJkK2F3IiwiYWxnIjoiRVMyNTYiLCJqa3QiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOi4uLiIsInkiOi4uLiJ9Cg.
  eyJqdGkiOi4uLiIsImh0bSI6IkdFVCIsImh0dSI6Imh0dHBzOi8vYXBpLmV4YW1wbGUuY29tL3Jlc291cmNlIiwiaWF0IjoxNzIzLCJhdGgiOi4uLiJ9Cg.
  SXQgdGhlbiBnZXRzIHNpZ25hdHVyZSBoZXJl...
```

### 4.1 URL Normalization Rules

| Input URL | Normalized `htu` |
|-----------|-------------------|
| `https://api.example.com/resource` | `https://api.example.com/resource` |
| `https://api.example.com/resource?foo=bar` | `https://api.example.com/resource` |
| `https://api.example.com/resource#fragment` | `https://api.example.com/resource` |
| `HTTPS://API.EXAMPLE.COM/resource` | `https://api.example.com/resource` |
| `https://api.example.com:443/resource` | `https://api.example.com/resource` |
| `https://api.example.com/%7Euser` | `https://api.example.com/~user` |

### 4.2 JWK Header Embedding

The DPoP proof header includes the full public JWK per RFC 9449 Section 4.2. This is REQUIRED (not optional) in our profile. The server extracts the proof key from the header JWK.

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "base64url-encoded x coordinate (32 bytes)",
    "y": "base64url-encoded y coordinate (32 bytes)"
  }
}
```

### 4.3 Payload Claim Details

| Claim | Type | Required | Source |
|-------|------|----------|--------|
| `jti` | string | YES | CSPRNG (UUID v4 or 16 random bytes base64url) |
| `htm` | string | YES | request.method.uppercase() |
| `htu` | string | YES | normalized URL per Section 4.1 |
| `iat` | integer | YES | Clock.now().epochSeconds (seconds since Unix epoch) |
| `nonce` | string | NO | server DPoP-Nonce value |
| `ath` | string | NO | base64url(sha256(access_token)) when access token present |

### 4.4 Signature Format

The ES256 signature MUST be the raw concatenation of the R and S integers, each 32 bytes, totaling 64 bytes. This is NOT DER-encoded.

```
signature_bytes = R (32 bytes, big-endian) || S (32 bytes, big-endian)
signature_b64url = base64url(signature_bytes)
```

Platform implementations that produce DER-encoded signatures (Android `SHA256withECDSA`, iOS `ecdsaSignatureMessageX962SHA256`) MUST convert to raw R||S format.

---

## 5. Token Binding Specification

### 5.1 Token Request Decoration

When making a token request (authorization code exchange or refresh):

```
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: <proofJwt>

grant_type=authorization_code
&code=...
&redirect_uri=...
&code_verifier=...
&client_id=...
```

The DPoP proof for a token request:
- `htm` = "POST"
- `htu` = the token endpoint URL
- NO `ath` (no access token yet)
- `nonce` = the last AS nonce, if previously received

### 5.2 Resource Request Decoration

```
GET /resource HTTP/1.1
Host: api.example.com
Authorization: DPoP <accessToken>
DPoP: <proofJwt>
```

The DPoP proof for a resource request:
- `htm` = "GET"
- `htu` = the resource URL
- `ath` = base64url(sha256(accessToken)) — the EXACT token bytes from the Authorization header
- `nonce` = the last RS nonce, if previously received

### 5.3 `ath` Computation

```
ath = base64url_encode(sha256(access_token_bytes))
```

Where `access_token_bytes` is the UTF-8 encoding of the access token string. The SDK computes `ath` internally — callers MUST NOT pre-compute it.

---

## 6. Nonce Handling Specification

### 6.1 Receiving a Nonce

When the server responds with a DPoP-Nonce:

```
HTTP/1.1 400 Bad Request
DPoP-Nonce: server-provided-nonce-value
WWW-Authenticate: DPoP error="use_dpop_nonce"
```

The SDK stores the nonce per-scope:

```kotlin
// AS nonce
NonceStore.setNonce(nonce = "server-provided-nonce", scope = ServerRole.AUTHORIZATION_SERVER, serverUrl = "https://as.example.com")

// RS nonce
NonceStore.setNonce(nonce = "server-provided-nonce", scope = ServerRole.RESOURCE_SERVER, serverUrl = "https://api.example.com")
```

### 6.2 Using a Nonce

On the next request to the same server, the SDK includes the stored nonce in the proof:

```json
{
  "jti": "fresh-jti",
  "htm": "POST",
  "htu": "https://as.example.com/token",
  "iat": 1234567890,
  "nonce": "server-provided-nonce"
}
```

### 6.3 Nonce Rotation

If the server provides a new nonce in a successful response, the SDK replaces the stored nonce. The old nonce is no longer valid.

### 6.4 Nonce Expiry

Nonces do not have a built-in TTL in the SDK. They are replaced when the server rotates them or cleared on logout. If the server rejects a proof with a stale nonce, it will respond with a new nonce challenge, which the SDK handles by replacing the stored nonce.

### 6.5 Nonce Isolation

```text
NonceStore
  ├── as: Map<serverUrl, nonce>     // authorization server nonces
  └── rs: Map<serverUrl, nonce>     // resource server nonces
```

AS and RS nonces are ALWAYS separate. A nonce received from the AS is never sent to the RS and vice versa.

---

## 7. Error Handling Contract

### 7.1 Error Propagation Rules

1. Internal errors are structured (typed, with reason codes).
2. External errors are lossy — no sensitive data in messages.
3. No private key bytes in any error message, log, or crash report.
4. No access tokens in error messages.
5. No raw `jti` or nonce values in error messages (only in debug-level traces).

### 7.2 Platform-Idiomatic Error Mapping

| Internal Error | Kotlin | Swift | TypeScript |
|---------------|--------|-------|------------|
| `KeyGeneration(SECURE_HARDWARE_UNAVAILABLE)` | `KeylixError.KeyGeneration(...)` | `KeylixError.keyGeneration(...)` | `{ type: "keyGeneration", reason: "secureHardwareUnavailable" }` |
| `Signing(KEY_LOCKED)` | `KeylixError.Signing(...)` | `KeylixError.signing(...)` | `{ type: "signing", reason: "keyLocked" }` |
| `Proof(INVALID_TARGET)` | `KeylixError.Proof(...)` | `KeylixError.proof(...)` | `{ type: "proof", reason: "invalidTarget" }` |
| `Attestation(VERDICT_DENIED)` | `KeylixError.Attestation(...)` | `KeylixError.attestation(...)` | `{ type: "attestation", reason: "verdictDenied" }` |
| `Storage(KEYCHAIN_LOCKED)` | `KeylixError.Storage(...)` | `KeylixError.storage(...)` | `{ type: "storage", reason: "keychainLocked" }` |

---

## 8. Testing Contract

Every SDK implementation MUST provide:

1. **Conformance tests** using shared JSON vectors from `tests/consumed/`.
2. **Unit tests** for every public API method.
3. **Roundtrip tests**: key gen → JWK → proof → verify against `keylix-dpop`.
4. **Negative tests** for every error variant.
5. **Platform-specific integration tests** (actual key generation and signing on device/emulator).
6. **Nonce flow tests**: challenge → store → retry → success.
