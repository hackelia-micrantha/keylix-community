# Threat Model

> **Keylix Client scope.** Covers the mobile/desktop SDK threat surface (secure hardware, attestation, client-side key handling) only. The canonical protocol-level threat model lives in the public [`keylix-community`](https://github.com/hackelia-micrantha/keylix-community) repository: [docs/THREAT_MODEL.md](https://github.com/hackelia-micrantha/keylix-community/blob/main/docs/THREAT_MODEL.md). On any conflict, the public canonical source governs.

**Status:** design phase — initial baseline.

This document defines Keylix Client's threat model. It extends the [Keylix threat model](https://github.com/hackelia-micrantha/keylix-community/blob/main/docs/THREAT_MODEL.md) with mobile-specific attack surfaces.

## Attacker Model

Assume an attacker can:

- Steal an OAuth access token without the DPoP proof key (e.g., via log leakage, browser history, proxy interception, clipboard sniffing)
- Replay a captured DPoP proof on a different request or after the allowed lifetime
- Install a malicious app on the same device attempting to access the DPoP key (Android, unless StrongBox isolation)
- Run the app on a rooted / jailbroken device
- Intercept and modify network traffic if TLS is broken (custom CA, proxy tool, network-level MitM)
- Reverse-engineer the app binary to extract hardcoded secrets
- Inject code into the app process (Frida, Xposed, Cycript, Substrate)
- Spoof attestation signals if the platform's integrity checks are bypassed
- Access app backups (iTunes, ADB backup) containing keychain/keystore entries

DPoP does **not** defend against a fully compromised device where the attacker controls the app process AND can invoke the legitimate signing capability. This is a fundamental platform limitation: if the legitimate app can sign, an attacker controlling that app can also sign.

## Attack Tree: DPoP Key Extraction

```text
Goal: Obtain DPoP proof private key
│
├─── [1] Software Key Extraction
│    ├─── [1a] Memory dump (process injection, debugger)
│    │    └─── MITIGATED: Key never in app memory (hardware signing)
│    │         FALLBACK RISK: Software fallback mode → key in memory
│    │
│    ├─── [1b] Keychain/keystore extraction (rooted device)
│    │    └─── MITIGATED: Hardware-backed keys resist OS-level extraction
│    │         StrongBox: Dedicated hardware; key not extractable even from TEE
│    │         Secure Enclave: Key material never in OS-visible memory
│    │
│    └─── [1c] Backup extraction (iTunes, ADB)
│         └─── MITIGATED: kSecAttrAccessibleWhenUnlockedThisDeviceOnly (iOS)
│              AndroidKeyStore keys are NOT included in ADB backups
│
├─── [2] Hardware Key Extraction
│    ├─── [2a] Side-channel attack (power analysis, EM)
│    │    └─── OUT OF SCOPE: Requires physical access + lab equipment
│    │
│    ├─── [2b] Fault injection (voltage/clock glitching)
│    │    └─── OUT OF SCOPE: Requires physical access + hardware tampering
│    │
│    └─── [2c] Hardware vulnerability exploitation
│         └─── MITIGATED: Platform security updates
│              RESPONSIBILITY: Apple/Google via security patches
│
└─── [3] Key Substitution
     ├─── [3a] Generate new key pair, substitute in OAuth session
     │    └─── MITIGATED: Token binding (cnf.jkt check on server)
     │         Server rejects tokens with mismatched key thumbprint
     │
     └─── [3b] Replace public key in JWK header
          └─── MITIGATED: JWK is inside the signed JWS header
               Changing JWK invalidates the signature
```

## Attack Tree: Proof Replay

```text
Goal: Reuse a captured DPoP proof
│
├─── [1] Same request replay
│    └─── MITIGATED: Server-side replay store (jti uniqueness)
│         Keylix/RS tracks accepted jti values
│
├─── [2] Cross-endpoint replay
│    ├─── [2a] Same method, different URL
│    │    └─── MITIGATED: htu binding (proof tied to exact URL)
│    │
│    └─── [2b] Different method, same URL
│         └─── MITIGATED: htm binding (proof tied to HTTP method)
│
├─── [3] Delayed replay (after request completes)
│    └─── MITIGATED: jti uniqueness + server replay store
│         Even delayed, the same jti is rejected
│
├─── [4] Token substitution (proof + different token)
│    └─── MITIGATED: ath binding (proof tied to token SHA-256)
│         Changing the token invalidates the ath check
│
└─── [5] Cross-session replay
     └─── MITIGATED: iat freshness window (300s default)
         Old proofs are rejected even if replay store is cleared
```

## Attack Tree: Client Impersonation

```text
Goal: Impersonate a legitimate mobile client
│
├─── [1] Clone app with same client_id
│    ├─── [1a] Public client (no secret)
│    │    └─── MITIGATED: DPoP key IS the client credential
│    │         Attacker needs the proof key, which is hardware-bound
│    │         Attacker's app generates a different key → different thumbprint
│    │         Server sees cnf.jkt mismatch
│    │
│    └─── [1b] Dynamic client registration
│         └─── MITIGATED: Per-instance keys + attestation
│              Digitalis verifies app signing identity
│
├─── [2] Reverse-engineer app to extract client secret
│    └─── MITIGATED: No shared secrets in public clients (RFC 8252)
│         DPoP key pair is the only credential; generated per-device
│
├─── [3] Distribute modified APK/IPA with stolen key
│    ├─── [3a] On iOS
│    │    └─── MITIGATED: Secure Enclave keys are device-bound
│    │         Key extracted from device A cannot be used on device B
│    │         (Key material cannot be extracted at all)
│    │
│    └─── [3b] On Android
│         └─── MITIGATED: StrongBox keys are device-bound
│              TEE keys cannot be exported; StrongBox keys never leave hardware
│
└─── [4] Attestation bypass
     ├─── [4a] Spoof Apple App Attest
     │    └─── MITIGATED: Apple verifies assertion server-side
│    │         Digitalis backend validates with Apple servers
│    │         Nonce binding prevents replay
│    │
│    └─── [4b] Spoof Google Play Integrity
│         └─── MITIGATED: Google verifies integrity token server-side
│              Digitalis backend validates with Google APIs
```

## Attack Tree: Network Attacks

```text
Goal: Intercept or modify DPoP-bound traffic
│
├─── [1] TLS interception (custom CA installed on device)
│    ├─── [1a] Read DPoP-bound token
│    │    └─── MITIGATED: DPoP requires proof key for use
│    │         Stolen token alone is useless without the proof
│    │
│    ├─── [1b] Modify request method/URL
│    │    └─── MITIGATED: DPoP htm/htu binding
│    │         Modified request fails proof verification
│    │
│    └─── [1c] Replay captured request
│         └─── MITIGATED: jti uniqueness + freshness window
│
├─── [2] Token theft from network
│    └─── MITIGATED: DPoP binding
│         Stolen token requires proof key → key is hardware-bound
│         Token alone cannot be used from another device
│
└─── [3] Downgrade attack (force bearer)
     └─── MITIGATED: DPoP-required flow rejects bearer
         Server requires DPoP header; missing → 401
```

## Mobile-Specific Attack Surfaces

### 1. Key Extraction

| Threat | Platform | Mitigation |
|--------|----------|------------|
| Attacker reads key bytes from keychain/keystore | iOS | Secure Enclave: key material never in application memory; signing occurs inside the coprocessor |
| Attacker exports key from AndroidKeyStore | Android | AndroidKeyStore blocks `getPrivate()` export; StrongBox provides hardware-level isolation |
| Attacker reads key from shared preferences / file | All | Keys are never serialized to disk; only key references (aliases) are stored |
| Attacker intercepts key during generation | All | Keys generated inside secure hardware; generation API returns only a handle |
| Software fallback key in memory | All (fallback) | Degraded mode; signaling to backend; no silent downgrade |
| Memory dump during signing | iOS/Android | Secure Enclave/StrongBox perform signing in hardware; app never sees key material |

### 2. Proof Replay

| Threat | Mitigation |
|--------|------------|
| Attacker replays a captured DPoP proof on the same endpoint | `jti` uniqueness + server-side replay store |
| Attacker replays a proof on a different URL | `htu` binding to exact request target |
| Attacker replays a proof with a different HTTP method | `htm` binding |
| Attacker replays after the proof expired | `iat` freshness window (300s default) |
| Server nonce enforcement | Once the AS/RS issues a nonce challenge, subsequent requests MUST include a fresh nonce |

### 3. Token Substitution

| Threat | Mitigation |
|--------|------------|
| Attacker replaces the access token in a DPoP-bound request | `ath` claim binds the proof to the SHA-256 of the exact presented token |
| Attacker presents a stolen bearer token without the proof key | Token alone is insufficient; DPoP verification fails |
| Attacker presents a DPoP-bound token with a different DPoP key | Server checks `cnf.jkt` matches the proof key thumbprint |

### 4. Client Impersonation

| Threat | Mitigation |
|--------|------------|
| Attacker publishes a clone app with the same `client_id` | Dynamic client registration with per-instance keys; attestation binding to app signing identity |
| Attacker re-distributes a modified APK/IPA | Digitalis attestation (Google Play Integrity / Apple App Attest) verifies app integrity |
| Attacker reverse-engineers the client secret | Public clients: no shared secret. DPoP proof key IS the client credential |

### 5. Device Compromise

| Threat | Mitigation |
|--------|------------|
| Rooted / jailbroken device extracts keychain entries | Secure Enclave / StrongBox resist even root; user authentication can be required for signing |
| Keylogger captures user auth for signing | Biometric-bound keys (Android `setUserAuthenticationRequired`, iOS `SecAccessControl` with biometrics) |
| Process injection calls the legitimate signer | This is outside DPoP's security boundary; attestation helps detect compromised environment |
| Malicious app on same device accesses AndroidKeyStore | AndroidKeyStore keys are UID-bound; other apps cannot access them |
| Clipboard sniffing captures access token | Token is not stored on clipboard by the SDK; DPoP bound tokens are useless without the proof key |

### 6. Man-in-the-Middle

| Threat | Mitigation |
|--------|------------|
| TLS interception via custom CA | Certificate pinning (for the AS/RS endpoints); DPoP complementing TLS, not replacing it |
| Proxy modifies request method / URL | DPoP `htm`/`htu` binding detects mismatches; signature verification fails |

### 7. Attestation Bypass

| Threat | Mitigation |
|--------|------------|
| Attacker spoofs Apple App Attest | Digitalis backend verifies attestation with Apple; nonce binding prevents replay |
| Attacker spoofs Google Play Integrity | Digitalis backend verifies with Google; device/app integrity signals evaluated |
| Attacker uses attestation token from a different device | Nonce binding + key attestation certificate chain ties token to the specific key/device |

## Trust Boundaries

```text
Untrusted:
  - Network path (TLS is a complementary control)
  - Other apps on the device (without platform isolation)
  - App process memory after runtime compromise
  - Web browser DOM (for Web adapter)

Conditionally trusted:
  - Platform keystore API (trusted if OS is not compromised)
  - Attestation evidence (trusted only after backend verification)
  - OAuth token (trusted only after AS issuance + DPoP binding)
  - Browser WebCrypto (trusted if browser is not compromised)

Protected boundary:
  - Secure Enclave / StrongBox / TEE hardware
  - Generated key material inside secure hardware
  - Platform-enforced key isolation
```

## Failure Modes

| Failure | Consequence | Desired Behavior |
|---------|-------------|-----------------|
| Secure hardware unavailable | Cannot generate non-extractable key | Fail closed: degrade to software key with explicit user consent + signal to backend, OR deny bootstrap |
| Attestation denied | Cannot prove device integrity | Fail closed: deny bootstrap for high-assurance features |
| Signing fails (auth required, user cancels) | No proof generated | Return `SigningError.keyLocked`; caller prompts user |
| Nonce required, not present | Server rejects with 400 + `use_dpop_nonce` | Return `NonceRequired` to caller; retry with fresh proof including the nonce |
| Clock skew > 300s | Proof considered stale | Reject proof; caller should sync clock or use nonce |
| Hardware failure during signing | Signing operation fails | Retry once; if persistent, return `SigningError.hardwareFailure` |
| Keychain locked | Cannot access key reference | Return `StorageError.keychainLocked`; prompt user to unlock device |

## Security Invariants

```text
assert(private_key_bytes_never_in_app_memory == true)
assert(each_proof_has_unique_jti == true)
assert(ath_binds_exact_token_bytes == true)
assert(nonce_retry_creates_new_proof == true)
assert(hardware_key_unavailable -> no_silent_downgrade_without_consent == true)
assert(attestation_denied -> no_high_assurance_bootstrap == true)
assert(dpop_required_flow_no_bearer_fallback == true)
assert(jwk_in_header_matches_signing_key == true)
```
