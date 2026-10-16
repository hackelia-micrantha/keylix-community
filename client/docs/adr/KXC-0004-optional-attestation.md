# ADR KXC-0004: Attestation as an Optional, Policy-Driven Layer

## Status

Accepted

## Context

Not all mobile applications require device attestation. High-assurance applications (banking, healthcare, government) benefit from Digitalis attestation (Apple App Attest, Google Play Integrity) to verify device/app integrity before using DPoP keys. Standard apps may not want the operational dependency on a backend.

## Decision

Attestation is an **optional**, **policy-driven** layer. The SDK exposes a `BootstrapConfig.attestationRequired` flag. When enabled:

1. **The DPoP proof key is generated FIRST** in platform secure hardware.
2. **The attestation is bound to that key** — the attestation evidence references the DPoP key's public key (Android: `setAttestationChallenge(publicKey)` during key gen; iOS: `clientDataHash = SHA-256(publicKey)` in `generateAssertion`).
3. **The attestation is submitted** to the configured Digitalis backend.
4. **If verdict = ALLOW**, the DPoP key becomes active and proof generation can proceed.
5. **If verdict = DENY**, the DPoP key is **deleted** from secure hardware and bootstrap fails closed.

### Correct ordering (key first, then attestation)

```text
1. generateKeyPair(alias)          → KeyReference
2. exportPublicKeyJwk(keyRef)      → Jwk { kty, crv, x, y }
3. compute thumbprint (RFC 7638)   → jkt
4. get attestation challenge from Digitalis
5. bind attestation to DPoP key
6. submit evidence to Digitalis
7. if ALLOW  → TRUSTED_ACTIVE
   if DENY   → deleteKey(alias); return Failure
```

This ordering is mandatory because:
- The attestation must prove "this specific key was generated in genuine hardware." A separate attestation key would prove nothing about the DPoP key.
- If attestation fails, the key is destroyed — it never enters service.
- The Digitalis backend verifies the attestation's embedded public key matches the DPoP key thumbprint presented in OAuth flows.

When attestation is disabled, the SDK generates the DPoP key directly (still in secure hardware) without the attestation round-trip.

## Consequences

- Positive: standard apps avoid backend dependency and latency.
- Positive: high-assurance apps get device integrity verification bound to the actual DPoP key.
- Positive: attestation denial deletes the key — no risk of an unattested key entering service.
- Positive: the attestation contract mirrors Digitalis RFC-0001 and the v1 control contract.
- Negative: two bootstrap paths to test (with/without attestation).
- Negative: attestation adds latency to first-launch bootstrap (one network round-trip to Digitalis).
- Negative: if the Digitalis backend is unreachable, attestation-required apps cannot bootstrap (by design — fail closed).
