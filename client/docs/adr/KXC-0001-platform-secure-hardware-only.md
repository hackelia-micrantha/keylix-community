# ADR KXC-0001: Platform-Secure-Enclave-Only Key Generation

## Status

Accepted

## Context

Keylix Client's primary defense against key exfiltration is to generate DPoP proof keys inside platform secure hardware (Secure Enclave, AndroidKeyStore/StrongBox, WebCrypto non-extractable). An alternative is to allow importing pre-existing keys, but importing requires exposing private-key bytes to application memory, breaking the non-extractable guarantee.

## Decision

Keylix Client v1 supports only key generation inside platform secure hardware. Importing pre-existing keys is NOT supported.

## Consequences

- Positive: private key bytes never enter application memory.
- Positive: key attestation (Android certificate chain, iOS App Attest) can bind to a freshly generated key.
- Negative: existing key material cannot be migrated into Keylix Client's storage.
- Negative: cross-device key sharing (e.g., synced passkeys) is out of scope for v1.
