# ADR-0010: Crypto and JOSE backend architecture

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

Keylix needs strict ES256 proof signing and verification, JWK parsing/validation, SHA-256 thumbprints and access-token hashes, and eventually support for non-extractable signing keys. A general-purpose JWT library can simplify compact-JWS handling, but it can also introduce algorithm dispatch, unrelated JWT claim semantics, and byte-oriented private-key APIs that conflict with Keylix's narrow DPoP security boundary.

The v0.1 algorithm policy is intentionally ES256/P-256 only (ADR-0005).

RFC 7518 defines an ES256 JWS signature as exactly 64 bytes: 32-byte big-endian `R` followed by 32-byte big-endian `S`.

`aws-lc-rs` exposes P-256/SHA-256 fixed-format ECDSA signing and verification matching that representation and documents EC public-key validation. It also provides an optional FIPS-backed build path. It requires native C/C++ build support.

## Decision

### Cryptographic backend

The default native v0.1 backend is **`aws-lc-rs`** for:

- P-256 public-key validation;
- ES256 signature verification;
- the reference in-process software signer;
- cryptographically secure randomness needed by the reference signer/key generator where applicable.

The precise dependency version is pinned through Cargo.lock for repository builds and governed by normal dependency review/update policy.

Keylix does not expose the backend's generic algorithm registry as its policy. The only verifier path wired in v0.1 is P-256 + SHA-256 + fixed-format ECDSA corresponding to `ES256`.

### Signing capability boundary

Proof construction depends on a Keylix signing capability rather than on private-key bytes, conceptually:

```text
DpopSigner
- algorithm() -> ES256
- public_jwk() -> PublicP256Jwk
- sign(signing_input) -> 64-byte ES256 signature
```

The reference software implementation uses `aws-lc-rs`. External implementations may delegate signing to a TPM, HSM, OS keystore, KMS, PKCS#11 provider, or another reviewed backend as long as they return the exact ES256 JWS signature format and the public JWK corresponds to the signing key.

The core proof builder never requires private-key extraction.

### JOSE handling

Keylix does **not** delegate DPoP verification to a general-purpose JWT `decode()` call.

The v0.1 DPoP layer owns a narrow compact-JWS codec for exactly the protocol surface it needs:

1. enforce exactly three compact-JWS segments;
2. base64url-decode protected header, payload, and signature with explicit size limits;
3. deserialize protected header and payload into strict typed structures;
4. reject duplicate required fields and ambiguous JSON;
5. reject missing/extra private JWK material according to policy;
6. require `typ = dpop+jwt` and `alg = ES256` before crypto dispatch;
7. reconstruct the JWS Signing Input from the original encoded protected-header and payload segments;
8. require a 64-byte ES256 JWS signature;
9. validate the P-256 public point and verify the signature with the fixed ES256 backend.

Owning compact-JWS framing and typed protocol parsing is not treated as implementing cryptographic primitives. Keylix does not implement ECDSA, SHA-256, random-number generation, or elliptic-curve arithmetic itself.

### Data-format dependencies

Use small, non-policy dependencies for protocol representation:

- `serde` / `serde_json` for typed JSON with explicit duplicate-field rejection behavior tested at the DPoP boundary;
- a well-maintained base64url implementation for JWS/JWK encoding;
- SHA-256 from the selected cryptographic backend or a narrowly reviewed hash crate where backend independence is needed.

Do not expose generic JWT validation semantics such as `exp`, `nbf`, `iss`, or `aud` from the DPoP proof parser. DPoP `iat` is evaluated by Keylix's explicit proof-freshness policy.

### WASM and alternate backends

WASM support is not a v0.1 requirement because `aws-lc-rs` is a native backend. A future backend may use RustCrypto/WebCrypto or another implementation behind the same Keylix signer/verifier boundary. Adding a backend must pass the same conformance, adversarial, property, and interoperability tests and must not expand the accepted algorithm policy implicitly.

## Consequences

### Positive

- exact match between the backend signature representation and RFC 7518 ES256 JWS encoding;
- documented P-256 public-key validation;
- no generic untrusted algorithm dispatch;
- private-key capabilities remain compatible with HSM/KMS/TPM designs;
- DPoP claim semantics remain under Keylix's explicit verifier policy;
- optional future FIPS-oriented deployment path.

### Negative

- native toolchain dependency for the default backend;
- Keylix owns a small amount of compact-JWS framing/parsing code that must be heavily fuzzed;
- WASM requires a future alternate backend;
- external signers need adapters and signature-format conformance tests.

## Required tests

- RFC 7518 ES256 fixed-signature vectors;
- valid/invalid P-256 point handling;
- wrong-length and DER-encoded signature rejection;
- algorithm/key mismatch rejection before signature acceptance;
- duplicate header/claim fields;
- malformed compact-JWS segmentation/base64/JSON;
- signing-input preservation using original encoded header/payload segments;
- software signer/verifier interoperability with an independent JOSE implementation;
- external mock signing capability returning valid, malformed, and mismatched-key signatures;
- no private key bytes required by the public proof-construction API.