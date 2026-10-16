# References

> **Keylix Client scope.** Adds mobile/desktop-specific references (platform secure-storage docs, OWASP Mobile, NIST 800-63B, FIDO) on top of the shared standards list. The canonical standards/references list lives in the public [`keylix-community`](https://github.com/hackelia-micrantha/keylix-community) repository: [docs/REFERENCES.md](https://github.com/hackelia-micrantha/keylix-community/blob/main/docs/REFERENCES.md).

## Standards

| RFC / Spec | Title | Relevance |
|-----------|-------|-----------|
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | OAuth 2.0 Demonstrating Proof of Possession (DPoP) | Core DPoP proof format and verification |
| [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) | OAuth 2.0 for Native Apps | Mobile OAuth best practices (browser-based flow, PKCE, no shared secrets) |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) | JSON Web Key (JWK) Thumbprint | Key identification and `cnf.jkt` matching |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) | JSON Web Algorithms (JWA) | ES256 signature format, JWK structure |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | Proof Key for Code Exchange (PKCE) | Authorization code protection for public clients |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key (JWK) | Public key representation |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature (JWS) | Compact JWS serialization |

## Platform Documentation

| Platform | Document | Relevance |
|----------|----------|-----------|
| iOS | [Apple CryptoKit](https://developer.apple.com/documentation/cryptokit) | Secure Enclave key generation and signing |
| iOS | [Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave) | Key storage |
| iOS | [Apple App Attest](https://developer.apple.com/documentation/devicecheck/attesting_app_integrity) | App attestation |
| Android | [AndroidKeyStore](https://developer.android.com/training/articles/keystore) | Hardware-backed key storage |
| Android | [Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) | Verifying hardware-backed keys |
| Android | [Play Integrity](https://developer.android.com/google/play/integrity) | Device/app integrity |
| Web | [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) | Browser-side key generation and signing |
| Web | [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) | Non-extractable CryptoKey operations |

## Related Projects

| Project | Relationship |
|---------|-------------|
| [Keylix](https://github.com/hackelia-micrantha/keylix-community) | Rust reference implementation of RFC 9449. Mobile SDKs MUST generate proofs verifiable by Keylix. |
| [Keylix Community](https://github.com/hackelia-micrantha/keylix-community) | Public development surface for Keylix. |
| [Digitalis](https://github.com/hackelia-micrantha/digitalis) | Mobile attestation backend (Apple App Attest, Google Play Integrity). Integrated as optional layer. |

## Attestation References

| Document | Relevance |
|----------|-----------|
| [Digitalis RFC-0001](https://github.com/hackelia-micrantha/digitalis/blob/main/rfcs/rfc_0001_trust_bootstrap_and_device_attestation_architecture.md) | Trust bootstrap architecture |
| [Digitalis Attest SDK v1 Contract](https://github.com/hackelia-micrantha/digitalis/blob/main/docs/attest_sdk_v_1_control_contract.md) | SDK interface contract |
| [Digitalis Threat Model](https://github.com/hackelia-micrantha/digitalis/blob/main/docs/threat-model.md) | Backend threat analysis |

## Mobile Security Best Practices

| Source | Relevance |
|--------|-----------|
| [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | Mobile threat landscape |
| [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) | Authentication assurance levels (AAL2/AAL3 with hardware attestation) |
| [FIDO Alliance](https://fidoalliance.org/) | Hardware-bound credentials (passkeys) — potential future integration |
