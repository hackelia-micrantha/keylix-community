# Requirements and Test Traceability

**Status:** v0.1 design and implementation traceability

This document turns Keylix's normative standards obligations and security invariants into executable test obligations. An implementation requirement is not considered complete until its positive and negative/adversarial coverage exists.

Sources:

- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- RFC 7638 — JSON Web Key (JWK) Thumbprint
- RFC 7515/7518 — JWS and ES256 representation
- Keylix threat-model invariants in [`THREAT_MODEL.md`](THREAT_MODEL.md)
- MCP SEP-1932 draft conformance behavior, tracked as an experimental integration profile

Status values: **Planned**, **Implemented**, **Covered**, **Deferred**.

## DPoP protected-resource verification

| ID | Source / invariant | Layer | Requirement | Positive test | Negative / adversarial test | Status |
| --- | --- | --- | --- | --- | --- | --- |
| KX-DPOP-001 | RFC 9449 §4.3; INV-1 | HTTP adapter | At most one `DPoP` header is accepted. | One header accepted. | Multiple headers/comma-joined ambiguity rejected. | Covered |
| KX-DPOP-002 | RFC 9449 §4.3; INV-2 | `keylix-dpop` | Proof is exactly one well-formed compact JWS/JWT with three segments. | Valid compact proof parses. | Missing/extra segments, invalid base64url, malformed JSON rejected. | Covered |
| KX-DPOP-003 | RFC 9449 §4.2/4.3; INV-3 | `keylix-dpop` | Required header/claims are present: `typ`, `alg`, `jwk`, `jti`, `htm`, `htu`, `iat`; `ath` for protected resources. | Complete proof accepted. | Each required member omitted independently. | Covered |
| KX-DPOP-004 | RFC 9449 §4.2; INV-4 | `keylix-dpop` | Protected header `typ` is exactly `dpop+jwt`. | Correct `typ`. | Missing/wrong/case-varied `typ`; unrelated signed JWT. | Covered |
| KX-DPOP-005 | RFC 9449 §4.3; ADR-0005; INV-5/8 | crypto policy | v0.1 accepts only `ES256` with EC/P-256. | ES256/P-256 accepted. | `none`, HS256, RSA, other EC curves/algs, alg/key mismatch rejected before acceptance. | Covered |
| KX-DPOP-006 | RFC 9449 §4.3; INV-7 | crypto backend | Signature verifies over original compact-JWS signing input with proof public key. | Independent valid ES256 vector accepted. | Bit-flipped header/payload/signature; wrong key; DER signature rejected. | Covered |
| KX-DPOP-007 | RFC 9449 §4.3; INV-6 | JWK parser | Proof JWK contains public material only and a valid P-256 point. | Valid public JWK accepted. | `d`, malformed coordinates, off-curve/invalid point, wrong `kty`/`crv` rejected. | Covered |
| KX-DPOP-008 | RFC 9449 §4.3; INV-9 | request binding | `htm` equals actual HTTP method. | Exact method accepted. | Different/case-manipulated/missing method rejected. | Covered |
| KX-DPOP-009 | RFC 9449 §4.3; ADR-0006; INV-10/11 | request binding | `htu` equals trusted effective request target after defined normalization, excluding query/fragment. | Equivalent normalized URI accepted. | Host/scheme/path/default-port/reserved-char mismatch; hostile forwarded headers rejected. | Covered |
| KX-DPOP-010 | RFC 9449 §4.3/§8/§9; ADR-0009; INV-16/17 | nonce | When nonce is required for the challenge context, proof carries the acceptable issued nonce. | Current nonce accepted. | Missing/stale/wrong/cross-server nonce and downgrade attempts rejected/challenged. | Covered |
| KX-DPOP-011 | RFC 9449 §4.3; ADR-0009; INV-15 | freshness | Default `iat` policy accepts only within ±300 seconds; policy is explicit/configurable. | Boundaries inside window accepted. | Past/future values outside window; non-number/overflow rejected. | Covered |
| KX-DPOP-012 | RFC 9449 §4.3/§7; INV-12 | token hash | `ath` equals base64url(SHA-256(access-token bytes)) for exact presented token. | Correct `ath` accepted. | Token substitution, missing/wrong `ath` rejected. | Covered |
| KX-DPOP-013 | RFC 9449 §4.3/§6; ADR-0007; INV-13/14 | `keylix-oauth` | Verified proof key thumbprint equals trusted `cnf.jkt` from validation of the exact presented token. | Valid JWT/introspection binding accepted. | Unvalidated `cnf`, wrong `jkt`, token-A metadata + token-B bytes rejected. | Covered |
| KX-DPOP-014 | RFC 9449 §11.1; ADR-0003/0009; INV-19–22 | replay | A proof identifier is accepted at most once in its verified key/method/target context during its acceptance lifetime. | First atomic insertion returns Fresh. | Sequential/concurrent replay returns Replay; backend failure fails closed in strict mode. | Covered |
| KX-DPOP-015 | INV-29–31; ADR-0007 | result types | Parsing, proof verification, and OAuth sender binding are distinct typed states. | `VerifiedSenderBinding` only produced by full composition. | Compile/API tests prevent treating parsed proof as verified binding; forged raw token metadata not accepted through normal adapters. | Covered |

`KX-DPOP-009` is **Covered** for Keylix's framework-neutral direct and explicitly trusted single-hop proxy adapter. The conformance suite exercises direct targets, trusted `Forwarded` and `X-Forwarded-*` reconstruction, untrusted peers, mixed/multi-hop ambiguity, malformed metadata, and proof verification against the reconstructed target. Frameworks still own peer identity and externally visible path-rewrite correctness; unsupported proxy topologies fail closed rather than being inferred. Distributed replay deployments retain the adapter obligations documented in [`STATE_STORES.md`](STATE_STORES.md).

## DPoP proof construction

| ID | Source / invariant | Layer | Requirement | Positive test | Negative / adversarial test | Status |
| --- | --- | --- | --- | --- | --- | --- |
| KX-BUILD-001 | RFC 9449 §4.2 | proof builder | Each proof gets a fresh collision-resistant `jti`; reference generator provides at least 96 random bits. | Generated proofs have unique IDs across large sample. | Injected deterministic/reused IDs are detectable by replay tests. | Covered |
| KX-BUILD-002 | RFC 9449 §4.2; ADR-0006 | proof builder | `htm` is request method and `htu` is target URI without query/fragment using Keylix normalization rules. | Known request produces expected claims. | Query/fragment never leaks into `htu`; ambiguous URI input fails. | Covered |
| KX-BUILD-003 | RFC 9449 §4.2 | proof builder | `iat` comes from injected clock. | Deterministic test clock produces exact value. | Invalid clock/time conversion produces error rather than malformed proof. | Covered |
| KX-BUILD-004 | RFC 9449 §4.2 | proof builder | Protected-resource proof contains correct `ath`. | RFC/known hash vector. | Different token changes hash; no accidental Unicode/string normalization. | Covered |
| KX-BUILD-005 | RFC 9449 §8/§9; ADR-0009 | proof builder/client | Issued nonce is included in the next proof for the correct issuer/server scope. | AS and RS nonce paths. | Cross-origin/AS-to-RS nonce confusion rejected by state model. | Covered |
| KX-BUILD-006 | ADR-0005/0010 | signer | Proof uses ES256 and public P-256 JWK only; signature is exactly 64-byte JWS R||S. | Software/external signer interoperability. | DER, wrong-length, mismatched-public-key output rejected. | Covered |
| KX-BUILD-007 | ADR-0009; INV-18 | retry integration | Every HTTP or nonce retry generates a fresh proof and `jti`. | Retry produces different proof. | Intentional proof reuse is rejected by integration/conformance scenario. | Covered |

All v0.1 proof-construction rows are **Covered**. Conformance now checks a large reference-generator `jti` sample plus intentional ID reuse/replay, exact injected-clock propagation and clock failure, the external `DpopSigner` capability contract including DER/wrong-length/key-mismatch rejection, and OAuth resource nonce retry with explicit fresh-`jti` comparison and replay rejection of the original proof.

## RFC 7638 JWK thumbprints

For v0.1 EC/P-256 JWKs, thumbprint input is the UTF-8 JSON object containing only the required members in lexicographic member-name order:

```json
{"crv":"P-256","kty":"EC","x":"...","y":"..."}
```

The digest is SHA-256 and the thumbprint is base64url without padding.

| ID | Source | Layer | Requirement | Positive test | Negative / adversarial test | Status |
| --- | --- | --- | --- | --- | --- | --- |
| KX-JWK-001 | RFC 7638 §3 | `keylix-core` | Thumbprint uses only required EC members `crv`, `kty`, `x`, `y` in lexicographic order. | RFC/independent vector matches. | Optional `kid`, `alg`, `use`, member ordering/whitespace do not change thumbprint. | Covered |
| KX-JWK-002 | RFC 7638 §3 | `keylix-core` | Member values are the exact normalized JWK strings used by the validated public JWK representation. | Equivalent parsed public key yields deterministic thumbprint. | Invalid base64url/coordinate values never produce trusted JWK type. | Covered |
| KX-JWK-003 | RFC 7638 §3.4 | `keylix-core` | SHA-256 is used and output is base64url without padding. | Known digest/output vector. | Padded/base64-standard/wrong-hash output differs and is rejected where parsed. | Covered |
| KX-JWK-004 | ADR-0004/0005 | `keylix-core` | Public/private key API separation prevents thumbprint calculation from requiring or serializing private material. | Public JWK thumbprint succeeds. | Any private `d` member supplied to the validated public-JWK boundary is rejected and never participates in identity. | Covered |

## OAuth composition and downgrade resistance

| ID | Source / invariant | Layer | Requirement | Positive test | Negative / adversarial test | Status |
| --- | --- | --- | --- | --- | --- | --- |
| KX-OAUTH-001 | RFC 9449 §5/§7; INV-26/27 | OAuth client | DPoP-required token flow requests a bound token and requires `token_type=DPoP`. | DPoP token returned/used. | Bearer/unbound token in required mode rejected; no fallback. | Covered |
| KX-OAUTH-002 | ADR-0007 | OAuth resource adapter | Token validation result is correlated to exact presented token before sender binding. | Matching token fingerprint. | Token A validation + token B presentation rejected. | Covered |
| KX-OAUTH-003 | RFC 9449 §6; ADR-0007 | OAuth resource adapter | `cnf.jkt` comes only from authenticated/validated token result. | Valid JWT and active authenticated introspection adapters. | Decoded-but-unverified JWT, inactive or unauthenticated introspection rejected. | Covered |
| KX-OAUTH-004 | RFC 9449 §7.1; INV-27 | HTTP protected resource | DPoP-bound token is sent with `Authorization: DPoP`, never silently as Bearer. | DPoP scheme accepted. | Bearer scheme in DPoP-required mode rejected. | Covered |
| KX-OAUTH-005 | RFC 9449 refresh-token requirements; INV-25 | OAuth client/key lifecycle | Bound refresh token continues to use its original proof key until OAuth relationship is deliberately replaced. | Refresh with K1 succeeds. | Refresh with rotated K2 rejected/prevented by client state model. | Covered |
| KX-OAUTH-006 | RFC 9449 §8/§9; ADR-0009 | OAuth client | Handles AS and RS `use_dpop_nonce` challenges with fresh-proof retry and tracks successful-response nonce updates. | Both nonce flows complete. | Nonce ignored, wrong scope, proof reused, retry loop bounded. | Covered |

`keylix-oauth` treats host validation as an explicit trust boundary rather than implementing token validation itself. The validated-JWT and authenticated-introspection constructors are host attestations over the exact token bytes; Keylix then enforces exact-token correlation and trusted `cnf.jkt` equality. See [`OAUTH_INTEGRATION.md`](OAUTH_INTEGRATION.md).

## Observability and security evidence

| ID | Source / invariant | Layer | Requirement | Positive test | Negative / adversarial test | Status |
| --- | --- | --- | --- | --- | --- | --- |
| KX-OBS-001 | ADR-0011; INV-24/28 | all crates/adapters | Ordinary `Debug`, errors, logs, traces, and metrics never expose credential material: access/refresh tokens, private keys, full proofs, raw nonces, raw `jti`, authorization-code/credential header values. | Safe snapshots/categories contain only approved fields. | Seed distinctive secrets/attacker strings and assert they are absent from all diagnostic outputs. | Covered |
| KX-OBS-002 | ADR-0011; INV-24 | telemetry | Raw JWK thumbprints are excluded from default logs and metric labels; metrics use bounded low-cardinality dimensions. | Default success/failure telemetry has bounded schema. | High-cardinality `jkt`/claims cannot become labels/log fields through normal API. | Covered |
| KX-OBS-003 | ADR-0011; INV-31 | evidence API | Stable key-level attribution is available only through an explicit structured security-evidence interface, optionally including `jkt`, and never includes raw token/proof/nonce/`jti`/private key. | Explicit evidence contains documented compact fields and supports omitting thumbprint. | Verbose logging does not enable evidence; forbidden fields cannot be emitted by the standard evidence builder. | Covered |

`KX-OBS-001` through `KX-OBS-003` are **Covered** by the dependency-free `keylix-observe` value layer and public conformance tests. Operational telemetry exposes only bounded static labels; the standard API has no arbitrary-label or credential-bearing field. Explicit `SenderBindingEvidence` can be constructed only from `VerifiedSenderBinding`, omits the stable key thumbprint by default, and still redacts it from `Debug` when explicitly included. Seeded credential, nonce, forwarded-header, malformed-input, and key-identifier values are asserted absent from ordinary diagnostics.

## MCP SEP-1932 experimental profile

MCP DPoP is treated as a version-aware experimental adapter until the extension stabilizes. These requirements mirror the current draft conformance direction rather than redefining MCP authorization.

| ID | Source | Layer | Requirement | Positive test | Negative / adversarial test | Status |
| --- | --- | --- | --- | --- | --- | --- |
| KX-MCP-001 | SEP-1932 draft; ADR-0008 | `keylix-mcp` client | MCP HTTP request carrying DPoP-bound token uses `Authorization: DPoP` and a fresh `DPoP` proof. | Draft conformance happy path. | Bearer scheme and reused proof fail draft conformance. | Covered |
| KX-MCP-002 | SEP-1932 draft | `keylix-mcp` client | Token endpoint proof is used when obtaining a DPoP-bound token. | Bound-token flow. | Omitting token-request proof yields unusable/unbound token for required profile. | Covered |
| KX-MCP-003 | SEP-1932 draft | `keylix-mcp` client | AS and RS nonce challenges are supported. | `auth/dpop-nonce` style flow. | Ignore-AS/ignore-RS nonce variants fail. | Covered |
| KX-MCP-004 | ADR-0001/0008 | architecture | DPoP stays in HTTP authorization transport; no DPoP fields are added to MCP JSON-RPC messages. | HTTP adapter integration. | Dependency/API check prevents MCP types in `keylix-dpop`. | Covered |
| KX-MCP-005 | ADR-0008 | compatibility | Adapter declares the MCP/SEP profile it targets and does not claim stable MCP conformance while SEP-1932 remains draft. | Version/status metadata test/documentation. | Unsupported profile is explicit rather than silently downgraded. | Covered |

`KX-MCP-001` through `KX-MCP-005` are **Covered** for the explicit Keylix `sep-1932-draft` contract. Coverage includes token-endpoint proof/key binding and missing-proof/Bearer negatives, official `rmcp` HTTP request decoration with fresh proofs, conflicting-header rejection before dispatch, replay/method/target binding, AS/RS nonce separation and bounded retry state, unchanged JSON-RPC forwarding, dependency direction, server-side pre-dispatch DPoP verification, exact-token `cnf.jkt` composition into `VerifiedSenderBinding`, stolen-token/key mismatch rejection, and explicit draft-profile metadata. This is not a claim of stable MCP DPoP conformance: SEP-1932 remains Draft. Trusted-proxy reconstruction of the external `EffectiveRequestTarget` remains the separate `KX-DPOP-009` integration obligation, and observability/evidence remains under `KX-OBS-*`.

## Threat-model invariant traceability

| Invariants | Primary requirement IDs |
| --- | --- |
| 1–8 proof structure/JOSE | KX-DPOP-001 through KX-DPOP-007, KX-DPOP-005 |
| 9–11 request binding | KX-DPOP-008, KX-DPOP-009, KX-BUILD-002 |
| 12–14 token binding | KX-DPOP-012, KX-DPOP-013, KX-OAUTH-002/003 |
| 15–22 freshness/nonce/replay | KX-DPOP-010/011/014, KX-BUILD-001/005/007, KX-OAUTH-006 |
| 23 key custody | KX-BUILD-006, KX-JWK-004 |
| 24 diagnostic secrecy/privacy | KX-OBS-001, KX-OBS-002 |
| 25 refresh-token/key lifecycle | KX-OAUTH-005 |
| 26–28 downgrade/failure resistance | KX-OAUTH-001/004/006, KX-MCP-001/005, KX-OBS-001 |
| 29–31 result/evidence semantics | KX-DPOP-015, KX-OAUTH-002/003, KX-OBS-003, architecture/API tests |

## Completion rule

A security-sensitive implementation PR should reference the relevant requirement IDs. When tests land, update each row from **Planned** to **Implemented** or **Covered**. A requirement may be **Deferred** only with an ADR or issue explaining why the v0.1 security contract does not require it.