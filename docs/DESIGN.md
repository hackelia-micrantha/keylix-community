# Keylix Design

**Status:** v0.1 design baseline accepted. Implementation should follow the decisions and invariants recorded here, in [`THREAT_MODEL.md`](THREAT_MODEL.md), [`REQUIREMENTS.md`](REQUIREMENTS.md), and the [ADRs](adr/README.md).

## Purpose

Keylix is a reusable Rust implementation of sender-constrained OAuth authorization primitives, beginning with DPoP (RFC 9449), plus adapters for OAuth protected-resource flows and MCP HTTP transports.

Keylix is deliberately **not** an authorization server, identity provider, policy engine, MCP gateway, or governance system. Its job is narrower: prove and verify that a caller presenting an OAuth credential also possesses the private key to which that credential is bound.

## Design goals

1. **Protocol correctness first.** RFC requirements become explicit types, policies, and negative tests.
2. **Fail closed.** Ambiguous, malformed, replayed, stale, downgraded, or unverifiable input is rejected.
3. **Small trusted core.** MCP and concrete HTTP clients remain adapters around a protocol-independent DPoP core.
4. **No ambient authority.** A verified DPoP proof is evidence of key possession, not an authorization decision.
5. **Opaque secrets.** Private-key and token APIs minimize serialization, logging, cloning, and accidental extraction.
6. **Explicit state semantics.** Replay and nonce handling are security boundaries with documented consistency guarantees.
7. **Interoperability without downgrade.** Integrations may support Bearer OAuth separately, but DPoP-required callers never silently fall back to Bearer.
8. **Testability.** Time, randomness, key storage, nonce state, replay state, token validation, and transport behavior are injected behind narrow ports.
9. **Traceability.** Security-sensitive implementation maps to explicit `KX-*` requirements and positive/negative tests.

## System context

```text
                 +---------------------------+
                 | Authorization Server / IdP|
                 | OAuth metadata + tokens   |
                 +-------------+-------------+
                               ^
                  token request| + DPoP proof
                               |
+--------------------+         |         +-------------------------+
| MCP / OAuth client |---------+-------->| Keylix client adapters  |
| agent / application|                   | proof + nonce handling  |
+--------------------+                   +------------+------------+
                                                     |
                                                     | HTTP
                                                     v
                                          +----------+-----------+
                                          | Resource / MCP server|
                                          +----------+-----------+
                                                     |
                                      request + token + DPoP proof
                                                     v
                                          +----------+-----------+
                                          | Keylix DPoP verifier |
                                          +----------+-----------+
                                                     |
                                              VerifiedDpopProof
                                                     |
                                  + validated OAuth token result
                                                     v
                                          +----------+-----------+
                                          | OAuth composition    |
                                          +----------+-----------+
                                                     |
                                           VerifiedSenderBinding
                                                     v
                                          +----------+-----------+
                                          | Application / gateway|
                                          | policy / governance   |
                                          +----------------------+
```

## Layering

```text
keylix-core
    ^
    | public-key/JWK/thumbprint types; sensitive wrappers; common errors
    |
keylix-dpop <----- keylix-http
    ^              | framework-neutral trusted HTTP target adaptation
    |              | direct / explicitly trusted single-hop proxy reconstruction
    |
    | RFC 9449 proof builder/verifier + clock/replay/nonce/signing ports
    |
keylix-oauth <----- keylix-observe
    ^              | bounded operational telemetry values
    |              | explicit evidence from VerifiedSenderBinding only
    |
    | exact-token OAuth composition + token/protected-resource integration
    |
keylix-mcp
    |
    | experimental SEP-1932/current MCP HTTP profile adapter
    v
applications / gateways / MCP SDKs

keylix-conformance -----> black-box tests against public protocol behavior
```

Dependencies point inward. `keylix-core` and `keylix-dpop` MUST NOT depend on an MCP SDK or a concrete OAuth provider. `keylix-observe` is a downstream adapter/value layer: it may consume verified OAuth sender state, but protocol crates do not depend on observability frameworks or on `keylix-observe`.

## Verified-state model

Keylix distinguishes untrusted parsed data, verified proof semantics, and OAuth sender binding in the type system.

```text
raw HTTP / compact JWS / JWK
          |
          v
 UnverifiedDpopProof
          |
          | verify(policy, effective_request, raw_access_token, state)
          v
   VerifiedDpopProof
      - verified proof key thumbprint
      - htm/htu/freshness/nonce/replay verified
      - ath verified for exact presented token when applicable
          |
          | compose(validated result for that exact token)
          v
  VerifiedSenderBinding
```

Callers cannot obtain a `VerifiedSenderBinding` merely by parsing a JWT, inspecting `cnf.jkt`, or validating a DPoP signature.

Candidate value types include:

- `PublicP256Jwk`
- `JwkThumbprint`
- `AccessTokenHash`
- `ProofId`
- `ProofIssuedAt`
- `EffectiveRequestTarget`
- `DpopNonce`
- `UnverifiedDpopProof`
- `VerifiedDpopProof`
- `ValidatedTokenBinding`
- `VerifiedSenderBinding`
- `VerificationPolicy`

Names may evolve, but trust-state distinctions must remain.

## Ports and adapters

Protocol code owns interfaces, not infrastructure.

### Client-side ports

- `DpopSigner`: exposes ES256 signing capability and public JWK without requiring private-key extraction.
- `Clock`: current time for `iat`.
- `ProofIdGenerator`: cryptographically strong fresh `jti` generation.
- `NonceStore`: nonce lookup/update scoped separately to authorization/resource servers.

### Server-side ports

- `Clock`: freshness evaluation.
- `ReplayStore`: atomic `check_and_record` for accepted proof identities.
- `NonceValidator`: deployment-selected nonce policy and rotation.
- trusted HTTP adapter: supplies method plus `EffectiveRequestTarget`.

### OAuth composition port

`keylix-oauth` accepts a trusted result from a host OAuth validator rather than validating general JWT/OAuth policy itself. The result must correlate to the exact presented token and contain trusted DPoP confirmation material.

## HTTP target model

DPoP is bound to the HTTP request, not to the MCP JSON-RPC payload. `keylix-dpop` receives a trusted external request context:

```text
EffectiveRequest
- method
- EffectiveRequestTarget
- presented access token (optional)
- DPoP proof
```

Per ADR-0006, the DPoP core never trusts `Forwarded` or `X-Forwarded-*` itself. `keylix-http` provides the framework-neutral v0.1 boundary: direct targets use host-trusted request parts, while proxy mode requires an injected immediate-peer trust policy and exactly one configured forwarding-header family. The generic adapter supports one trusted hop and fails closed on mixed, appended/multi-hop, malformed, or untrusted metadata; frameworks still supply the externally visible path/query so Keylix does not guess rewrite semantics.

`htu` comparison strips query/fragment and applies the defined RFC 3986 syntax/scheme normalization before exact comparison.

## Algorithm and crypto policy

Per ADR-0005, v0.1 accepts only:

```text
JWS alg = ES256
JWK kty = EC
JWK crv = P-256
```

Untrusted JOSE `alg` never expands policy. `none`, MAC algorithms, RSA, other curves, and other signature algorithms are rejected in the v0.1 profile.

Per ADR-0010:

- `aws-lc-rs` is the default native P-256/SHA-256 backend;
- proof verification uses the RFC 7518 fixed 64-byte ES256 JWS signature representation;
- the signing API remains capability-based so HSM/TPM/KMS/keystore adapters can be non-extractable;
- Keylix owns a narrow, size-bounded compact-JWS framing/parser rather than delegating DPoP trust semantics to a general-purpose JWT decoder.

## State model

### Replay

Replay prevention is an atomic operation:

```text
check_and_record(replay_key, expiry) -> Fresh | Replay | StoreFailure
```

Per ADR-0009, the logical identity is derived from:

```text
proof key thumbprint + canonical HTTP method + normalized htu + jti
```

and is preferably stored as a fixed-size digest. `ath` is intentionally excluded so token substitution cannot create a new replay namespace for an already-used proof ID.

Logical expiry is `iat + max_proof_age`. With the default ±300-second freshness policy, a future-dated proof accepted at the skew boundary can require up to 600 seconds of remaining store TTL.

Reference backends:

1. bounded in-memory atomic TTL store for tests/single-instance services;
2. distributed-store adapter contract for multi-instance deployments.

A process-local backend must never be represented as cluster-safe.

### Nonce

Authorization-server and resource-server nonce namespaces are separate. Clients support both challenge classes in v0.1 and every retry creates a new proof/new `jti`.

Server nonce enforcement is supported but opt-in. Once a challenge establishes nonce use for its context, verification cannot silently downgrade to nonce-less acceptance.

## Proof freshness

The default v0.1 policy accepts `iat` within ±300 seconds of the verifier clock, matching the current SEP-1932 conformance window. Deployments may tighten past-age/future-skew policy or use nonce enforcement for stronger freshness.

Time policy is explicit and injectable; malformed or out-of-range `iat` fails closed.

## Key lifecycle

The API supports a stable client proof key across the lifetime of a DPoP-bound refresh-token relationship. For public clients, transparent local key rotation cannot move an active bound refresh token to another key.

Recommended signer backends include:

- reference in-process software P-256 key;
- OS/platform keystore adapters;
- PKCS#11/HSM/TPM/KMS-style non-extractable signing adapters.

The proof builder depends on signing capability, not raw private-key bytes.

## Error model

Errors are structured internally but intentionally lossy at protocol boundaries.

```text
ParseError
VerificationError
  - malformed proof
  - unsupported algorithm/key
  - invalid signature
  - method mismatch
  - target mismatch
  - stale/future proof
  - access-token hash mismatch
  - nonce required/mismatch
  - replay detected
  - state backend unavailable
OAuthBindingError
  - token not DPoP-bound
  - token identity mismatch
  - proof-key/token-key mismatch
IntegrationError
```

External adapters map these to protocol-appropriate OAuth/HTTP errors without exposing proof/token/key contents or unnecessary validation oracles.

## Observability and evidence

Per ADR-0011, normal logs/errors/metrics never contain access/refresh tokens, authorization codes, private key bytes, full proofs, raw nonces, raw `jti`, Authorization/DPoP header values, or raw `jkt` metric/log fields.

An explicitly enabled security-evidence sink may carry a compact verified sender binding including the public-key thumbprint for provenance/audit, with retention/privacy controlled by the host. Increasing log verbosity does not enable this evidence path.

## Integration posture

### OAuth

`keylix-oauth` composes with existing OAuth implementations. It provides:

- token-request proof decoration;
- AS/RS DPoP nonce challenge handling;
- `token_type=DPoP` enforcement when DPoP is required;
- protected-resource request decoration using `Authorization: DPoP` plus a fresh proof;
- exact-token correlation between host OAuth validation and trusted `cnf.jkt`;
- composition into `VerifiedSenderBinding`;
- refresh-token/proof-key continuity handling.

It does **not** become an authorization-code flow framework, OIDC implementation, issuer/audience/scope policy engine, token issuer, or general JWT validator.

### MCP

Per ADR-0008, `keylix-mcp` is initially:

- explicitly experimental/profile-based while SEP-1932 is draft;
- HTTP transport only;
- a thin adapter over `keylix-oauth`;
- strict about configured/negotiated DPoP support;
- incapable of silently converting DPoP-required use into Bearer;
- version-aware so stabilized MCP extension semantics can replace local profile logic without changing `keylix-dpop`.

DPoP fields do not enter MCP JSON-RPC messages. STDIO MCP authorization remains out of this HTTP OAuth scope.

### Gateways and governance

Gateways such as Invokrum can consume `VerifiedSenderBinding`/explicit evidence as one input to authorization/governance. They remain responsible for identity, scopes/entitlements, tool/resource policy, approvals, workload/agent identity, and audit/provenance decisions.

Anthesis-style governance may retain a verified public-key thumbprint as provenance only through the explicit evidence interface; it never receives private keys or raw access tokens from Keylix.

## Conformance strategy

Conformance is part of the product, not a late test phase. [`REQUIREMENTS.md`](REQUIREMENTS.md) is the executable traceability plan covering:

1. every RFC 9449 proof validation/construction obligation;
2. RFC 7638 EC thumbprints;
3. RFC 7518 ES256 representation;
4. OAuth exact-token/key-binding composition and downgrade resistance;
5. replay races, state failure, freshness and nonce behavior;
6. parser differentials and malformed JOSE/JWK input;
7. safe observability/evidence behavior;
8. draft MCP SEP-1932 interoperability, separate from core RFC conformance;
9. all 31 threat-model invariants.

Fuzz targets cover compact-JWS/JWK parsing and verifier input boundaries. Crypto interoperability uses an independent implementation in addition to the reference backend.

## Delivery sequence

```text
Accepted design / ADRs / requirements
              |
              v
RFC 7638 JWK + thumbprints (#3)
              |
              v
RFC 9449 proof builder/verifier (#4)
        + replay/nonce state (#5)
              |
              v
conformance + adversarial/fuzz (#6)
              |
              v
OAuth adapters (#7)
              |
              v
MCP experimental SEP-1932 adapter (#8)
```

No MCP-specific behavior may justify weakening RFC 9449 semantics.

## Future design evolution

The initial v0.1 design gate is complete. Future changes require explicit issues/ADRs where they affect security behavior, including:

- additional signature algorithms;
- alternate/WASM crypto backends;
- framework-specific proxy reconstruction helpers;
- concrete distributed replay/nonce backends;
- stabilized MCP DPoP negotiation once SEP-1932 lands;
- richer workload identity, hardware attestation, or other sender-constraint mechanisms;
- deployment-specific evidence retention/privacy policy.
