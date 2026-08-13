# Integration Architecture

Keylix integrates with existing OAuth, HTTP, MCP, key-storage, replay/nonce, and policy systems without taking ownership of them.

## Integration principles

1. **Adapter, not framework takeover.** Decorate/verify around an existing OAuth implementation rather than reimplement OAuth/OIDC end to end.
2. **Exact validated token boundary.** Trusted `cnf.jkt` data comes from validation of the exact token presented to DPoP verification (ADR-0007).
3. **Fresh proof per HTTP attempt.** Every retry creates a new proof/new `jti`, including nonce and transient retries.
4. **No implicit downgrade.** DPoP-required flows never silently fall back to Bearer.
5. **MCP is downstream.** MCP-specific behavior remains in `keylix-mcp`; RFC 9449 stays independently usable.
6. **Opaque signing.** Integrations depend on signing capability, not extractable private-key bytes.
7. **Safe evidence.** Ordinary telemetry and explicit security evidence are separate interfaces (ADR-0011).

## OAuth client integration

```text
application / OAuth library
        |
        | token request context
        v
keylix-oauth
        |
        +--> DpopSigner
        +--> AS nonce state
        +--> fresh jti / iat
        +--> keylix-dpop proof builder
        |
        v
Authorization Server
        |
        +--> token_type=DPoP
        +--> bound access/refresh token state
        +--> optional DPoP-Nonce
```

Keylix does not own browser redirects, state validation, PKCE generation, OIDC login UX, issuer discovery policy, or general token issuance.

### DPoP-required token contract

In required mode:

- a fresh DPoP proof is attached to the token request;
- an AS `use_dpop_nonce` challenge is retried with the supplied nonce and a new proof/new `jti`;
- a token response whose token type is not `DPoP` is rejected/discarded;
- the token state records the proof-key identity needed for refresh-token continuity.

Bearer remains a separate explicit application mode, never an automatic retry path.

## OAuth protected-resource client

Every protected HTTP attempt is decorated immediately before transmission:

```text
request(method, effective URI) + access token
             |
             v
keylix-oauth / keylix-dpop
- calculate ath from exact token bytes
- bind htm / normalized htu
- load RS nonce for this issuer if present
- create fresh iat / jti
- sign ES256 proof
             |
             v
Authorization: DPoP <token>
DPoP: <proof>
```

Retry middleware sits **outside** proof generation:

```text
attempt 1 -> proof A -> retryable response
attempt 2 -> proof B -> send again
```

A fully decorated request containing a DPoP proof must not be cached/reused.

## OAuth resource-server composition

The DPoP and OAuth-validity paths remain separate until their trusted outputs are composed:

```text
incoming request
   |
   +----------------------------+
   |                            |
   v                            v
host OAuth validator       trusted HTTP adapter
- signature/introspection  - method
- issuer/audience/expiry    - EffectiveRequestTarget
- scopes/policy as host     - raw DPoP proof
- trusted cnf.jkt           - exact token bytes
- exact token correlation        |
   |                             v
   |                        keylix-dpop
   |                        - proof/ES256
   |                        - htm/htu/iat
   |                        - nonce/replay
   |                        - ath exact token
   |                             |
   |                       VerifiedDpopProof
   +--------------+--------------+
                  |
                  v
             keylix-oauth
       exact-token correlation
       proof-key == trusted cnf.jkt
                  |
                  v
        VerifiedSenderBinding
                  |
                  v
        application authorization
```

Conceptually, the host validation adapter produces a trusted structure containing:

```text
ValidatedTokenBinding
- token_fingerprint   # correlation to exact token bytes
- jwk_thumbprint      # trusted cnf.jkt/equivalent
```

The exact type may carry additional non-secret context required for safe adapter composition, but a raw decoded JWT payload or arbitrary caller `jkt` string cannot satisfy this boundary.

## JWT access-token adapter

The host JWT library first performs its normal signature/issuer/audience/expiry validation. Only then may the Keylix adapter extract the trusted DPoP confirmation thumbprint and correlate it to the exact token bytes.

Keylix does not become a general JWT validator.

## Opaque-token / introspection adapter

An authenticated, active introspection response may provide `cnf.jkt`. The adapter maps that trusted response plus exact token correlation into `ValidatedTokenBinding`.

Keylix does not own introspection client authentication, caching, or the authorization server's token-active decision.

## Authorization-code binding (`dpop_jkt`)

RFC 9449's optional authorization-code binding belongs in an OAuth client adapter, not `keylix-dpop` core. If enabled, the authorization request uses the same proof-key thumbprint that must later be used at the token endpoint.

This helper can be added when a real integration needs it; it does not alter core proof validation.

## Key-storage integrations

The signer boundary is capability-based:

```text
DpopSigner
├── AwsLcSoftwareP256Signer     # reference/native
├── OSKeyStoreSigner
├── PKCS11Signer
├── TPMSigner
├── HsmSigner
└── External/KmsSigner
```

Each implementation exposes the corresponding public P-256 JWK and returns the RFC 7518 fixed 64-byte ES256 signature. The core proof builder never requires private-key extraction.

Remote signers must account for latency, availability, rate limits, and authorization because every HTTP attempt needs a fresh signature.

## Replay-store integrations

```text
ReplayStore
├── InMemoryReplayStore
├── Redis-like adapter
├── SQL adapter with atomic uniqueness semantics
└── application-provided implementation
```

Security-semantic operation:

```text
check_and_record(replay_key, expires_at)
    -> Fresh | Replay | StoreFailure
```

Per ADR-0009, the replay identity derives from proof key thumbprint + canonical method + normalized `htu` + `jti`; `ath` is excluded. The backend documents the topology over which atomicity is guaranteed.

A best-effort local cache is not equivalent to cluster-safe strict replay prevention.

## Nonce-state integrations

Client nonce state is partitioned by issuing server **and role**:

```text
NonceKey
- authorization_server | resource_server
- issuer/origin/resource identifier
- optional client/session partition
```

Client v0.1 handles both AS and RS nonce challenges. Server nonce enforcement is opt-in. Once a challenge establishes nonce use, wrong/missing nonce cannot silently downgrade into acceptance.

## HTTP stack integrations

Core request semantics should use small `http`-level/value-object boundaries rather than one concrete client/server stack.

Convenience adapters may target:

- `reqwest` middleware;
- `hyper` client/server;
- Tower layers/services;
- Axum extractors/middleware;
- other frameworks through `EffectiveRequestTarget` + method context.

The transport adapter owns effective external URI construction and any trusted-proxy policy. `keylix-dpop` never parses forwarding headers directly.

## MCP client integration

`keylix-mcp` wraps HTTP transport/auth extension points rather than modifying JSON-RPC messages:

```text
MCP client
   |
   v
rmcp HTTP transport
   |
   v
keylix-mcp [experimental SEP-1932 profile]
   |
   v
keylix-oauth -> keylix-dpop
   |
   v
MCP HTTP server
```

A proof is generated per HTTP request/attempt, not per tool invocation or session.

### Current profile status

The implemented adapter targets the explicit `sep-1932-draft` profile, `rmcp` 3.0.1, and MCP 2026-07-28. SEP-1932 remains Draft, so the adapter is intentionally experimental and version-aware rather than represented as stable MCP conformance.

The client integration wraps the official `rmcp::StreamableHttpClient` extension point. It attaches `Authorization: DPoP <token>` plus a fresh proof to each HTTP attempt, supports separately scoped AS/RS nonce state through `keylix-oauth`, rejects conflicting Authorization/DPoP headers before dispatch, and never converts a required DPoP flow into Bearer. The token-endpoint integration verifies the DPoP proof key used to establish the bound-token relationship.

The server integration accepts a host-constructed trusted `EffectiveRequestTarget` plus an already validated exact-token result, verifies proof/request/nonce/replay semantics, composes trusted `cnf.jkt` with the verified proof key, and returns only `VerifiedSenderBinding` before MCP method dispatch. Raw proof/token material is not injected into JSON-RPC messages or downstream dispatch context.

MCP-specific behavior remains downstream of `keylix-oauth` and `keylix-dpop`; no MCP SDK fork is required.

## MCP server integration

```text
incoming MCP HTTP request
       |
       v
HTTP/framework adapter + host OAuth validator
       |
       v
keylix-dpop -> VerifiedDpopProof
       |
       v
keylix-oauth -> VerifiedSenderBinding
       |
       v
MCP dispatch
```

Sender binding is established **before** MCP method/tool dispatch. Downstream context receives the verified binding/evidence, not the raw proof.

## Invokrum integration

Invokrum can consume Keylix at its invocation boundary:

```text
MCP caller
   |
   v
Invokrum ingress
   +--> host OAuth validation
   +--> Keylix sender binding
   |
   v
InvocationContext
   |
   v
routing / mediation / capability handling
```

Invokrum does not own DPoP crypto, proof parsing, nonce, or replay primitives.

## Anthesis integration

Anthesis consumes sender binding as one evidence input alongside its actor/policy/approval model:

```text
actor/workload identity
+ validated OAuth context
+ optional Keylix SenderBindingEvidence
+ capability
+ policy decision
+ approval
-------------------------
Anthesis evidence/provenance
```

Per ADR-0011, the explicit evidence sink may include the verified public-key thumbprint when key-level attribution is desired. It never contains private keys, raw tokens, proofs, nonces, or raw `jti`. Ordinary logs do not emit raw `jkt` by default.

## Workload identity

DPoP and workload identity remain distinct:

- DPoP: does the presenter possess the key bound to this credential?
- workload identity: what workload/process/environment is this?

A host can correlate a DPoP signer with workload identity, but Keylix does not claim that possession alone proves workload identity or attestation.

## Observability integrations

Normal telemetry exposes bounded structured outcomes such as:

```text
keylix.verify.result = success | invalid_signature | replay | ...
keylix.verify.algorithm = ES256
keylix.verify.proof_age = bounded bucket
keylix.replay.backend = in_memory | distributed | custom
```

Do not use tokens, proofs, raw nonces, raw `jti`, arbitrary claims, or raw key thumbprints as ordinary log fields/metric labels. Explicit audit/provenance evidence uses the separate ADR-0011 interface.

## Integration maturity

### v0.1

- RFC 7638 / RFC 9449 core and `KX-*` conformance;
- generic effective HTTP request boundary;
- OAuth client/resource-server composition contracts;
- reference in-memory replay/nonce state;
- reference native software signer;
- experimental Rust MCP SEP-1932 adapter.

### Later

- Tower/Axum/Reqwest convenience integrations;
- concrete durable/distributed replay backends;
- OS/HSM/TPM/KMS signer adapters;
- stable official MCP DPoP integration once SEP-1932 stabilizes;
- optional authorization-code binding helper;
- alternate/WASM crypto backend;
- cross-language bindings after the Rust API/security contract stabilizes.
