# Architecture

Keylix uses a layered, ports-and-adapters architecture around a deliberately small DPoP domain core.

See also:

- [Design baseline](DESIGN.md)
- [Security architecture](SECURITY_ARCHITECTURE.md)
- [Integration architecture](INTEGRATIONS.md)
- [Protocol flows](PROTOCOL_FLOWS.md)
- [Threat model](THREAT_MODEL.md)
- [Requirements/test traceability](REQUIREMENTS.md)
- [Architecture decisions](adr/README.md)

## System boundary

Keylix owns **cryptographic sender binding**.

It does not own application identity, OAuth token issuance, issuer/audience/scope policy, MCP tool authorization, approval, or governance.

```text
OAuth / IdP
    |
    | token + trusted validation result
    v
+-----------------------------+
| Keylix                      |
| keys/JWK/thumbprints        |
| DPoP proof + verification   |
| nonce/replay contracts      |
| OAuth composition/adapters  |
| MCP HTTP adapter            |
+--------------+--------------+
               |
               | VerifiedSenderBinding
               v
+-----------------------------+
| application / gateway       |
| identity + authorization    |
| policy + governance         |
+-----------------------------+
```

## Dependency rule

```text
                +--------------------+
                | keylix-conformance |
                +----------+---------+
                           |
                           | black-box/public API
                           v
+-------------+     +-------------+     +--------------+     +------------+
| keylix-core |<----| keylix-dpop |<----| keylix-oauth |<----| keylix-mcp |
+-------------+     +-------------+     +--------------+     +------------+
```

Dependencies point inward.

### `keylix-core`

Owns protocol-independent value types and primitives:

- validated public EC/P-256 JWK representation;
- RFC 7638 thumbprints;
- sensitive-value wrappers;
- signing-capability abstraction and shared public-key types;
- common errors/value objects that do not depend on OAuth providers or MCP.

It must not contain HTTP client logic, OAuth flows, or MCP types.

### `keylix-dpop`

Owns RFC 9449 proof semantics:

- narrow compact-JWS proof construction/parsing;
- strict ES256/P-256 proof verification;
- HTTP method/target binding;
- `ath` calculation/validation against exact presented token bytes;
- proof freshness policy;
- nonce/replay ports and checks;
- `UnverifiedDpopProof` and `VerifiedDpopProof`.

It does **not** decide OAuth token validity and does not trust/resolve `cnf.jkt` from arbitrary tokens. It must not depend on an MCP SDK.

### `keylix-oauth`

Owns OAuth composition around the DPoP core:

- token-endpoint proof decoration;
- `token_type=DPoP` enforcement;
- AS/RS nonce challenge handling;
- protected-resource request decoration;
- adapters from trusted JWT/introspection/token-validation results;
- exact-token correlation between validation metadata and presented token;
- proof-key vs trusted `cnf.jkt` comparison;
- production of `VerifiedSenderBinding`;
- refresh-token/proof-key continuity;
- optional authorization-code `dpop_jkt` helpers.

It does not become a general OAuth/OIDC/JWT validation framework.

### `keylix-mcp`

Owns MCP HTTP integration only:

- bridge to official Rust SDK HTTP/auth extension points;
- pre-dispatch sender-binding composition;
- client HTTP proof decoration;
- draft/stable profile compatibility behavior;
- propagation of `VerifiedSenderBinding` through request context.

MCP DPoP support remains experimental/profile-based while SEP-1932 is unstable.

### `keylix-conformance`

Owns externally observable standards behavior:

- RFC vectors;
- `KX-*` positive/negative requirement coverage;
- adversarial parser cases;
- replay/nonce behavior tests;
- interoperability fixtures;
- fuzz corpora/targets.

It tests public behavior rather than becoming a privileged implementation helper.

## Domain pipeline

```text
wire input
   |
   v
UnverifiedDpopProof
   |
   | RFC 9449 proof verification
   v
VerifiedDpopProof
   |
   | + trusted validation result for exact token
   | + proof-key / cnf.jkt comparison
   v
VerifiedSenderBinding
```

The first transition belongs to `keylix-dpop`; the second belongs to `keylix-oauth`.

Downstream consumers should not need raw proof/token material once the verified binding/evidence has been produced.

## Trusted inputs and ports

### Trusted transport context

The DPoP verifier needs:

```text
EffectiveRequest
- method
- EffectiveRequestTarget
- presented access-token bytes (when applicable)
```

Reverse-proxy trust decisions happen in an adapter before this value reaches `keylix-dpop` (ADR-0006).

### DPoP-side ports

```text
Clock
ProofIdGenerator
DpopSigner
NonceStore / NonceValidator
ReplayStore
```

These interfaces permit deterministic tests, non-extractable signing backends, and replaceable replay/nonce infrastructure without changing RFC semantics.

### OAuth-side validation boundary

`keylix-oauth` consumes a host-provided trusted token-validation result correlated to the exact presented token (ADR-0007). JWT signature validation, authenticated introspection, issuer/audience checks, expiry, scopes, and policy remain host responsibilities.

## Security-critical state

### Replay state

Strict replay protection requires:

```text
check_and_record(replay_key, expires_at)
    -> Fresh | Replay | StoreFailure
```

Per ADR-0009, replay identity is derived from proof key thumbprint + canonical method + normalized `htu` + `jti`; logical expiry is `iat + max_proof_age`.

A backend's atomicity and consistency guarantees are part of its security contract. Process-local state is not cluster-safe.

### Nonce state

Nonce state is partitioned by issuing server and role:

```text
authorization server A != resource server A != authorization server B
```

Retries use a fresh proof/new `jti`. Server enforcement is opt-in but cannot downgrade after a challenge establishes nonce use for its context.

### Key state

A public client's bound refresh token may require continued use of the same DPoP key. Key identity is part of OAuth session/token state, not a freely rotating implementation detail.

## Integration result

`VerifiedSenderBinding` is a compact sender-constraint result, not a generic authenticated principal. Conceptually it can expose:

```text
VerifiedSenderBinding
- mechanism = DPoP
- verified public-key thumbprint
- verification time/context
- token binding verified
- nonce/replay policy outcome
```

Detailed target/proof metadata belongs only where necessary, and safe observability/evidence follows ADR-0011.

The host combines the binding with:

```text
validated issuer/audience/scopes
+ user/client/workload identity
+ application policy
+ approvals/governance
```

## MCP boundary

DPoP applies to the **HTTP transport request**, not the MCP JSON-RPC body.

```text
MCP operation
     |
     v
MCP HTTP transport
     |
     v
keylix-mcp -> keylix-oauth -> keylix-dpop
     |
     v
VerifiedSenderBinding before MCP dispatch
```

No DPoP claims are injected into MCP JSON-RPC payloads.

## Future mechanisms

Do not generalize the public API around a universal `SenderConstraint` trait until another mechanism has concrete requirements.

DPoP should first establish a complete conformant implementation. If mTLS, workload identity, hardware attestation, or another mechanism later shares a genuine abstraction, extract it from at least two working implementations rather than designing it speculatively.
