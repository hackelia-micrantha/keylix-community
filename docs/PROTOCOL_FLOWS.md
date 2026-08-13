# Protocol Flows

These flows describe the v0.1 Keylix integration contract. Concrete APIs may evolve, but the trust transitions and security semantics are fixed by the ADRs and `docs/REQUIREMENTS.md`.

## 1. Token acquisition with DPoP

```text
Client                    Keylix                    Authorization Server
  |                          |                              |
  | token request context    |                              |
  |------------------------->|                              |
  |                          | select DpopSigner            |
  |                          | load AS nonce (optional)     |
  |                          | create fresh jti/iat         |
  |                          | sign ES256 proof             |
  |                          |----------------------------->|
  |                          | POST /token                  |
  |                          | DPoP: <proof>                |
  |                          |                              |
  |                          |<-----------------------------|
  |                          | token_type=DPoP              |
  |                          | access/refresh token state   |
  |                          | optional DPoP-Nonce          |
  |<-------------------------|                              |
  | bound token + key state  |                              |
```

In DPoP-required mode, a non-`DPoP` token type is rejected rather than silently becoming Bearer state.

## 2. Authorization-server nonce challenge

```text
Client/Keylix                         Authorization Server
     |                                        |
     | token request + proof A                |
     |--------------------------------------->|
     |                                        |
     |<---------------------------------------|
     | use_dpop_nonce + DPoP-Nonce: N1        |
     |                                        |
     | store N1 in AS namespace               |
     | generate proof B                       |
     | - N1                                   |
     | - new jti                              |
     | - fresh iat                            |
     |--------------------------------------->|
     |                                        |
     |<---------------------------------------|
     | token response / optional next nonce   |
```

Proof A is never reused. Authorization-server nonce state cannot be used as resource-server nonce state.

## 3. Protected-resource request

```text
Client                    Keylix                        Resource Server
  |                          |                                |
  | request + access token   |                                |
  |------------------------->|                                |
  |                          | compute ath                    |
  |                          | bind htm/normalized htu        |
  |                          | load RS nonce if present       |
  |                          | fresh jti/iat                  |
  |                          | sign ES256 proof               |
  |                          |------------------------------->|
  |                          | Authorization: DPoP <token>    |
  |                          | DPoP: <proof>                  |
```

Every HTTP attempt gets a new proof, including network/transient retries.

## 4. Resource-server verification and OAuth composition

The core proof verifier and OAuth token validator do not impersonate each other's trust responsibilities.

```text
incoming HTTP request
    |
    +-----------------------------------+
    |                                   |
    v                                   v
trusted transport adapter          host OAuth validator
- actual method                    - signature/introspection
- EffectiveRequestTarget           - issuer/audience/expiry
- exact access-token bytes         - host scope/policy checks
- raw DPoP proof                   - trusted cnf.jkt
    |                              - exact token correlation
    v                                   |
keylix-dpop                             |
- one DPoP header                      |
- strict compact JWS                   |
- typ = dpop+jwt                       |
- ES256 / EC P-256                     |
- public point + signature             |
- htm / normalized htu                 |
- iat ± policy                         |
- nonce when required                  |
- ath exact token                      |
- atomic replay                        |
    |                                   |
    v                                   |
VerifiedDpopProof                       |
    +----------------+------------------+
                     |
                     v
                keylix-oauth
          - validated metadata belongs
            to exact presented token
          - trusted cnf.jkt equals
            proof-key thumbprint
                     |
                     v
           VerifiedSenderBinding
                     |
                     v
          application authorization
```

A proof can therefore be cryptographically valid yet fail sender binding because the OAuth token is invalid, unbound, belongs to another key, or is not the exact token represented by the trusted validation result.

## 5. Resource-server nonce challenge

```text
Client/Keylix                           Resource Server
     |                                        |
     | protected request + proof A            |
     |--------------------------------------->|
     |                                        |
     |<---------------------------------------|
     | 401 / use_dpop_nonce                   |
     | DPoP-Nonce: R1                         |
     |                                        |
     | store R1 in RS namespace               |
     | create proof B                         |
     | - R1                                   |
     | - new jti                              |
     | - fresh iat                            |
     |--------------------------------------->|
```

Server nonce enforcement is opt-in, but after a challenge establishes a required nonce for its context, nonce-less/wrong-nonce requests cannot silently downgrade into acceptance.

A successful response may provide a replacement nonce for the next request.

## 6. Atomic replay race

Unsafe:

```text
Instance A                  Store                  Instance B
    | contains(K)?            |                        |
    |------------------------>|                        |
    | false                   |                        |
    |<------------------------|                        |
    |                         |<-----------------------|
    |                         | contains(K)?           |
    |                         |----------------------->|
    |                         | false                  |
    | insert(K)               |       insert(K)        |
```

Both requests can pass.

Required:

```text
Instance A                  Shared Store             Instance B
    | check_and_record(K,E)    |                        |
    |------------------------->|                        |
    | Fresh                    |<-----------------------|
    |<-------------------------| check_and_record(K,E)  |
    |                          |----------------------->|
    |                          | Replay                 |
```

Per ADR-0009:

```text
K = digest(proof_key_thumbprint, canonical_method, normalized_htu, jti)
E = iat + max_proof_age
```

`ath` is not in `K`, so changing access tokens cannot make a used proof identifier fresh again. A process-local store is not cluster-safe.

## 7. Proof freshness boundaries

Default policy:

```text
verifier now = T
accept if:
  iat >= T - 300s
  iat <= T + 300s
```

Examples:

```text
iat = T - 299s -> eligible subject to all other checks
iat = T + 299s -> eligible subject to all other checks
iat = T - 301s -> reject
iat = T + 301s -> reject
```

Deployments can tighten the window. Nonces can add stronger server-issued freshness.

## 8. Reverse-proxy target reconstruction

```text
Public client
    |
    | https://api.example.com/mcp
    v
Trusted proxy
    |
    | internal http://10.0.0.4:8080/mcp
    v
Application adapter
```

The proof `htu` represents the public/external target. The host adapter establishes the trusted external target using deployment configuration; `keylix-dpop` never decides whether arbitrary forwarding headers are trustworthy.

```text
trusted connection/server metadata
+ explicit proxy identity/config
+ selected supported forwarding metadata
-----------------------------------------
EffectiveRequestTarget
```

Both the trusted target and proof `htu` have query/fragment stripped and undergo the same ADR-0006 normalization before exact comparison.

## 9. Token validation mix-and-match defense

Unsafe composition:

```text
validate token A -> cnf.jkt = K1
present token B  -> ath proof for B
combine K1 + B   -> ambiguous / unsafe
```

Required composition correlates the validation result to the exact presented token:

```text
validate token A
 -> token fingerprint FA
 -> trusted cnf.jkt K1

present token B
 -> fingerprint FB

FA != FB -> reject before VerifiedSenderBinding
```

Then `ath(B)` and the verified proof key are checked independently.

## 10. Refresh-token and key continuity

```text
Authorization 1
    |
    +--> proof key K1
    +--> refresh token RT1 bound to K1

refresh(RT1, proof(K1)) -> allowed
refresh(RT1, proof(K2)) -> rejected/prevented
```

Local key rotation is not transparent while a bound refresh token remains active. Rotation requires a new authorization/token relationship or a server-defined migration mechanism.

## 11. MCP experimental SEP-1932 profile

While SEP-1932 remains draft:

```text
MCP client
    |
    | explicit matching DPoP profile
    v
keylix-mcp [experimental]
    |
    +--> token endpoint proof
    +--> AS/RS nonce handling
    +--> fresh HTTP proof
    v
Authorization: DPoP <token>
DPoP: <proof>
    |
    v
MCP HTTP server with matching draft profile
```

DPoP remains entirely at the HTTP authorization layer. No DPoP claims are injected into MCP JSON-RPC messages. A required sender-constrained session does not automatically resend as Bearer if the profile is unavailable or verification fails.

## 12. Safe evidence into Invokrum / Anthesis

```text
MCP request
    |
    v
Invokrum ingress
    +--> host OAuth validation
    +--> Keylix sender binding
    |
    v
InvocationContext
    +--> actor/workload identity
    +--> scopes/capability
    +--> VerifiedSenderBinding
    |
    +--> optional explicit SenderBindingEvidence
    |    - mechanism DPoP
    |    - optional public-key thumbprint
    |    - algorithm/profile
    |    - verification time/control outcomes
    |    - NO raw token/proof/nonce/jti/private key
    v
Anthesis policy / approval / provenance
    |
    v
MCP dispatch
```

Responsibilities remain distinct:

- **Keylix:** cryptographic sender constraint;
- **Invokrum:** invocation mediation/boundary;
- **Anthesis:** identity/policy/approval/evidence/provenance.

The key thumbprint is a stable correlator and is emitted only through the explicit evidence interface when the host needs key-level attribution; normal logs/metric labels omit it.
