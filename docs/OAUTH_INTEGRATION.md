# OAuth DPoP Integration

`keylix-oauth` composes strict DPoP proof verification with OAuth validation that the host application has already performed. It also provides transport-agnostic helpers for DPoP-required token and protected-resource requests.

## Trust boundary

Keylix does not validate JWT signatures, issuer, audience, expiry, scopes, authorization policy, or introspection endpoint authenticity. The host owns those decisions.

After the host validates the **exact presented token**, it adapts that trusted result into one of the explicit constructors:

```rust
HostValidatedToken::from_host_validated_jwt(token_bytes, trusted_cnf_jkt)
HostValidatedToken::from_host_authenticated_introspection(token_bytes, active, trusted_cnf_jkt)
HostValidatedToken::from_equivalent_host_validator(token_bytes, trusted_cnf_jkt)
```

Calling one of these constructors is an attestation by the host integration that the corresponding validation has already succeeded. Raw decoded JWT claims do not have a separate Keylix path to `VerifiedSenderBinding`.

`HostValidatedToken` stores an opaque SHA-256 fingerprint of the exact token bytes plus the trusted `cnf.jkt`. Ordinary diagnostics expose neither value.

## Sender-binding composition

The protected-resource integration should first verify the DPoP proof through `keylix-dpop`, using the exact access-token bytes in `DpopRequest`. That produces `VerifiedDpopProof` only after signature, request binding, freshness, `ath`, nonce, and replay checks required by the configured verifier policy succeed.

`compose_sender_binding` then requires all of the following:

1. the DPoP proof verified `ath` against an exact access token;
2. the token bytes being presented have the same SHA-256 fingerprint as the host-validated result;
3. the host-validated token contains a trusted DPoP `cnf.jkt`;
4. that `jkt` equals the verified proof-key thumbprint.

Only then is `VerifiedSenderBinding` produced. This prevents validation metadata for token A from being accidentally or maliciously paired with token B, and it prevents an attacker-controlled decoded `cnf` value from becoming trusted sender identity.

## DPoP-required client mode

`DpopRequiredClient` is an injected, transport-independent request decorator. The caller supplies:

- a `DpopSigner` capability;
- a `Clock`;
- a `ProofIdGenerator`;
- a `ClientNonceStore`.

The host still owns HTTP execution, response parsing, OAuth error interpretation, TLS, and application policy.

A token-endpoint attempt is created with `token_request`. Each call builds a new proof and `jti`; the returned `TokenEndpointDpop` represents that single HTTP attempt and is intentionally not cloneable.

When the token response is accepted through `accept_token_response`, strict mode requires `token_type=DPoP`. Bearer and other token types fail closed. The resulting access and optional refresh tokens are pinned to the current proof-key thumbprint.

A protected-resource attempt is created with `protected_resource`. It emits explicit credential-bearing values for:

```text
Authorization: DPoP <access-token>
DPoP: <fresh-proof>
```

There is no Bearer fallback path in this client type. Each call creates fresh proof material, so callers should retry by invoking the decorator again rather than caching or replaying a previously decorated request.

## Nonce challenge and retry

Authorization-server and resource-server nonce state use distinct `NonceContext` namespaces. A nonce learned from one server or protocol role is not reused for another.

For each logical HTTP operation that can automatically respond to `use_dpop_nonce`, create a fresh retry budget:

```rust
let mut retry = NonceRetryBudget::single_retry();
```

When the host recognizes a nonce challenge, call:

```rust
client.record_nonce_challenge(&context, &nonce, &mut retry)?;
```

The v0.1 budget permits one automatic nonce-triggered retry. A second challenge for the same logical operation returns `NonceRetryLimitExceeded`. The budget is consumed before nonce-state mutation, so an exhausted retry cannot silently update state and continue looping.

The retry itself is produced by calling `token_request` or `protected_resource` again, which creates a fresh proof and `jti` containing the stored nonce.

A `DPoP-Nonce` received on a successful response can be saved with `record_success_nonce`. Passing `None` preserves an already-established nonce requirement rather than silently downgrading the context.

## Refresh-token key continuity

A refresh token accepted in a DPoP token set is pinned to the proof key active at acceptance time. `refresh_token_request` checks that the current signer still has that thumbprint before producing a token-endpoint proof.

A deliberate key rotation therefore requires replacing the OAuth relationship through application-defined lifecycle logic. Keylix does not silently move a bound refresh relationship from key K1 to K2.

The same continuity check applies when using a bound access token for a protected-resource request.

## Credential-bearing accessors

Token strings, proofs, token fingerprints, confirmation thumbprints, and nonces are redacted from ordinary `Debug` output.

Explicit accessors such as `as_secret_value`, `authorization_header_value`, `dpop_header_value`, and `DpopNonce::as_header_value` are credential-bearing integration surfaces. Applications should use them only to construct the intended protocol request and should not log or attach them to ordinary telemetry.

## Non-scope

`keylix-oauth` deliberately does not own:

- OpenID Connect login or redirect flows;
- JWT/JWKS discovery or signature policy;
- issuer/audience/scope/application authorization;
- introspection transport authentication;
- HTTP retries or networking;
- MCP JSON-RPC behavior.

Those remain host or downstream adapter responsibilities. MCP-specific DPoP behavior belongs in `keylix-mcp` and remains a separate profile claim.