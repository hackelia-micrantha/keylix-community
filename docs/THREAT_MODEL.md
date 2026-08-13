# Threat Model

**Status:** v0.1 design baseline. Security-sensitive implementation must map code/tests back to these invariants and [`REQUIREMENTS.md`](REQUIREMENTS.md).

See [Security Architecture](SECURITY_ARCHITECTURE.md) for control placement and [Protocol Flows](PROTOCOL_FLOWS.md) for request sequences.

## Scope

This threat model covers Keylix's DPoP proof construction/verification, JWK/thumbprint handling, nonce/replay behavior, and OAuth/MCP HTTP adapters.

It does not attempt to threat-model an entire OAuth authorization server, identity provider, MCP application, browser, host OS, or governance system.

## Security objective

For DPoP-required protected-resource access, Keylix should establish that:

1. the presented proof is a structurally valid RFC 9449 DPoP proof;
2. it was signed by the private key corresponding to the public JWK in the proof;
3. that public key is the key to which the validated access token is bound;
4. the proof is bound to the current HTTP method and target URI;
5. the proof is bound to the specific access-token value;
6. freshness, nonce, and replay requirements are satisfied;
7. success is represented only as proof-of-possession evidence and is not confused with broader authorization.

## Assets

- DPoP private keys
- access and refresh tokens
- authorization codes/PKCE state when passed through client adapters
- DPoP proofs and server nonces
- replay-detection state
- validated `cnf.jkt` token confirmation values
- trusted effective HTTP request context
- `VerifiedSenderBinding` values consumed by callers

## Trust boundaries

### Client boundary

Trusted:

- Keylix code and selected cryptographic implementation;
- configured signing-key backend;
- configured clock/random source;
- nonce state backend.

Untrusted or partially trusted:

- authorization/resource server responses until protocol validation;
- network;
- application inputs;
- code executing elsewhere in the client process (DPoP cannot fully defend against runtime compromise).

### Server boundary

Trusted:

- Keylix verifier;
- validated OAuth token result supplied by a trusted token validator;
- configured clock;
- replay/nonce backend according to its documented consistency model;
- effective URI/method supplied by a correctly configured transport/trusted-proxy adapter.

Untrusted:

- raw HTTP headers/body;
- DPoP proof/JWT/JWK;
- access token before OAuth validation;
- forwarding headers unless the deployment adapter has established their trusted source.

## Attacker capabilities

Assume an attacker may:

- obtain an OAuth access token without obtaining the DPoP private key;
- obtain a refresh token and try to redeem it with a different proof key;
- observe/capture previously valid DPoP proofs;
- control request method, target URI, headers, and malformed JWT/JWK input at a resource-server boundary;
- send multiple DPoP headers or syntactically ambiguous input;
- race duplicate requests across concurrent verifier instances;
- influence clock skew and request timing within operational bounds;
- pre-generate proofs when the legitimate key is temporarily available;
- attempt algorithm-confusion, signed-JWT swapping, key-substitution, parser-differential, URI-normalization, token-substitution, nonce-downgrade, and replay attacks;
- inject spoofed `Forwarded`/`X-Forwarded-*` headers when proxy trust is misconfigured;
- attempt memory exhaustion through oversized/high-cardinality `jti` values;
- trigger replay/nonce backend outages;
- read ordinary logs/metrics;
- compromise an upstream/downstream component without necessarily compromising the Keylix process;
- run malicious code in the client runtime and invoke its signing capability while it is online.

## Security invariants

### Proof structure and JOSE

1. No request is accepted with more than one `DPoP` header.
2. The header value contains one well-formed JWT.
3. Required claims/header parameters are present.
4. `typ` is exactly `dpop+jwt`.
5. `alg` is asymmetric, supported, and explicitly allowed by local policy; `none` and MAC algorithms are rejected.
6. The proof `jwk` contains public key material only.
7. The JWS signature verifies using that public key.
8. Untrusted JOSE metadata cannot cause algorithm-policy expansion.

### Request binding

9. `htm` matches the actual HTTP method.
10. `htu` matches the trusted effective request target after RFC 9449-compatible normalization and after query/fragment are excluded.
11. Effective external URI reconstruction never trusts arbitrary forwarding headers by default.

### Token binding

12. For protected-resource requests, `ath` matches SHA-256 over the presented access-token value as specified by RFC 9449.
13. The RFC 7638 thumbprint of the proof public key equals the `cnf.jkt` from an already validated token/introspection result.
14. Keylix never trusts confirmation material obtained only by decoding an unvalidated access token.

### Freshness, nonce, replay

15. Accepted proofs fall within an explicitly configured freshness/skew policy.
16. If the relevant server has required/provided a nonce, the proof includes an acceptable matching nonce.
17. A server does not silently downgrade to accepting nonce-less proofs after establishing nonce use.
18. A retry generates a new proof/new `jti`, including nonce retries and transient HTTP retries.
19. Strict replay prevention uses an atomic check-and-record operation.
20. A process-local replay backend is not represented as cluster-safe.
21. Replay-state failure fails closed when strict replay enforcement is configured.
22. Accepted `jti` values are size-bounded or safely digested for storage.

### Key custody and lifecycle

23. The primary private-key API is signing-capability-based; raw extraction is not required.
24. Private keys/tokens do not appear in ordinary logs, errors, debug output, or metrics.
25. Refresh-token/key continuity is preserved for public clients; an active key-bound refresh-token relationship is not transparently moved to a new local key.

### Downgrade resistance

26. A DPoP-required token flow rejects a non-`DPoP` token type.
27. A DPoP-required protected-resource/MCP flow does not silently retry as Bearer.
28. Backend/nonce/replay failures do not silently turn off sender constraint.

### Result semantics

29. Parsing a proof cannot produce a verified sender binding.
30. A successful DPoP verification is not represented as authentication, scope authorization, workload identity, or policy approval.
31. Downstream code can consume a compact verified binding without needing raw proof/token material.

## Threats and mitigations

| Threat | Primary mitigation |
| --- | --- |
| stolen access token | token bound to proof public key + fresh DPoP proof |
| stolen proof replayed at another endpoint | `htm` + `htu` binding |
| stolen proof replayed at same endpoint | freshness + atomic `jti` replay state; nonce where configured |
| token substituted under captured proof | `ath` check |
| attacker-controlled proof key paired with victim token | `cnf.jkt` vs proof JWK thumbprint |
| signed JWT used as a DPoP proof | `typ=dpop+jwt` validation |
| algorithm confusion | explicit asymmetric allow-list + key/alg compatibility |
| private JWK smuggled in proof | reject private JWK parameters |
| nonce downgrade | once required/provided, nonce-less proof rejected |
| proof pre-generation | short acceptance windows + server-provided nonces for higher assurance |
| reverse-proxy host/scheme spoofing | trusted effective-URI adapter; no default trust of forwarding headers |
| replay race across replicas | atomic shared state or documented equivalent topology guarantee |
| replay-store DoS | bounded `jti`, TTL, capacity controls, digested keys |
| token/key leakage via diagnostics | sensitive-value redaction and safe observability schema |
| malicious code in client runtime | out of full scope; non-extractable key reduces exfiltration but cannot prevent live signing abuse |
| request body tampering | TLS/application integrity controls; DPoP does not sign body/general headers |

## Explicit non-goals

DPoP/Keylix does not replace:

- TLS;
- OAuth token signature/introspection validation;
- issuer/audience validation;
- scopes/entitlements;
- client authentication;
- application authorization;
- workload identity/attestation;
- host/process compromise defenses;
- MCP tool-level policy;
- human approval or governance;
- request-body integrity/signing.

## Failure-mode policy

Security-sensitive state failures must be distinguishable from invalid-client input.

Examples:

```text
ReplayDetected        -> reject request
ReplayBackendFailure  -> reject in strict replay mode + operational signal
NonceMismatch         -> protocol challenge/error as appropriate
InvalidProof          -> protocol-compliant authentication error
TokenBindingMismatch  -> reject request
```

Avoid retry storms and do not expose sufficiently detailed errors to turn verification behavior into a useful oracle beyond protocol requirements.

## Resolved v0.1 design decisions

The initial security decisions are recorded as ADRs rather than delegated to library defaults:

- algorithm/key policy: ES256 / EC P-256 only — ADR-0005;
- effective-target normalization and trusted-proxy boundary — ADR-0006;
- validated exact-token binding composition — ADR-0007;
- MCP DPoP as an experimental SEP-1932 profile — ADR-0008;
- ±300-second default freshness, atomic replay identity/lifetime, and AS/RS nonce behavior — ADR-0009;
- `aws-lc-rs` default native crypto backend and narrow compact-JWS handling — ADR-0010;
- safe diagnostics and explicit opt-in security evidence for stable key identifiers — ADR-0011.

Normative implementation and test traceability is maintained in [`REQUIREMENTS.md`](REQUIREMENTS.md).

## Future evolution, not v0.1 blockers

The following may require new/superseding ADRs as the ecosystem evolves:

- additional DPoP signing algorithms or alternate/WASM crypto backends;
- framework-specific trusted-proxy helpers;
- additional distributed replay/nonce backends;
- a stabilized MCP DPoP extension/profile after SEP-1932 lands;
- richer workload identity or hardware attestation mechanisms layered above/beside DPoP;
- deployment-specific evidence retention/privacy requirements.
