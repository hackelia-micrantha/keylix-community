# Design Review Checklist

**Status:** initial v0.1 design gate complete. Implementation may proceed against the accepted ADRs and [`REQUIREMENTS.md`](REQUIREMENTS.md); changes to these security boundaries require deliberate review.

## Accepted architecture constraints

- [x] DPoP core remains protocol-independent (ADR-0001).
- [x] DPoP-required flows never silently downgrade to Bearer (ADR-0002).
- [x] Strict replay prevention uses an atomic state operation (ADR-0003).
- [x] Private keys are modeled primarily as signing capabilities, not extractable bytes (ADR-0004).
- [x] v0.1 algorithm profile is ES256 / EC P-256 only (ADR-0005).
- [x] `htu` verification consumes an explicit trusted effective request target; forwarding metadata is never trusted by default (ADR-0006).
- [x] OAuth sender binding consumes confirmation material only from validation of the exact presented token (ADR-0007).
- [x] MCP DPoP remains an explicit draft/profile adapter while SEP-1932 is unstable (ADR-0008).
- [x] Default proof freshness is ±300 seconds; atomic replay identity/lifetime and AS/RS nonce behavior are defined (ADR-0009).
- [x] `aws-lc-rs` is the default native ES256 crypto backend; DPoP owns narrow compact-JWS framing rather than generic JWT policy dispatch (ADR-0010).
- [x] Ordinary telemetry excludes credential material and raw key thumbprints; stable key identifiers are exposed only through explicit security evidence (ADR-0011).

## Security review outcomes

- [x] Parsed/untrusted proof state is distinct from `VerifiedDpopProof` and `VerifiedSenderBinding`.
- [x] Arbitrary decoded `cnf.jkt` cannot satisfy the normal OAuth composition boundary.
- [x] All retries, including nonce retries, require a fresh proof and `jti`.
- [x] Replay/nonce/backend failure behavior is fail-closed where the control is required.
- [x] Proxy/header metadata cannot select `htu` unless an adapter explicitly establishes a trusted proxy boundary.
- [x] Private key/token/proof material is excluded from ordinary diagnostics by design; implementation tests remain required.
- [x] Accepted algorithm/key types are explicit and cannot expand through untrusted `alg` metadata.
- [x] Cluster-safe replay enforcement requires shared atomic state; process-local state is labeled accordingly.
- [x] Bound refresh-token/key continuity is a lifecycle invariant rather than transparent key rotation.

## Integration review outcomes

- [x] `keylix-oauth` composes with host OAuth validators instead of becoming a general authorization server/JWT validator.
- [x] Keylix does not own authorization redirects, OIDC login, issuer/audience policy, scopes, entitlements, or application authorization.
- [x] Effective external URI resolution is outside `keylix-dpop` framework-specific logic.
- [x] `keylix-mcp` is HTTP-transport/profile focused; DPoP is not embedded in MCP JSON-RPC messages.
- [x] MCP DPoP is explicitly experimental while SEP-1932 remains draft and reference SDK support is absent.
- [x] Downstream gateways/governance systems consume compact verified binding/evidence rather than proof/token/private-key material.

## Conformance readiness

- [x] [`REQUIREMENTS.md`](REQUIREMENTS.md) maps RFC 9449 proof validation/construction, RFC 7638 thumbprints, OAuth composition, MCP draft-profile behavior, and all 31 threat-model invariants to positive and negative/adversarial test obligations.

## Implementation gate

Implementation PRs should:

1. reference the affected `KX-*` requirement IDs;
2. preserve the accepted ADR boundaries;
3. add the positive and negative/adversarial tests for the implemented requirement;
4. update requirement status to `Implemented` or `Covered` only when the corresponding behavior/tests exist;
5. add or supersede an ADR if implementation evidence shows that a security decision must change.