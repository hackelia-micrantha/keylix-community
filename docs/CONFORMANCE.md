# Conformance and Adversarial Testing

Keylix treats externally observable standards and security behavior as a first-class deliverable. The deterministic suite keeps RFC/OAuth claims separate from experimental MCP profile claims.

## Deterministic RFC/OAuth suite

Run the RFC/security conformance crate directly with:

```bash
cargo test --locked -p keylix-conformance
```

The repository's normal CI runs this suite through the workspace test gate together with formatting, strict Clippy, and rustdoc checks.

Conformance tests prefer public Keylix APIs. This keeps the suite useful as a downstream contract and reduces the chance that tests pass only because they can observe private implementation details.

Test names and assertion messages include the relevant `KX-*` requirement identifiers where practical so a failure points back to [`REQUIREMENTS.md`](REQUIREMENTS.md).

## Current deterministic RFC/OAuth coverage

The suite currently exercises:

- RFC 7638 P-256 JWK thumbprint vectors and identity invariants;
- duplicate/private/unsupported/non-canonical public-JWK rejection;
- RFC 9449 compact-JWS malformed input handling;
- independent ES256 DPoP signature verification;
- request-target normalization, rejection, and idempotence;
- method/request binding round trips;
- replay concurrency and fail-closed backend behavior;
- AS/RS nonce namespace isolation and successful-response rotation;
- exact-token OAuth validation correlation and trusted `cnf.jkt` composition;
- strict DPoP token-type and no-Bearer-downgrade behavior;
- DPoP protected-resource authorization and fresh proof construction;
- refresh-token proof-key continuity;
- fresh, scoped, single-retry-bounded OAuth nonce handling;
- ordinary diagnostic surfaces for credential leakage;
- deterministic property-style sweeps across generated P-256 identities and request bindings.

This suite supplements crate-local tests. A requirement is marked `Covered` only when the behavior stated by the requirement is actually exercised; the existence of a nearby primitive is not sufficient.

## MCP SEP-1932 draft-profile suite

MCP coverage is intentionally separate from the RFC/OAuth conformance crate and remains labeled as an experimental profile claim. The current Keylix profile identifier is `sep-1932-draft`, targeting `rmcp` 3.0.1 and the MCP 2026-07-28 specification generation.

The `keylix-mcp` integration suites exercise:

- token-endpoint DPoP proof verification and derivation of the sender key used for a DPoP-bound token relationship;
- missing token-request proof and Bearer token-response rejection in required mode;
- `Authorization: DPoP <token>` plus a fresh proof on official `rmcp::StreamableHttpClient` HTTP attempts;
- rejection of pre-existing Bearer/Authorization or DPoP proof headers before inner transport dispatch;
- replay rejection and HTTP method/target binding;
- separate authorization-server and resource-server nonce scopes and bounded retry state;
- unchanged MCP JSON-RPC message forwarding through the HTTP wrapper;
- dependency direction that keeps `rmcp` and MCP-specific types out of `keylix-dpop`;
- server-side proof verification before MCP dispatch;
- exact-token OAuth sender-binding composition into `VerifiedSenderBinding`;
- stolen bound-token use without the bound proof key;
- distinct proof-validation versus OAuth sender-binding failure categories;
- ambiguous multiple DPoP header rejection;
- explicit Draft profile/version metadata and failure for unknown profile identifiers.

Passing these tests means `KX-MCP-001` through `KX-MCP-005` are covered for the **Keylix `sep-1932-draft` contract**. It does not claim stable/final MCP DPoP conformance, because SEP-1932 remains a draft and may change.

## Independent ES256 fixture

The fixed DPoP proof used by the RFC suite was generated outside Keylix with Python `cryptography`, backed by OpenSSL, using a fixed P-256 private scalar. Keylix receives only the resulting public JWK and compact JWS. This provides an interoperability cross-check rather than signing and verifying with the same implementation.

The same compact proof is stored as the standalone fuzz seed:

```text
fuzz/corpus/dpop_parse_verify/independent.proof
```

That file can also be consumed by non-Rust test harnesses.

## Fuzzing

The `fuzz/` directory is a separate Cargo workspace so fuzz-only dependencies never enter the root workspace's locked dependency graph.

Current targets are:

| Target | Boundary | Input ceiling |
| --- | --- | ---: |
| `jwk_parse` | public P-256 JWK parser | 16 KiB |
| `dpop_parse_verify` | compact proof parser and verifier | 16 KiB |
| `request_target` | effective HTTP request-target parser | 8 KiB |

Seed corpora live under `fuzz/corpus/`. Each target rejects oversized input before invoking the parser/verifier boundary.

Run a target locally with nightly Rust and `cargo-fuzz`, for example:

```bash
cd fuzz
cargo +nightly fuzz run jwk_parse
```

The repository also includes the manual `Fuzz` GitHub Actions workflow. It is intentionally not part of every pull request and has a bounded time and RSS limit per target. This keeps deterministic CI reproducible while allowing deeper parser exploration on demand.

## OAuth validation boundary

OAuth conformance exercises the explicit public host-validation adapters in `keylix-oauth`. The test harness supplies the exact token bytes and trusted confirmation metadata as a host-attested validation result, then proves that token mix-and-match, missing/mismatched confirmation, Bearer downgrade, proof-key changes, and unbounded nonce retries fail closed.

This does not claim that Keylix validates JWT signatures, issuer/audience/scope, or authenticates introspection endpoints. Those remain host responsibilities as documented in [`OAUTH_INTEGRATION.md`](OAUTH_INTEGRATION.md).

## RFC/OAuth versus MCP profile claims

RFC-level DPoP/JWK behavior and MCP profile behavior remain separate claims. The RFC/OAuth suite does not depend on an MCP SDK. The MCP suite deliberately exposes its SEP/profile status and SDK/spec target rather than representing draft SEP-1932 behavior as stable conformance.

Profile drift is isolated to `keylix-mcp`; RFC 9449 and OAuth sender-binding semantics remain authoritative upstream layers.

## Remaining implementation-owned coverage

The MCP draft-profile requirements are covered, but the overall Keylix matrix is not complete. Remaining integration-owned work includes:

- trusted-proxy/framework reconstruction of the external effective request target (`KX-DPOP-009`), beyond the protocol-level URI normalization already tested in `keylix-dpop`;
- broader generic HTTP-retry/external-provider interoperability obligations where rows remain `Implemented` rather than `Covered`;
- telemetry/evidence-specific observability requirements (`KX-OBS-001` through `KX-OBS-003`), which are not inferred from ordinary `Debug` redaction alone.

Those requirements remain conservative until their own integration/evidence boundaries are exercised.