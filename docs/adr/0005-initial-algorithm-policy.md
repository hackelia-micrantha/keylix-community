# ADR-0005: Initial DPoP signing algorithm policy

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

RFC 9449 requires an asymmetric signature algorithm that is supported and acceptable to local policy; it does not mandate one universal algorithm. Supporting more algorithms increases interoperability but also increases crypto dependencies, parser/key variants, test combinations, and downgrade/confusion surface.

The active MCP SEP-1932 conformance work uses ES256/P-256 as its default proof algorithm and advertises ES256 in the authorization-server fixture. The conformance validators deliberately recognize additional asymmetric algorithms for negative/interoperability coverage, but no current reference MCP SDK is reported as implementing DPoP yet.

## Decision

Keylix v0.1 has one required and enabled DPoP algorithm profile:

- JWS `alg`: `ES256`
- JWK `kty`: `EC`
- JWK `crv`: `P-256`
- SHA-256 for RFC 7638 thumbprints and `ath` as required by RFC 9449

The verifier uses an explicit local algorithm policy. Untrusted `alg` input never selects or enables an implementation. In the v0.1 default profile, every algorithm other than `ES256` is rejected before signature verification.

For an ES256 proof JWK:

- `kty` must be exactly `EC`;
- `crv` must be exactly `P-256`;
- `x` and `y` must decode as valid P-256 coordinates;
- private key material such as `d` is rejected;
- the public point must pass the selected cryptographic backend's P-256 validation;
- `alg`, key type, curve, and verifier implementation must agree explicitly.

Do not add RSA merely for breadth. EdDSA or other asymmetric algorithms may be added later as separately testable policy capabilities after interoperability evidence exists. Adding an algorithm is a deliberate security/API change, not a configuration string passed through to a generic JOSE dispatcher.

## Consequences

### Positive

- small cryptographic and test surface;
- aligns with RFC 9449 examples and current SEP-1932 fixtures;
- simpler JWK domain model for the first release;
- easier conformance, property, and fuzz coverage;
- reduces algorithm-confusion/downgrade surface.

### Negative

- deployments requiring another asymmetric algorithm will not interoperate in v0.1;
- adding another key type later requires explicit design and tests.

## Follow-up

The concrete crypto/JOSE backend remains a separate design decision. Dependency selection must demonstrate strict P-256 public-key validation, fixed ES256 signature encoding/verification semantics, and compatibility with capability-based/non-extractable signing providers.