# ADR-0006: Effective HTTP target and trusted-proxy boundary

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

DPoP binds proofs to the HTTP method and target URI. RFC 9449 requires `htu` comparison against the URI of the actual request, excluding query and fragment, and recommends RFC 3986 syntax- and scheme-based normalization.

Applications frequently run behind TLS-terminating reverse proxies where the framework-visible request URI differs from the external URI used by the client. Blindly trusting `Forwarded` or `X-Forwarded-*` headers lets an attacker influence the value being verified.

## Decision

`keylix-dpop` consumes an already trusted `EffectiveRequestTarget`; it does not parse or trust forwarding headers.

Framework or gateway integrations construct that value using an explicit deployment mode:

1. **Direct** — derive the external scheme, authority, and path from directly trusted request/server context.
2. **Trusted proxy** — reconstruct the external target only after the host integration has authenticated the immediate proxy boundary according to explicit deployment policy.

There is no default `trust_forwarded_headers=true` behavior. Generic Keylix code does not infer proxy trust from the mere presence of forwarding headers.

The comparison pipeline is:

```text
trusted external request URI  -> strip query/fragment -> normalize
proof htu                     -> strip query/fragment -> normalize
                                                -> exact comparison
```

### Normalization contract

The v0.1 comparison follows the RFC 9449 recommendation to apply RFC 3986 syntax-based and scheme-based normalization. In particular:

- scheme and host comparison are case-insensitive and canonicalized to lowercase;
- percent-encoding hex digits are canonicalized consistently;
- percent-encoded unreserved characters may be decoded as part of syntax normalization;
- dot segments are removed according to RFC 3986;
- an empty path for an authority-based HTTP(S) URI is normalized consistently with `/`;
- default ports are normalized according to scheme (`80` for HTTP, `443` for HTTPS);
- query and fragment are not part of `htu` comparison and are stripped before comparison;
- reserved characters are not broadly decoded/re-encoded into semantic equivalents beyond RFC 3986 normalization;
- trailing-slash differences are not treated as equivalent unless produced by the defined normalization rules.

The core operates on URI semantics, not on raw `Host`, `Forwarded`, or `X-Forwarded-*` strings.

### Proxy integration contract

A proxy-aware adapter must require explicit configuration describing how the trusted external target is obtained. If an adapter supports `Forwarded` or `X-Forwarded-*`, that support is opt-in and must document:

- which immediate peers are trusted;
- which header family is accepted;
- how multi-hop values are selected;
- whether the proxy overwrites rather than appends untrusted inbound values;
- what happens when metadata is malformed or incomplete.

Ambiguous reconstruction fails closed.

### v0.1 adapter

`keylix-http` implements the first framework-neutral adapter without weakening the core boundary. Direct mode accepts only host-trusted scheme/authority/path inputs. Trusted-proxy mode requires an injected immediate-peer `ProxyTrust` policy and an explicitly selected header family (`Forwarded` or `X-Forwarded-Proto` + `X-Forwarded-Host`). v0.1 supports exactly one trusted hop; mixed families, comma/appended multi-hop metadata, malformed or incomplete values, and untrusted peers fail closed. Path/query rewrite semantics remain host/framework-owned rather than inferred from forwarding headers.

## Consequences

### Positive

- DPoP semantics remain independent of proxy/framework conventions;
- host/scheme spoofing cannot silently alter core verification;
- proxy trust becomes visible deployment configuration;
- direct and proxied deployments can share the same verifier once the external target is resolved.

### Negative

- framework adapters need deployment-specific configuration;
- proxy misconfiguration causes legitimate proofs to fail closed;
- robust proxy helpers require integration-specific tests rather than one universal parser.

## Required tests

Conformance/adversarial coverage must include query stripping, percent encoding, host/scheme case, default ports, empty paths, dot segments, reserved-character distinctions, direct deployment, trusted-proxy deployment, and hostile forwarding-header spoofing.