# Safe observability and security evidence

Keylix separates ordinary operational telemetry from explicit security evidence. The boundary follows ADR-0011 and is implemented by the dependency-free `keylix-observe` crate.

## Operational telemetry

`TelemetryEvent` is the standard Keylix-owned telemetry schema. It contains only bounded enums and can be converted to `TelemetryLabels`, whose values are compile-time/static low-cardinality strings.

```text
TelemetryEvent
├── mechanism       DPoP
├── algorithm       ES256/P-256
├── operation       bounded enum
└── outcome
    ├── success
    └── failure     bounded failure class
```

There is intentionally no API for attaching arbitrary strings, request identifiers, token data, proof data, nonces, `jti`, claims, or JWK thumbprints. A host can map these values into `tracing`, OpenTelemetry, Prometheus, structured logs, or another observability system without giving Keylix's standard schema a credential-bearing escape hatch.

Keylix does not depend on a logging or telemetry framework. This keeps protocol/security crates independent from deployment choices and avoids implicit emission of sensitive values.

## Explicit sender-binding evidence

`SenderBindingEvidence` can be constructed only from `VerifiedSenderBinding`, after DPoP verification and exact-token OAuth composition have succeeded.

Its v0.1 fields are deliberately compact:

```text
SenderBindingEvidence
├── mechanism
├── algorithm
├── token validation source
├── proof issued-at time
├── evidence verification time
├── nonce enforced
├── replay checked
└── key thumbprint     optional, explicit policy only
```

The default `EvidenceKeyPolicy::Omit` excludes the RFC 7638 key thumbprint. `EvidenceKeyPolicy::Include` makes it available through an explicit evidence getter for audit/provenance consumers that need stable key-level attribution.

Even when the key thumbprint is included, `Debug` redacts it. Increasing logging verbosity does not enable evidence or reveal the stable identifier.

Evidence never contains:

- access or refresh tokens;
- authorization codes or credential headers;
- compact DPoP proofs;
- raw nonces;
- raw `jti` values;
- private key material;
- arbitrary claims;
- host-supplied free-form resource identifiers.

Hosts that need application/resource context should envelope Keylix evidence inside their own audit model. That keeps user-controlled/high-cardinality fields outside Keylix's safe evidence core.

## Privacy and retention

A JWK thumbprint is derived from public key material, but it is still a stable pseudonymous correlator. A consumer that explicitly exports it owns the retention, access-control, and privacy policy for that evidence.

Ordinary telemetry should remain suitable for broad operational aggregation. Security evidence should be routed only to destinations with an explicit audit/provenance need, such as a gateway or governance system.

## Integration pattern

```text
Keylix verification
      |
      +----> TelemetryEvent --------> host logging / tracing / metrics adapter
      |        bounded only
      |
      `----> VerifiedSenderBinding
                    |
                    `----> SenderBindingEvidence ----> audit / provenance system
                              explicit opt-in
```

This makes Anthesis/Invokrum-style evidence integration possible without turning production debug logging into an audit channel.
