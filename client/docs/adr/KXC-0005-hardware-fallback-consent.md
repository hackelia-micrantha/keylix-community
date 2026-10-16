# ADR KXC-0005: Hardware-Unavailable Fallback Requires Explicit Consent

## Status

Accepted

## Context

Some devices (older Android without StrongBox/TEE, simulators, web views) cannot generate non-extractable keys in secure hardware. An SDK could silently fall back to software key generation, but this creates a silent security downgrade that the authorization server cannot detect.

## Decision

When secure hardware is unavailable:
1. The SDK returns `KeyGenerationError.secureHardwareUnavailable`.
2. The application MAY prompt the user for consent to use a software key.
3. If the user consents, the SDK generates a software key and marks the bootstrap result as `degraded`.
4. The application SHOULD signal the degraded posture to the backend (e.g., via a custom claim or metadata).
5. If the user does not consent, bootstrap fails closed.

## Consequences

- Positive: no silent security downgrade.
- Positive: the backend can distinguish hardware-backed vs software-backed clients.
- Positive: high-assurance apps can deny bootstrap when hardware is unavailable.
- Negative: degraded mode introduces a weaker security tier.
- Negative: software keys are still vulnerable to extraction on compromised devices.
