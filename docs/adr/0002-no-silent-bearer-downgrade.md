# ADR-0002: Require explicit DPoP mode and prohibit silent Bearer downgrade

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

RFC 9449 signals a DPoP-bound access token using `token_type=DPoP` and uses `Authorization: DPoP <token>` for protected-resource access. A server may choose to return a Bearer token instead, but that response does not provide DPoP access-token protection.

MCP core authorization currently specifies Bearer access tokens, while DPoP support is being developed separately. Compatibility logic could therefore be tempted to retry or downgrade automatically.

## Decision

Keylix distinguishes explicit security modes.

At minimum:

```text
DPoPRequired
DPoPPreferred / caller-managed compatibility (if later justified)
```

In `DPoPRequired` mode:

- a token response whose type is not `DPoP` is rejected;
- a protected-resource failure is not retried using Bearer;
- MCP integration does not infer ordinary Bearer support as permission to downgrade;
- state/backend failures do not silently disable sender-constraint enforcement.

Any weaker compatibility mode must be deliberately selected by the application and clearly observable.

## Consequences

### Positive

- operational failures cannot silently erase the requested security property.
- clients can reason about whether a token/session is actually sender constrained.
- MCP interoperability experimentation cannot weaken the underlying OAuth behavior accidentally.

### Negative

- some existing OAuth/MCP servers will fail rather than interoperate in strict mode.
- applications that intentionally permit Bearer fallback must model that choice explicitly.

## Guardrail

A code path named or typed as DPoP-required must never return success after switching the request/token to Bearer authentication.
