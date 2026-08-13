# Execution Principals and Delegated Runtime Identity

Status: architecture proposal  
Date: 2026-08-12  
Tracking: #19

## Purpose

Keylix authenticates and constrains the principal that invokes a capability. It does not authenticate a model's explanation of how the invocation was chosen.

This distinction keeps the OAuth/DPoP boundary useful across direct model clients, supervisor/specialist systems, recurrent runtimes, and other future agent architectures.

## Mental model

```text
supervisor principal
       |
       | bounded delegation
       v
specialist/runtime principal
       |
       | token + DPoP proof
       | exact capability/resource scope
       v
Keylix / MCP resource boundary
       |
       v
protected capability
```

The effective execution principal is established by an authenticated runtime/protocol boundary. Caller-supplied descriptive fields do not create identity.

## Execution principal

An execution principal is the authenticated workload/runtime identity on whose behalf an invocation is evaluated.

Candidate logical attributes:

- stable workload/runtime subject;
- proof-of-possession key binding;
- parent/delegator reference where applicable;
- delegated capability/resource scope;
- task/run/session reference for attribution;
- issuance and expiry;
- replay-prevention state;
- optional attested environment identity when a concrete trusted attester/profile exists.

These are conceptual requirements, not a commitment to token claim names. Existing OAuth/DPoP standards and Keylix protocol profiles remain authoritative for wire representation.

## Delegation

Delegation must narrow authority.

```text
parent grant
  capability: repo.write
  resource: repo:A
  paths: src/**
  expires: T
       |
       v
child grant
  capability: repo.write
  resource: repo:A
  paths: src/parser/**
  expires: <= T
```

A child cannot acquire a broader capability, resource set, lifetime, or delegation depth merely because the supervisor requested it.

Required properties:

- parent identity is attributable;
- child effective identity is explicit;
- scope is an intersection/narrowing of parent and policy limits;
- replay controls remain effective across redelegation;
- retry/resume does not silently produce a stronger identity;
- revocation/expiry semantics remain well defined.

## Task and run references

Task/run/session identifiers improve attribution and exact binding but are not credentials.

They may be included or referenced when useful to bind:

- an Anthesis decision to the same effective principal;
- an Invokrum invocation to the authenticated runtime;
- a Dubnium child run to its delegator;
- evidence to the exact execution instance.

An attacker who can choose a task ID must not gain authority from that choice.

## Relationship to DPoP

DPoP continues to prove possession and bind requests according to the selected OAuth profile. Agent-specific metadata must not weaken those protocol semantics.

In particular:

- `htu`/`htm` and nonce/replay requirements remain protocol-correct;
- task or role metadata never substitutes for proof of possession;
- a copied authorization decision without the correct effective principal/key binding is insufficient;
- a supervisor's proof cannot be reused as a generic specialist credential unless an explicit delegation profile authorizes that exact use.

## Anthesis integration

Keylix answers the authentication/authorization-subject side of the boundary; Anthesis answers the governance decision.

```text
authenticated execution principal
          +
exact capability / target / request
          |
          v
Anthesis policy decision
          |
          v
Keylix-bound executable grant / downstream enforcement
```

An Anthesis decision must refer to the same effective principal and request subject that Keylix enforces. Runtime/provider evidence cannot widen that decision.

## Trust boundaries

### Keylix owns

- authentication/profile validation;
- proof-of-possession verification;
- effective execution-principal identity;
- delegated authorization binding;
- replay/expiry enforcement defined by the protocol/profile.

### Keylix does not own

- model reasoning or runtime planning;
- project/workflow state;
- whether an effect is acceptable under governance policy;
- runtime process lifecycle;
- evidence/provenance interpretation.

Neighbor ownership:

- Calathea — workflow authoring;
- Invokrum — portable invocation contract;
- Dubnium — runtime creation/execution of supervisor and specialist runs;
- Anthesis — policy, approvals, governed effects, evidence semantics.

## Threat cases

Conformance and threat analysis should cover:

1. supervisor credential reused directly by an untrusted specialist;
2. caller JSON attempts to override authenticated runtime identity;
3. child delegation requests broader capability/resource scope;
4. stale task/run binding is replayed against a new invocation;
5. valid DPoP proof is presented with an Anthesis decision bound to another principal;
6. runtime self-description claims a stronger role than its authenticated identity;
7. redelegation exceeds configured depth or lifetime;
8. optional attestation is absent, stale, or unverifiable.

The safe outcome is explicit rejection or downgrade according to the profile, never implicit trust in descriptive runtime metadata.

## Private runtime computation

No token, proof, or authorization subject needs model-private computation. Keylix remains concerned with cryptographic/protocol identity and exact executable authority.

This avoids making authentication depend on a runtime-specific representation and avoids introducing unnecessary sensitive context into bearer/token/log surfaces.

## Research motivation

BDH-CQ (arXiv:2608.09888) is a useful architecture signal because its computation need not be exposed as an external reasoning sequence. Keylix's existing DPoP direction naturally fits that future: authenticate the execution principal and request, not the internal reasoning mechanism.

## Next step

Issue #19 owns the review of existing `ARCHITECTURE.md`, `DESIGN.md`, OAuth integration, protocol flows, threat model, and conformance docs, followed by the smallest stable ADR/profile change.