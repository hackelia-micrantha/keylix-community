# Cryptographic Survivability

Status: post-v0.1 design guidance
Tracking: issue #73

Keylix v0.1 deliberately supports one DPoP proof profile:

~~~text
JWS alg: ES256
JWK kty: EC
JWK crv: P-256
~~~

That narrow policy reduces interoperability ambiguity, algorithm-confusion surface, parser/key variants, and conformance cost.

This document does not change that v0.1 decision. It defines how Keylix should remain migratable as cryptographic requirements evolve, including future post-quantum transitions.

## Current security boundary

ADR-0005 remains authoritative for v0.1:

- ES256/P-256 is the only enabled proof-signing profile;
- untrusted algorithm input never selects an implementation;
- unsupported algorithms fail before signature verification;
- key type, curve, algorithm, and verifier implementation must agree;
- adding an algorithm is a deliberate security/API change.

The migration posture must preserve those properties.

## Long-horizon limitation

P-256/ES256 is a classical elliptic-curve signature profile. A sufficiently capable quantum computer would invalidate the security assumptions of the underlying elliptic-curve signature primitive.

This does not make the current v0.1 design incorrect for its present interoperability target. It means:

> v0.1 algorithm policy must not become permanent identity architecture.

## Identity is not the key algorithm

Keylix should preserve the distinction:

~~~text
logical principal / installation identity
  != one DPoP public key forever
  != P-256 forever
  != one proof profile forever
~~~

A principal may rotate proof keys over time. A future algorithm/profile transition should similarly be able to establish fresh proof authority without redefining the application's logical identity.

The exact identity/credential owner remains the consuming application or authorization system; Keylix is not an identity provider.

## Standards dependency

Keylix implements standards-based sender binding.

It should not define a private "PQ-DPoP" or "PQ-JOSE" format simply because post-quantum primitives exist.

Future support needs a reviewable interoperable answer for the complete proof representation, including applicable:

- signature algorithm identifier;
- public-key representation;
- proof-header representation;
- key thumbprint/binding;
- access-token confirmation binding;
- verifier policy;
- key rotation/profile negotiation;
- error semantics;
- conformance vectors.

Until those surrounding protocol semantics are standardized or otherwise appropriately interoperable, the correct posture is:

- retain the current v0.1 profile;
- keep profile selection explicit;
- isolate algorithm-specific implementation;
- document the dependency;
- inventory current deployments;
- avoid domain assumptions that make migration impossible.

## Algorithm policy remains explicit

Future agility must not become algorithm negotiation driven by attacker-controlled proof content.

~~~text
configured local policy
  -> accepted profile set
  -> parse proof
  -> identify claimed profile
  -> require exact allowed profile
  -> require key/profile/implementation agreement
  -> verify

request content
  -X-> enable implementation
  -X-> widen accepted profile set
~~~

Do not implement "try all known algorithms until one verifies."

Unsupported or retired profiles must fail explicitly.

## Profile model

A future internal abstraction may need to distinguish at least:

~~~text
ProofProfile {
  profile_id
  signature_algorithm
  public_key_representation
  thumbprint_binding
  verifier_backend
  signer_capabilities
  conformance_version
}
~~~

This is conceptual. Do not create a public schema until implementation needs one.

The key property is that profile identity is explicit and versionable rather than hidden behind generic JOSE library dispatch.

## JWK and thumbprint boundary

Current v0.1 uses JWK and RFC 7638 thumbprints as part of DPoP/token binding.

A future PQ migration must not assume that any new public key can simply be inserted into the current JWK/thumbprint construction.

Review must establish:

- standardized key representation;
- canonical fields;
- thumbprint/canonicalization rules;
- collision/security properties;
- compatibility with DPoP proof headers;
- compatibility with access-token confirmation semantics;
- parser/resource bounds.

If future standards use a different representation/binding mechanism, Keylix should adapt deliberately rather than forcing it through a P-256-shaped abstraction.

## Token binding

A proof-key/profile migration can affect the authorization-server/resource-server boundary.

Review applicable behavior for:

- current access token bound to old proof key;
- fresh token bound to new key;
- key rotation while a token remains valid;
- old profile retirement;
- nonce state;
- replay cache;
- access-token hash binding;
- token confirmation binding;
- token substitution;
- cross-profile proof substitution.

A successful signature under a newly supported algorithm is insufficient if the access-token confirmation binding does not refer to that exact key/profile.

## Mobile signer boundary

Issue #60 owns current KMP/Android/iOS DPoP client delivery. Its current profile remains ES256/P-256.

The current mobile security objective is:

- platform-backed private-key custody where supported;
- no ordinary shared-memory private-key export;
- no hidden plaintext-key fallback;
- explicit unavailable/locked signer failure.

Future PQ support must separately assess platform reality:

~~~text
hardware confinement
  != algorithm availability
  != post-quantum strength
~~~

A Secure Enclave/StrongBox key can be strongly non-exportable while its algorithm remains classical.

A future profile may require software signing on platforms that lack hardware PQ support. That is a separate assurance decision and must not be represented as equivalent hardware confinement.

## Server verifier boundary

A future verifier profile should preserve v0.1's fail-closed structure.

Review:

- strict profile allowlist;
- key/profile matching;
- parser limits;
- signature length limits;
- CPU/memory cost limits;
- replay-store impact;
- proof/header size limits;
- HTTP/header limits;
- fuzzing corpus changes;
- error normalization;
- versioned conformance vectors.

Post-quantum public keys and signatures can be materially larger than P-256/ES256 material, so resource behavior is a first-class security concern.

## Historical evidence

A proof accepted under v0.1 establishes what the v0.1 verification policy established at that time.

If ES256 is retired under a future policy, historical verification may remain useful for audit without allowing an old proof/key/profile to create current authority.

~~~text
historically valid proof/evidence
  != currently accepted proof profile
  != current authorization
~~~

The consuming system remains authoritative for token validity, identity, scopes, and authorization.

## Crypto inventory

Keylix should provide enough non-secret information for a deployment inventory to identify its current cryptographic posture.

Useful facts include:

- Keylix version;
- enabled proof profiles;
- active client proof profile;
- public key identifier/thumbprint;
- key custody class;
- key creation/rotation age where available;
- platform signer type;
- verifier accepted-profile set;
- relevant standards/conformance profile.

Do not expose private keys or raw sensitive credential material.

This allows consumers such as Dubnium to calculate cryptographic dependency/blast-radius information without coupling to Keylix internals.

## Migration sequence

A future transition should prefer staged, explicit profile evolution.

~~~text
v0.1
  ES256-only
      |
      v
internal profile abstraction
  still ES256-only externally
      |
      v
interoperable future profile defined
      |
      v
candidate signer/verifier implementation
  + deterministic vectors
  + fuzz/adversarial coverage
      |
      v
explicit dual-profile policy where needed
      |
      v
clients rotate keys/tokens
      |
      v
old profile deprecated/retired
~~~

A dual-profile period must not mean:

~~~text
new profile fails
  -> silently retry ES256
~~~

Fallback/downgrade semantics must be explicit policy.

## Mobile/client migration

A client profile transition may require:

1. generate a new proof key under the new profile;
2. enroll/bind that key according to the consuming identity/credential system;
3. obtain a token bound to the new key;
4. prove new profile interoperability with the resource server;
5. retire old token/key according to policy;
6. preserve bounded audit evidence.

Keylix should not invent enrollment/identity semantics owned by the consumer.

## Threat cases

Future conformance/review should include:

1. unsupported future profile identifier;
2. request/proof attempts to enable a disabled profile;
3. ES256 proof submitted after policy requires the new profile;
4. key representation valid for one profile interpreted as another;
5. token confirmation bound to old key while proof uses new key;
6. retired old-profile proof replay;
7. profile downgrade after verifier/backend failure;
8. large valid public key/signature causing resource pressure;
9. malformed large key/signature causing parser differential;
10. hardware signer unavailable and client silently falls back to weaker/unreviewed signer;
11. historical ES256 evidence confused with current authorization;
12. algorithm/profile metrics exposing sensitive key material.

## Relationship to v0.1 release

Post-quantum planning must not destabilize the v0.1 security gate.

v0.1 should continue to be reviewed and tested against its actual contract:

- RFC 9449;
- RFC 7638;
- ES256;
- P-256;
- exact token binding;
- nonce/replay semantics;
- strict parsing;
- explicit algorithm policy.

Future algorithm agility is a separate compatibility/security evolution.

## Non-goals

This guidance does not:

- add another algorithm to v0.1;
- weaken ES256/P-256 conformance;
- create a custom PQ DPoP/JOSE dialect;
- predict quantum-computer timelines;
- treat hardware-backed P-256 as post-quantum;
- make Keylix an authorization server or identity provider;
- allow request-selected crypto backends;
- require speculative mobile PQ implementation before ecosystem support exists.
