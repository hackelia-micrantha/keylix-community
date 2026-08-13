# ADR-0007: Accept token binding only from validated OAuth results

- **Status:** Accepted
- **Date:** 2026-08-11

## Context

Protected-resource DPoP verification requires the proof key to match the key to which the access token is bound, commonly represented as `cnf.jkt` in a JWT access token or token introspection response.

If Keylix simply decodes an arbitrary JWT and trusts its `cnf.jkt`, an attacker can manufacture confirmation material that matches their own proof key. Full OAuth token validity—issuer, signature or authenticated introspection, audience, expiry, scopes, and resource policy—is outside the DPoP verifier's responsibility.

A second class of integration bug is mix-and-match: an application validates token A, then accidentally combines token A's `cnf.jkt` with raw token B when checking a proof. The proof's `ath` alone does not establish that token B was the token whose OAuth validity was established.

## Decision

The protocol-independent `keylix-dpop` crate does not accept untrusted token claims as authoritative confirmation material and does not perform general OAuth access-token validation.

The boundary is split into two stages:

```text
raw proof + request + raw access token
        |
        v
keylix-dpop
  -> VerifiedDpopProof
     - proof key thumbprint
     - verified htm/htu/iat/jti/nonce
     - verified ath for the exact presented token

validated OAuth result + exact token identity
        |
        v
keylix-oauth
  -> VerifiedSenderBinding
```

`keylix-oauth` accepts a host-provided token-validation result only through a narrow adapter contract. That result must establish, for the exact access token being presented:

- token validity according to the host OAuth policy;
- the DPoP confirmation thumbprint (`cnf.jkt` or equivalent trusted confirmation metadata);
- identity of the exact validated token, represented internally by a SHA-256 fingerprint of the token bytes or an equivalent non-ambiguous correlation mechanism.

Before producing `VerifiedSenderBinding`, `keylix-oauth` verifies all of the following:

1. the exact presented access token is the one represented by the validated OAuth result;
2. the DPoP proof's `ath` matches that presented access token;
3. the validated token's confirmation thumbprint matches the verified proof key thumbprint.

Adapters may obtain the validated result from:

- a successfully validated JWT access token;
- an authenticated, active token-introspection response;
- another host token validator with equivalent trust guarantees.

A raw decoded JWT payload, unauthenticated introspection document, or caller-provided `jkt` string is not a validated token result.

## API implications

- `VerifiedDpopProof` and `VerifiedSenderBinding` are distinct types.
- Application authorization consumes `VerifiedSenderBinding` only after normal OAuth validation has also succeeded.
- Construction APIs for validation adapters must make the trust boundary explicit in naming and documentation; Keylix must not imply that a caller-created structure was itself OAuth-validated by Keylix.
- Error mapping distinguishes at least: token not DPoP-bound, token/proof key mismatch, token identity mismatch, and invalid DPoP proof.

## Consequences

### Positive

- clean separation between OAuth token validity and DPoP proof/key binding;
- prevents accidental trust of unverified JWT claims;
- prevents validated-token/raw-token mix-and-match;
- works for both JWT and opaque access tokens;
- avoids turning Keylix into a general JWT/OAuth validation framework.

### Negative

- applications integrate a token validator as well as Keylix;
- common validators need small adapters;
- the OAuth composition layer has to preserve exact token correlation.

## Required tests

Tests must cover JWT and introspection paths, unverified `cnf` injection, inactive/introspection failure, token A metadata combined with token B, missing confirmation material, `ath` mismatch, and proof-key/token-key mismatch.