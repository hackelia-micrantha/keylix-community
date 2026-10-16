# Conformance Vector Schema (Keylix Client)

**Status:** proposed (see issue #12 and the "Fix conformance corpus" issue).
**Owner:** all SDK owners.

This document defines the *normative* JSON schema for the shared conformance corpus in
`tests/consumed/`. Every platform SDK MUST load and satisfy these vectors. CI MUST validate
every vector file against this schema **before** running SDK tests — a parse-only `json.load`
is insufficient (see the prior CI gap).

## Common envelope

Every vector file shares this shape:

| Field           | Type   | Required | Notes                                            |
|-----------------|--------|----------|--------------------------------------------------|
| `_description`  | string | yes      | Human note.                                      |
| `profile`       | string | yes      | MUST be `"v1"`.                                  |
| `algorithm`     | string | yes      | MUST be `"ES256"`.                               |
| `vectors`       | array  | yes      | Objects; see per-file schema below.              |

## `proof-vectors.json`

Each vector:

| Field         | Type    | Required | Notes                                                                 |
|---------------|---------|----------|-----------------------------------------------------------------------|
| `id`          | string  | yes      | Unique within the file.                                              |
| `description` | string  | yes      | What this case exercises.                                            |
| `valid`       | boolean | yes      | MUST be `true` in this file.                                         |
| `request`     | object  | yes      | `{ "method": string, "url": string }`. `method` is an uppercase HTTP method; `url` is an absolute `http`/`https` URL. |
| `key`         | object  | yes      | JWK: `kty:"EC"`, `crv":"P-256"`, `x`, `y` (base64url, 32 bytes each). `d` (private) is OPTIONAL and ONLY for fixed-key deterministic vectors. |
| `fixedJti`    | string  | no       | Testing override for `jti`.                                          |
| `fixedIat`    | integer | no       | Testing override for `iat` (Unix seconds).                          |
| `expectedProof` | string | yes     | The exact compact JWS `header.payload.signature` (base64url, **raw R||S** 64-byte signature). MUST be a real, verifiable value — never a placeholder like `eyJ0eX...TURE`. |

**Verification:** the SDK builds the proof from `request` + `key` (applying `fixedJti`/`fixedIat`
when present) and the produced proof MUST equal `expectedProof` AND verify against `keylix-dpop`.

**Private-key handling:** if a `d` is present it MUST be a synthetic key, MUST NOT be a real key,
and fixtures SHOULD move to `tests/fixtures/keys.json` (synthetic-only, never committed from a real source).

## `invalid-proofs.json`

Each vector:

| Field          | Type    | Required | Notes                                                                 |
|----------------|---------|----------|-----------------------------------------------------------------------|
| `id`           | string  | yes      | Unique.                                                              |
| `description`  | string  | yes      | What is being rejected.                                              |
| `valid`        | boolean | yes      | MUST be `false`.                                                     |
| `request`      | object  | yes      | Same shape as proof-vector `request`.                                |
| `expectedError`| string  | yes      | MUST be one of the API_CONTRACT `ProofReason` values: `invalidTarget`, `nonceRequired`, `clockSkewExceeded`, `invalidAccessToken` (or the platform `ProofError` equivalent). Dot-notation such as `proof.invalidTarget` is NOT allowed. |

**Verification:** the SDK MUST reject the request and surface the matching `ProofReason`.

## `thumbprint-vectors.json`

Each vector:

| Field                | Type    | Required | Notes                                                                 |
|----------------------|---------|----------|-----------------------------------------------------------------------|
| `id`                 | string  | yes      | Unique.                                                              |
| `description`        | string  | yes      |                                                                      |
| `jwk`                | object  | yes      | `{ kty, crv, x, y }` with 32-byte coordinates.                      |
| `expectedThumbprint` | string  | yes      | `base64url(SHA-256(canonical JWK))` per RFC 7638.                   |

Canonical JWK = `{"crv":...,"kty":...,"x":...,"y":...}` with keys sorted lexicographically
(`crv`, `kty`, `x`, `y`), no whitespace. The SDK MUST compute the RFC 7638 thumbprint and it
MUST equal `expectedThumbprint`.

## Volume targets (Phase 0 exit criteria)

- `proof-vectors.json`: **>= 10** valid vectors — cover GET/POST/PUT/DELETE/PATCH, with/without
  access token, with/without nonce, `ath` present/absent.
- `invalid-proofs.json`: **>= 10** vectors — invalid scheme, empty URL, relative URL, wrong `ath`,
  stale `iat`, missing nonce (when required), algorithm mismatch, malformed URL, etc.
- `thumbprint-vectors.json`: **>= 3** vectors, including at least one RFC 7638 Appendix A known answer.

## Generation

Vectors are generated from the `keylix` Rust workspace (`keylix-dpop`) via
`scripts/conformance-pull.sh` and committed. Do NOT hand-edit `expectedProof` /
`expectedThumbprint`. Synthetic private keys live only in `tests/fixtures/keys.json`.

## CI contract

`.github/workflows/ci.yml` MUST run a schema validator (e.g. `python tools/validate_vectors.py`
or `jsonschema`) across all three files; a parse-only `json.load` does NOT satisfy this. CI MUST
fail on schema violations.
