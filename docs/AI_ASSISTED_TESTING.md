# AI-assisted adversarial testing

Keylix may use an optional model to **propose** adversarial test dimensions. A model is never a protocol oracle, never supplies reusable protocol material, and is never required by normal CI.

## Trust boundary

The model may emit only a bounded JSON batch selecting from a closed semantic mutation vocabulary:

- `method_mismatch`
- `target_mismatch`
- `query_variation_ignored`
- `access_token_mismatch`
- `nonce_mismatch`
- `replay_same_proof`

The candidate schema contains only an identifier, one mutation selector, and a short rationale. It has no fields for proofs, private keys, tokens, nonces, expected errors, or expected pass/fail results.

`keylix-conformance` then creates synthetic keys, proofs, tokens, and nonces locally and executes the selected mutation against the normal deterministic DPoP implementation. Keylix determines whether the selected case must verify or reject and, for rejection cases, the required failure category. Model text cannot alter that result.

Malformed JSON, unknown fields, unsupported mutation names, duplicate IDs, duplicate semantic mutations, oversized batches, control characters, and sensitive-looking material fail closed.

## Current execution boundary

The checked-in adapter is intentionally **local/offline only** while #29 and #30 establish the private-canonical/public-community boundary and reconciliation rules. It must not be used with a hosted or otherwise externally networked model command.

A run must state this boundary explicitly:

```text
python3 scripts/ai_adversary.py \
  --execution-boundary local-offline \
  --generator '<local-offline-model-cli>' \
  --generator-label '<model-label>' \
  --output candidates.json
```

Any execution-boundary value other than `local-offline` fails before canonical context is read. The selected generator is therefore an operator assertion that the model remains inside the trusted local boundary; Keylix does not attempt to infer whether an arbitrary executable secretly uses the network.

Hosted/external generation remains disabled until the repository split is operational. When that path is introduced, prompt context must come from the reviewed `keylix-community` projection or an explicit sanitized export, or be proven byte-equivalent to the reviewed public projection. Arbitrary private canonical files must never become an implicit data-export channel.

## Local/offline adapter

Before invoking the local/offline model, the adapter reads only this fixed canonical allowlist:

- `docs/THREAT_MODEL.md`
- `docs/REQUIREMENTS.md`
- `docs/TESTING.md`

Those paths are anchored to the repository containing the adapter. Symlinks and other non-regular files are rejected before reading so a changed checkout cannot redirect the allowlist to arbitrary local files. The context is read with a byte cap and must be UTF-8.

The adapter rejects obvious PEM/JWT-shaped sensitive material before model invocation and again before retaining output. A model-assisted run is bounded to:

- exactly one generator invocation with no automatic retry;
- 96 KiB sanitized repository context;
- 64 KiB generator stdout, enforced while streaming rather than after buffering;
- 16 candidates;
- 60 seconds for the generator;
- 60 seconds for deterministic evaluation.

If the generator exceeds its stdout or runtime bound, Keylix terminates the generator process tree on supported platforms and rejects the run. Generator stderr is not retained.

The adapter strips the free-form rationale and pipes only canonical `id<TAB>mutation` records to:

```text
cargo run --locked -p keylix-conformance --bin keylix-ai-candidate-check
```

The deterministic checker is run from the Keylix repository root. Only output accepted and executed by that checker may be retained for human review.

When `--output` is used, the adapter also writes `<output>.provenance.json` containing the caller-supplied non-secret generator/model label, `local-offline` execution boundary, canonical fixed-allowlist context source, UTC generation time, candidate count, SHA-256 digest of the normalized candidate JSON, and the generic invocation/context/output/runtime bounds. The executable generator command is deliberately not persisted because it may contain local paths, arguments, or credentials.

## Promotion rule

A useful discovery does not remain model-owned. Promote it into an ordinary deterministic regression test, fixture, or fuzz seed with enough provenance to explain the semantic dimension. The promoted asset must run with no model, network, provider account, or model credentials.

The initial AI-assisted implementation review identified query variation as a useful explicit normalization dimension. `EffectiveRequestTarget` deliberately omits query and fragment components from DPoP `htu`, so a proof built for `?a=1&b=2` must remain valid when the same normalized resource is presented as `?b=2&a=1`. This behavior is promoted in `crates/keylix-conformance/tests/ai_promoted_regression.rs`.

The finding is useful precisely because an intuitive adversarial hypothesis would expect query reordering to break target binding; deterministic Keylix semantics corrected that hypothesis. This demonstrates why the model proposes dimensions but cannot determine expected behavior.

Promoted cases land in canonical Keylix first and become ordinary deterministic assets. After the private/public split is operational, public publication follows the normal reviewed canonical → `keylix-community` path rather than treating model output as an independent public edit.

This promotion record does not make future model output authoritative. The checked-in deterministic regression is the lasting evidence.

## Non-goals

This workflow does not:

- use an LLM as judge;
- repair malformed model output;
- generate or expose production credentials;
- enable hosted/external model access to canonical context;
- replace property or fuzz testing;
- run automatically on pull requests;
- automatically commit model output;
- bypass the canonical → community publication boundary;
- allow prompt/model changes to weaken `KX-*` requirements.
