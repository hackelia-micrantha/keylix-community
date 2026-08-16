# Testing Strategy

Keylix treats tests as security evidence, not only as coverage. A useful test must identify the boundary it exercises and use a deterministic oracle for protocol or security correctness.

## Test layers

| Layer | Purpose | Default command |
| --- | --- | --- |
| Unit | Local parsing, value, policy, and state invariants | `cargo test --locked --workspace --all-features --lib` |
| Integration | Cross-module/crate behavior, adapters, state stores, and conformance suites | `cargo test --locked --workspace --all-features --test '*' -- --skip kx_mcp_e2e_` |
| End-to-end | A representative cross-stack client-to-server sender-binding path | `cargo test --locked -p keylix-mcp --test end_to_end` |
| Fuzz | Parser/verifier robustness and bounded resource behavior | `.github/workflows/fuzz.yml` |

### Unit tests

Unit tests should be fast, isolated, and deterministic. Prefer them for:

- parsing and canonicalization edge cases;
- typed-value validation;
- proof/request policy decisions;
- nonce/replay-store state transitions;
- error classification and redaction behavior.

A unit test is not sufficient evidence when the security property depends on composition across boundaries.

### Integration and conformance tests

Integration tests exercise public boundaries between crates and adapters. The `keylix-conformance` crate remains the authority for externally observable RFC/security behavior and requirement traceability.

The CI integration command selects only Cargo integration-test targets. The E2E test function is skipped there and run separately so unit, integration/conformance, and E2E failures remain independently attributable.

Integration coverage should include both positive behavior and a negative/adversarial case when a boundary is security-sensitive. Failures should remain attributable to the relevant `KX-*` requirement where practical.

### End-to-end tests

`crates/keylix-mcp/tests/end_to_end.rs` provides a deterministic cross-stack smoke path:

```text
MCP DPoP client
  -> rmcp StreamableHttpClient decoration boundary
  -> verifying in-process transport
  -> MCP server DPoP verification
  -> OAuth exact-token sender binding
  -> replay state
```

The wrapped transport invokes the server-side Keylix verifier during the same client operation. The test then replays the captured proof against the same replay store and requires deterministic rejection.

This is intentionally self-contained for pull-request CI: it crosses the public Keylix client/server boundaries without requiring a live OAuth provider, network service, external credentials, or timing-sensitive infrastructure.

A future wire/process interoperability suite may add local HTTP processes or independently implemented peers. That suite should complement, not replace, this deterministic smoke path.

## Fuzz testing

The existing `cargo-fuzz` suite targets the highest-risk untrusted-input boundaries:

- JWK parsing;
- DPoP compact proof parsing and verification;
- effective request-target parsing.

Fuzzing is bounded in the manual workflow by per-target runtime and RSS limits. Crashes, panics, sanitizer findings, or pathological resource behavior are failures.

The manual **Fuzz** workflow is exploratory/regression discovery. It accepts a short bounded runtime and does not by itself constitute first-release evidence.

### Release-candidate fuzz evidence

Before a release candidate is treated as fuzz-validated, run the canonical **Release Candidate Fuzz** workflow with the exact full SHA of the candidate on canonical `main`.

The release-candidate workflow is deliberately separate from pull-request CI:

- the requested SHA must be a full 40-character lowercase commit identifier;
- the checked-out revision must exactly match that SHA and be reachable from canonical `main`;
- each of the three supported fuzz targets runs for a bounded 60–900 seconds, with 300 seconds per target as the default;
- RSS remains bounded to 2 GiB per libFuzzer invocation;
- cargo-fuzz is installed from the pinned 0.13.2 release archive only after its SHA-256 digest is verified;
- compile status, exact commit/tree, workflow run identity, fuzz duration, tool versions, and per-target results are written to a retained evidence artifact;
- target logs and any generated `fuzz/artifacts` reproducers are retained with that evidence;
- individual target failures do not prevent evidence collection, but the workflow fails after artifacts are uploaded if compilation or any target did not succeed.

A successful run is evidence only for the exact recorded revision. A later commit requires a new release-candidate fuzz run.

Longer external campaigns may still be useful, but they are not silently implied by this bounded release gate.

When fuzzing discovers a security-relevant input:

1. minimize the reproducer;
2. classify the violated invariant or requirement;
3. add a deterministic regression test when practical;
4. retain a minimized corpus seed when it improves future exploration.

The fuzz corpus is therefore an input-discovery mechanism; ordinary deterministic tests remain the regression oracle.

## AI-assisted testing

For Keylix, "AI testing" initially means **AI-assisted adversarial test generation and analysis**, not putting an LLM in the runtime or making model judgment part of protocol verification.

### Appropriate uses

A model may be used offline or in a manual workflow to:

- propose malformed JWK/JWS/DPoP inputs;
- mutate existing public conformance and fuzz fixtures;
- derive candidate negative cases from `docs/THREAT_MODEL.md` and `docs/REQUIREMENTS.md`;
- propose protocol-state sequences around nonce rotation, replay, retries, and target binding;
- identify semantic dimensions that appear under-tested;
- help minimize or explain a discovered failure before a human-reviewed deterministic regression test is added.

### Non-negotiable constraints

AI output is **never the pass/fail oracle** for a Keylix security property.

- Deterministic code, normative vectors, explicit properties, or independently implemented protocol checks decide correctness.
- CI must not require an LLM, model API, network access, or model credentials to validate a pull request.
- Private keys, bearer/DPoP access tokens, reusable proofs, nonces, production traces, and other secrets must not be sent to a model.
- A model-generated claim cannot override a failing deterministic test or weaken a `KX-*` requirement.
- Prompt/model changes must not silently change the security baseline.
- Accepted AI-generated cases become normal reviewed fixtures/tests in the repository and must reproduce without the model.

### Recommended experimental workflow

```text
public requirements + threat model + sanitized seed fixtures
                      |
                      v
             AI candidate generator
                      |
                      v
       schema / bounds / secret validation
                      |
                      v
          deterministic Keylix oracle
                      |
              +-------+-------+
              |               |
           reject          novel case
                              |
                              v
                    minimize + human review
                              |
                              v
                  checked-in regression test
```

Start this as a manual, advisory workflow. Promotion to an automated gate should happen only if the generated artifacts are deterministic, bounded, provider-independent at the correctness boundary, and demonstrably add unique coverage.

## CI policy

Pull-request CI should fail on dependency advisories, formatting, lint, unit, integration/conformance, end-to-end, or documentation failures. Longer fuzz campaigns remain explicitly bounded/manual. AI-assisted discovery remains non-blocking until any useful output has been converted into ordinary deterministic tests or fixtures.
