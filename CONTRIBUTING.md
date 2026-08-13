# Contributing to Keylix

Keylix is a security-sensitive protocol implementation. Correctness, explicit invariants, and adversarial tests take precedence over API convenience.

## Before coding

For security-significant behavior, start with an issue that identifies:

1. the relevant RFC/specification requirement;
2. the security invariant being enforced;
3. expected failure behavior;
4. positive and negative test cases;
5. compatibility implications.

## Quality gate

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

Security-sensitive parsing or verification changes should also include adversarial, property, or fuzz tests as appropriate.

## Design constraints

- Keep `keylix-dpop` independent of MCP.
- Do not introduce custom cryptographic primitives.
- Reject algorithm confusion and implicit algorithm negotiation.
- Avoid APIs that expose or log private key material.
- Keep URI/method canonicalization rules explicit and covered by vectors.
- Make replay and nonce storage behavior observable and testable.
- Prefer dependency injection at stateful/time/randomness boundaries so verification can be deterministic in tests.

## Commits and pull requests

Keep changes narrowly scoped. PR descriptions should identify the security property affected and link to normative specification text where relevant.
