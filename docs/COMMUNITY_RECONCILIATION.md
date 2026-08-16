# Community contribution reconciliation

Keylix uses two repositories with deliberately different authority:

```text
public contribution
    -> hackelia-micrantha/keylix-community PR/review
    -> accepted commit on keylix-community/main
    -> explicit reconciliation into canonical keylix
    -> canonical review + validation + merge
    -> normal reviewed publication back to keylix-community
```

`hackelia-micrantha/keylix` remains the canonical implementation source. The public repository is the supported contribution, review, inspection, and distribution surface. A public merge is accepted input to canonical reconciliation; it is not a second independent source of security semantics.

The operator helper described below is **canonical-only tooling**. It is intentionally not part of the public projection; contributors do not need access to it or to the canonical repository.

## Authority rules

1. Only a commit already reachable from `keylix-community/main` is eligible for the standard reconciliation helper.
2. Reconciliation identifies the exact public commit by full SHA and records that SHA in the canonical commit.
3. Contributor authorship is preserved in the canonical reconciliation commit.
4. Canonical tests, static analysis, conformance, and review run again after import. Public CI success is evidence, not a bypass token.
5. Conflicts fail closed. Do not resolve a conflict by silently preferring canonical or community content.
6. Repository-control files are reconciled manually because the two repositories intentionally have different workflow and publication authority.
7. Canonical publication remains the only operation that establishes the next public implementation state.
8. Do not reconcile embargoed vulnerability material through the public workflow.

## Supported first-stage import surface

The canonical helper at `scripts/community_import.py` is intentionally narrower than the total public repository surface.

Accepted without additional acknowledgement:

- `docs/**`;
- `crates/*/tests/**`;
- `fuzz/corpus/**`.

Accepted only with explicit `--allow-source` acknowledgement:

- `crates/**` implementation paths;
- `fuzz/fuzz_targets/**`;
- `Cargo.toml` / `Cargo.lock`;
- `fuzz/Cargo.toml`;
- `rust-toolchain.toml`.

Always manual:

- `.github/**`;
- `README.md`;
- `PUBLICATION.md`;
- `CONTRIBUTING.md`;
- `SECURITY.md`;
- `.gitignore`;
- unknown/new top-level paths.

This is intentional. A new public path does not implicitly gain canonical import authority. Rename detection is disabled during path-policy evaluation so moving a repository-control file into an allowed path cannot hide the control-path deletion.

## Plan an import

Start from a clean canonical checkout. Do not work directly on `main`.

```bash
# create/switch to a review branch first
python3 scripts/community_import.py plan <40-char-community-sha>
```

For a source-bearing contribution:

```bash
python3 scripts/community_import.py plan <40-char-community-sha> --allow-source
```

`plan` fetches the current public `main`, verifies the supplied commit is an accepted ancestor of it, validates every changed path, and prints the contributor, subject, path classes, and diff stat. It does not alter the canonical worktree.

Review the public PR and the planned diff before applying it.

## Apply an accepted contribution

```bash
python3 scripts/community_import.py apply <40-char-community-sha>
```

or, after explicitly reviewing source-bearing paths:

```bash
python3 scripts/community_import.py apply <40-char-community-sha> --allow-source
```

The helper refuses to run on `main`, in a detached HEAD, or with a dirty canonical worktree. It also refuses a public commit that already appears in canonical reconciliation provenance.

For a two-parent public merge commit, reconciliation applies the change relative to its first parent. Octopus/root commits require manual handling.

A successful canonical commit retains the public author's identity and adds:

```text
Community-Repository: hackelia-micrantha/keylix-community
Community-Commit: <full-public-sha>
```

These trailers are durable reconciliation provenance. Public and canonical issue/PR numbers remain repository-local; do not use them as cross-repository identifiers.

## Validate canonically

After applying the contribution, inspect the resulting canonical diff and run the complete canonical quality gate:

```bash
cargo fetch --locked
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python3 -m unittest discover -s scripts -p 'test_*.py'
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
```

Run additional adversarial/property/fuzz validation whenever the affected security boundary requires it.

The reconciliation branch then goes through normal canonical review/merge. Do not weaken validation because the contribution already passed public CI.

## Republish the canonical result

After canonical merge:

1. run **Publication Preview** against the exact canonical `main` SHA;
2. confirm the recorded `community_base_sha` still matches the public `main` containing the accepted contribution;
3. review the projection diff and provenance bundle;
4. run **Publish Community Candidate** with those exact reviewed SHAs;
5. merge the generated public publication PR only after normal public CI/review succeeds.

The publication pipeline refuses a stale public base. This prevents a canonical publication from silently overwriting community work that landed after preview.

## Conflict handling

If planning rejects a path or applying the commit conflicts with canonical state:

- stop the automated import;
- compare the public contribution against current canonical requirements/ADRs and implementation;
- create a normal canonical reconciliation branch with an explicit manual patch;
- preserve contributor attribution and the `Community-Commit` trailer;
- explain any semantic deviation from the public contribution in the canonical PR;
- rerun the complete canonical validation set;
- republish only the reconciled canonical outcome.

Never use last-writer-wins synchronization between the repositories.

## Public vs private issue routing

Use `keylix-community` for:

- public bugs and feature requests;
- standards/conformance discussions;
- API proposals;
- public documentation and examples;
- external implementation contributions.

Use canonical/private tracking for:

- deployment or environment-specific integration;
- publication credentials and protected-environment configuration;
- unreleased experiments that are not yet part of the public contract;
- operational evidence not suitable for publication;
- coordinated/embargoed security remediation.

Security semantics and releasable fixes must ultimately become inspectable in the public projection after coordinated disclosure/remediation.

## Initial exercise

Before relying on the helper for routine source changes, exercise one harmless documentation or deterministic test contribution end to end:

```text
community PR -> community main -> plan -> apply -> canonical CI/review
-> canonical merge -> publication preview -> publication PR -> public CI/review
```

Record the originating public SHA and resulting canonical SHA in the relevant issue/PR. That exercise is the acceptance proof for the first reconciliation workflow.
