# Release contract

Keylix is a coordinated Rust crate set. The workspace version and exact internal dependency requirements move together.

## Public crates

The intended registry packages are:

1. `keylix-core`
2. `keylix-dpop`
3. `keylix-http`
4. `keylix-oauth`
5. `keylix-observe`
6. `keylix-mcp`

`keylix-conformance` and the fuzz workspace are intentionally not published as registry packages.

All publishable Keylix sibling dependencies are declared in the root `[workspace.dependencies]` with both a local `path` and an exact `=VERSION` requirement. Local development therefore uses the workspace source while Cargo uses the registry version when preparing a package for publication.

Cargo's `version` key denotes registry availability even when a local path is also present. This means the first coordinated release has an unavoidable bootstrap sequence: Cargo cannot prepare a dependent package for publication until its exact Keylix sibling version exists in the target registry.

## Pre-publication package-readiness evidence

Run:

```bash
bash scripts/release/package-public.sh
```

Outside the canonical publication pipeline this requires a clean checkout. Publication Preview runs the same script against the reviewed projected public tree, where `PUBLICATION-SOURCE.json` binds the intentionally uncommitted projection to an exact canonical commit/tree.

Before any Keylix version exists in the registry, the evidence directory contains:

- the real, fully `cargo package`-verified `keylix-core` `.crate` archive;
- its **readiness-only** SHA-256 checksum and normalized packaged manifest;
- Cargo's `.cargo_vcs_info.json` from that readiness archive;
- a context-independent content manifest that hashes the packaged payload while excluding `.cargo_vcs_info.json`;
- the locked Cargo dependency inventory for the complete workspace;
- a machine-readable publish plan proving one shared version, exact internal version requirements, and a valid topological order;
- source manifests for dependent public crates, clearly labeled as source manifests rather than built `.crate` archives;
- publication-source provenance when run against a projected public tree.

The validator rejects a core package that retains parent-relative dependency paths or points users at the canonical repository rather than `keylix-community`.

### Readiness checksum versus final release checksum

Cargo embeds repository context in `.cargo_vcs_info.json`. Consequently, the canonical readiness archive and a dirty publication-preview archive may have different whole-archive hashes even when every other packaged file is identical. The readiness bundle preserves both the archive checksum and a payload manifest that excludes this context-specific VCS file so the distinction is reviewable rather than hidden.

Neither canonical CI nor an uncommitted Publication Preview defines the final registry artifact checksum.

The **final release package must be constructed from the exact committed `keylix-community` release revision**, after the canonical projection has landed and public CI/review has completed. Checksums recorded for that committed public revision are the release-artifact checksums.

The pre-publication gate does **not** claim that dependent `.crate` archives exist or have passed isolated registry verification before their required sibling versions are actually available.

## First coordinated publication

`keylix-core` is published and verified first. Each next package is prepared and verified only after all exact Keylix registry dependencies it requires are available.

Required dependency order:

```text
keylix-core
  -> keylix-dpop
       -> keylix-http
       -> keylix-oauth
            -> keylix-observe
            -> keylix-mcp
```

Operationally:

1. from the exact committed `keylix-community` release revision, package/verify `keylix-core` and record the release checksum;
2. publish `keylix-core`, then confirm `keylix-core =0.1.0` is available from the target registry;
3. package/verify and publish `keylix-dpop` from that same public revision;
4. after `keylix-dpop =0.1.0` is available, package/verify `keylix-http` and `keylix-oauth`;
5. after `keylix-oauth =0.1.0` is available, package/verify `keylix-observe` and `keylix-mcp`;
6. stop immediately if any registry package differs from the reviewed source or fails its normal Cargo verification/build.

Do not use `--no-verify` to represent dependent packages as registry-ready. Workspace CI/conformance proves the integrated source tree; isolated Cargo package verification is separate release evidence and occurs at the point each registry dependency becomes resolvable.

## Release evidence

A `v0.1.0` release is not ready solely because `keylix-core` can be packaged or because workspace tests pass. The release candidate must also have:

- the private-canonical/public-community authority controls from canonical issue #29;
- a reviewed publication projection from the exact candidate revision;
- green public/canonical validation and dependency-advisory policy;
- successful exact-revision Release Candidate Fuzz evidence;
- reviewed package-readiness evidence and the staged registry verification results;
- final package checksums generated from the exact committed public release revision;
- the locked dependency inventory for artifacts actually produced;
- no unsupported claim of independent audit/interoperability if that evidence has not occurred.

Final registry credentials and publication are separate privileged release operations and must not be exposed to pull-request workflows.
