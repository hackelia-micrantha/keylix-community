# Keylix Publication Boundary

`hackelia-micrantha/keylix` is the private canonical repository. `hackelia-micrantha/keylix-community` is the public development, review, distribution, and release surface.

## Invariants

- Publication flows one way from the private canonical repository to this public repository through a reviewed allowlisted projection.
- Security semantics are public by default: protocol behavior, cryptographic design, threat models, public APIs, conformance tests, fuzz targets, and security-relevant ADRs belong here.
- Private deployment topology, credentials, operational evidence, embargoed vulnerabilities, unreleased experiments, and environment-specific configuration must not be published.
- Public and private implementations must not diverge into separate security semantics.
- External contributions are accepted against the public repository and must be reconciled into the private canonical repository before the next publication.
- Dependency/version automation runs against the canonical repository; generated dependency PRs must not create a community-only source-of-truth branch.
- Public issue and pull-request numbers are repository-local and must not be used as aliases for private canonical issue numbers.
- This repository is the externally consumable release authority, but not an independent implementation authority.

## Current-tree public CI guard

Every public pull request, merge-queue commit and push to main runs
`python3 scripts/check_publication.py` over all tracked files plus synthetic
regression tests. It blocks credential-like filenames, symlinks and PEM/PGP
private-key armor without emitting secret values. Public proof fixtures,
PGP public keys/signatures, and intentional protocol documents remain allowed.

This is an **additional defense**, not canonical publication authorization:
the private source allowlist/review/sealed-revision workflow below remains
mandatory. The guard neither searches historical Git objects and releases
nor proves that a private-to-public projection contains no sensitive
operational context.

## Publication gate

Canonical publication is an explicit reviewed operation:

1. the private repository selects an exact canonical commit and exact current community base commit;
2. the allowlisted projection is generated and validated;
3. the complete resulting public tree is secret-scanned;
4. formatting, static analysis, tests, documentation, package/readiness, and other release-relevant validation run against the projected tree;
5. the reviewed candidate is sealed to the exact input revisions/tree;
6. the protected publication job creates a `publication/<canonical-sha>` branch and pull request here;
7. public CI/review remains authoritative before `main` changes.

Publication does not push directly to `main`. A moved community base invalidates the reviewed candidate and requires a fresh preview.

`PUBLICATION-SOURCE.json` records the exact canonical commit/tree that produced the current projected public source state.

## Release authority

For an externally supported release, the exact committed public revision in this repository is the artifact source of truth.

```text
private keylix canonical source
        -> reviewed projection
keylix-community committed public revision
        -> public tag / GitHub Release
        -> Cargo artifacts and public Nix consumption
        -> supported downstream integrations
```

The matching `keylix-community` tag/GitHub Release is the public release identity. Cargo registry packages, GitHub release artifacts, and public Nix consumption must correspond to that same public release revision/version.

Supported downstream consumers must not depend on private `hackelia-micrantha/keylix` source, private Git history, canonical-only paths, or publication credentials. They pin this public repository by immutable release tag/revision or consume immutable public release artifacts.

The reviewed public `flake.nix` and `flake.lock` are now committed here through the protected publication path. The public flake is the reproducible source/toolchain boundary and currently exposes the pre-release `keylix-verifier` package/app together with checks for its shipped contract surface. Its committed presence on `main` does **not** by itself establish a supported release.

Supported downstream Nix consumption must bind to an immutable public release tag/revision that explicitly establishes support and must correspond to the same public revision as Cargo packages and other release artifacts. Before that release exists, consumers may inspect and qualify the committed public flake, verifier package, and public contract documentation, but must not treat `main` as a stable supported interface.

The current projected source also includes public client protocol/design contracts under `client/docs`. Those documents define future SDK-facing behavior within the public review surface; they are not evidence that a separately versioned client SDK has been released.

The archived `hackelia-micrantha/keylix-client` repository is historical evidence only; it is not a parallel release authority. Future client SDK/release work originates from canonical Keylix and follows this same public release identity model.
