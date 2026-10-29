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
6. a public workflow dispatch on protected main pauses for approval in
   the public keylix-community-publication GitHub environment;
7. after required approval, the public job replays the exact private
   Publication Preview patch on the reviewed public base, verifies the
   ZIP digest, source SHA, sealed tree, complete manifest and secret-scan receipt;
8. it opens only a publication candidate PR, never pushes public main;
9. public CI and independent review remain mandatory before merging.

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

## Free-plan approval setup (currently inactive)

The old private Publish Community Candidate credential-bearing workflow is
retired. The private Publication Preview still creates validated, secret-scanned,
immutable review artifacts. **GitHub Free required reviewers are available only
for public repositories**, so authorization moves here, NOT source authority.

Configure Settings > Environments > keylix-community-publication in this PUBLIC
repository: require a **different trusted human reviewer**, enable **prevent
self-review**, and restrict eligible deployment branches to main. Protect public
main with pull-request review/required CI. AI/Supervisor review is supplemental,
not a substitute for a distinct human approver.

Only after these controls are verified, add the following ENVIRONMENT secrets:
KEYLIX_PRIVATE_PREVIEW_READ_TOKEN (fine-grained private canonical Actions:read
and Metadata:read) and KEYLIX_PUBLICATION_WRITE_TOKEN (fine-grained public
Contents:read/write, Pull requests:read/write). Use expiring scoped credentials.
Never use repository-level secrets or store credentials in workflow inputs.
Rotate the existing private publisher token before production use.

Review the successful private Publication Preview diff, source/commit receipts,
sealed candidate Git tree and SHA-256 of its actual ZIP. Dispatch
Actions > Approve Keylix Publication from public main, enter the two source
SHAs, candidate tree, successful preview run ID, artifact ID, ZIP SHA-256
and confirmation PUBLISH. Preflight has no secrets; a PUBLIC environment
approval releases the protected job. The approved job checks official GitHub
run and artifact identity, exact ZIP digest, canonical/public SHAs, Gitleaks
report, full file manifest and rebuilt candidate Git tree, then opens only
a public candidate PR. Stale inputs and repeat branches fail closed.

Before activating, test that unapproved jobs cannot access secrets,
self-approval is denied, missing credentials fail, bad SHA/digest/tree,
moved public base and duplicate branch all fail without publication.
Confirm the approved test creates a PUBLIC PR only and that public CI
and independent PR review still gate public main.

If there is no second trusted human, DO NOT claim two-person approval. Keep
this publisher disabled and use a separately controlled manual operator-held
credential with documented single-operator risk acceptance. That fallback
is NOT implemented by this approval workflow.

This PR neither provisions credentials/reviewer settings nor creates
a supported v0.1.0 tag or Cargo registry publication.
