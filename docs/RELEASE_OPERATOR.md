# First Keylix 0.1.0 release — single-operator procedure

## Explain it to a human

A successful source build is not a public release. Publish the six Keylix
crates sequentially, and only from one exact reviewed public commit, after
each necessary registry dependency exists. Separate the release decision,
the credential-backed registry uploads and the final immutable GitHub tag.

This guide is a plan and safety control; it does not itself approve
publishing to crates.io or waive independent interoperability acceptance.

## Pre-publication release authority

The operator must check these gates before any irreversible registry action:

1. Public community release commit is final, fully qualified, protected,
   reviewed and green on both public CI and source-security gates. Its
   publication-source identity must match the reviewed private canonical
   tree. Do not use a mutable main branch for downstream dependencies.
2. The current Git commit has the exact v0.1.0 Cargo workspace version
   and six exact-version internal dependencies. No public v0.1.0 tag/Release
   exists. All six desired crate names are confirmed controlled/unclaimed.
3. Independent interoperability evidence is recorded **or** a concrete,
   explicitly approved and bounded pre-1.0 deferral is documented. Existing
   independent OpenSSL/ES256 vectors and the self-contained MCP test suite
   are not a third-party end-to-end review; SEP-1932 remains a draft.
4. Historical publisher token retirement is independently verified. Any
   current publishing token is held on the trusted operator workstation only.
   Do not add it to GitHub Actions, repository secrets or the public tree.
5. Package-readiness evidence, Rust/conformance tests and reviewed fuzz
   receipts are tied to the exact source. A green dry run cannot
   authenticate a registry owner or prove a future registry checksum.

The old candidate SHA b5b083e034516aeb398f4b3726c20230cf0d9f7c
was verified before this release-operator tooling was added. Use the final
NEW receiving-main SHA after this tool's PR merges, regenerate checksums,
and update issue #33. Never pass the old SHA as if it were the new release
commit.

## Operator commands

Only on a clean, current checkout of hackelia-micrantha/keylix-community
main, with an authenticated LOCAL Cargo registry client and SSH Git origin:

    git switch main
    git pull --ff-only
    RELEASE_SHA="$(git rev-parse HEAD)"
    bash scripts/release/operator-publish.sh verify-registry "$RELEASE_SHA"
    bash scripts/release/operator-publish.sh preflight "$RELEASE_SHA"

These read-only checks verify the exact GitHub public origin, current clean
main, SHA, canonical provenance, package versions and registry state.
Preflight runs Cargo publish --dry-run --locked for core. No token or
registry upload is needed for the dry run.

Only after explicit, separate publication authority and a successful
preflight, create a private owner-only evidence directory OUTSIDE the
checkout and opt in to one privileged crate publication at a time:

    umask 077
    mkdir -p "$HOME/.local/state/keylix-release-v0.1.0"
    chmod 700 "$HOME/.local/state/keylix-release-v0.1.0"
    export KEYLIX_RELEASE_EVIDENCE_DIR="$HOME/.local/state/keylix-release-v0.1.0"

    bash scripts/release/operator-publish.sh publish-one "$RELEASE_SHA" keylix-core

The script requires an exact typed terminal confirmation including the
crate name/version and first 12 characters of the release SHA. It refuses
Actions/CI, wrong or dirty origin, moving public main, tag preexistence,
wrong canonical identity, a published crate/version, or missing sibling
registry dependencies. It runs Cargo's normal package verification without
--allow-dirty or --no-verify. It records a private local attempted-publication
receipt before the registry side effect; after a successful Cargo return it
appends publication_cli_exit=0. A command success **does not** prove
registry index availability or checksum consistency.

Check the actual crates.io version and published checksum against the local
archive, and retain the registry-verified receipt, before proceeding to:

    keylix-dpop
    keylix-http
    keylix-oauth
    keylix-observe
    keylix-mcp

Call publish-one separately for each crate, changing only its name. Never
retry an ambiguous failed upload blindly; if the receipt already exists or
registry visibility is uncertain, investigate first. The tool refuses
overwriting an existing audit receipt to protect that decision boundary.

## Final public release gate

Once all six versions are discoverable in the target registry, re-fetch each
.crate archive/checksum independently and compare its exact package VCS
source identity and local archive checksum. Complete the release manifest
with every SHA, existing successful CI/run/artifact references, Cargo.lock
inventory, interoperability decision, and credential-retirement evidence.

Then separately approve the immutable v0.1.0 tag and GitHub Release for
the *same* exact public commit. Do not publish a supported release from
the wrong commit or infer it from green CI. GitHub Release creation
is NOT handled by the operator-publish tool.

The supported Dubnium verifier installation still requires a subsequent
public-only pin and independent runtime/AF_UNIX contract qualification.
Even a valid Keylix release never grants GitHub principal authentication,
an Anthesis allow, a registered OCI provider or physical Gateway authority.

See Keylix #33/#52 and Dubnium #1275 for the separate blocked gates.
