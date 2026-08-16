#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

output="${1:-target/keylix-package-evidence}"
rm -rf "$output" target/package
mkdir -p "$output/packages" "$output/manifests" "$output/payload"

# Canonical/local validation must package a committed tree. Publication preview
# deliberately operates on an uncommitted projected community checkout, whose
# exact source is instead bound by PUBLICATION-SOURCE.json and the surrounding
# immutable-SHA publication workflow.
if [[ ! -f PUBLICATION-SOURCE.json && -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "package validation requires a clean checkout outside a publication projection" >&2
  exit 1
fi

publishable=(
  keylix-core
  keylix-dpop
  keylix-http
  keylix-oauth
  keylix-observe
  keylix-mcp
)

metadata="$output/dependency-inventory.json"
cargo metadata --locked --format-version 1 > "$metadata"

python3 - "$metadata" "$output/publish-plan.json" <<'PY'
import json
from pathlib import Path
import sys
import tomllib

metadata_path = Path(sys.argv[1])
plan_path = Path(sys.argv[2])

with metadata_path.open(encoding="utf-8") as stream:
    metadata = json.load(stream)

root = Path.cwd()
with (root / "Cargo.toml").open("rb") as stream:
    workspace = tomllib.load(stream)

publish_order = [
    "keylix-core",
    "keylix-dpop",
    "keylix-http",
    "keylix-oauth",
    "keylix-observe",
    "keylix-mcp",
]
publishable = set(publish_order)
packages = {p["name"]: p for p in metadata["packages"] if p["name"] in publishable}
if set(packages) != publishable:
    missing = sorted(publishable - set(packages))
    raise SystemExit(f"missing publishable Keylix packages from cargo metadata: {missing}")

versions = {package["version"] for package in packages.values()}
if len(versions) != 1:
    raise SystemExit(f"publishable Keylix crates do not share one version: {sorted(versions)}")
version = next(iter(versions))

workspace_dependencies = workspace.get("workspace", {}).get("dependencies", {})
for name in publishable:
    dep = workspace_dependencies.get(name)
    if not isinstance(dep, dict):
        raise SystemExit(f"missing root workspace dependency contract for {name}")
    if dep.get("version") != f"={version}":
        raise SystemExit(
            f"{name} workspace dependency must use exact ={version}, got {dep.get('version')!r}"
        )
    if not dep.get("path"):
        raise SystemExit(f"{name} workspace dependency must retain a local development path")

edges = {}
for name in publish_order:
    package = packages[name]
    internal = []
    for dependency in package["dependencies"]:
        dep_name = dependency.get("name")
        if dep_name not in publishable:
            continue
        req = dependency.get("req")
        if req != f"={version}":
            raise SystemExit(
                f"{name} -> {dep_name} must require exact ={version}, got {req!r}"
            )
        internal.append(dep_name)
    edges[name] = sorted(internal)

seen = set()
for name in publish_order:
    unresolved = [dependency for dependency in edges[name] if dependency not in seen]
    if unresolved:
        raise SystemExit(
            f"publish order places {name} before required siblings: {', '.join(unresolved)}"
        )
    seen.add(name)

plan = {
    "schema_version": 1,
    "workspace_version": version,
    "publish_order": publish_order,
    "internal_dependencies": edges,
    "bootstrap_rule": (
        "Before the first coordinated registry release, only keylix-core can be fully "
        "packaged/verified. Each dependent crate is packaged and verified only after its "
        "exact Keylix registry dependencies are published and available."
    ),
}
plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

version="$(python3 - "$output/publish-plan.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["workspace_version"])
PY
)"

# keylix-core has no unpublished Keylix registry dependency. Cargo can therefore
# create its real .crate archive and run the normal isolated verification build.
# The archive checksum here is readiness evidence only: Cargo embeds VCS state
# in .cargo_vcs_info.json, so canonical and projected preview contexts are
# expected to have different archive hashes even when the package payload is
# otherwise identical. Final release package hashes must come from the exact
# committed keylix-community revision used for publication.
cargo package --locked --allow-dirty -p keylix-core

core_archive="target/package/keylix-core-${version}.crate"
[[ -f "$core_archive" ]] || {
  echo "missing expected package archive: $core_archive" >&2
  exit 1
}
cp "$core_archive" "$output/packages/"
sha256sum "$core_archive" | sed "s#  target/package/#  packages/#" > "$output/readiness-packages.sha256"

extract_dir="$output/payload/keylix-core-${version}"
mkdir -p "$extract_dir"
tar -xzf "$core_archive" -C "$output/payload"
cp "$extract_dir/Cargo.toml" "$output/manifests/keylix-core.Cargo.toml"
if [[ -f "$extract_dir/.cargo_vcs_info.json" ]]; then
  cp "$extract_dir/.cargo_vcs_info.json" "$output/keylix-core.cargo-vcs-info.json"
fi

# Build a deterministic payload manifest that excludes Cargo's context-specific
# VCS metadata. This lets canonical and projected readiness runs compare the
# actual package payload separately from the expected VCS-info difference.
(
  cd "$extract_dir"
  find . -type f ! -name '.cargo_vcs_info.json' -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
) > "$output/keylix-core.payload.sha256"
(
  cd "$output"
  sha256sum keylix-core.payload.sha256
) > "$output/keylix-core.payload-manifest.sha256"

if grep -Fq 'path = "../' "$output/manifests/keylix-core.Cargo.toml"; then
  echo "keylix-core packaged manifest retains a parent-relative dependency path" >&2
  exit 1
fi
if grep -Fq 'hackelia-micrantha/keylix"' "$output/manifests/keylix-core.Cargo.toml"; then
  echo "keylix-core packaged manifest points at the canonical repository" >&2
  exit 1
fi
grep -Fq 'hackelia-micrantha/keylix-community' "$output/manifests/keylix-core.Cargo.toml" || {
  echo "keylix-core packaged manifest does not point at the public repository" >&2
  exit 1
}

# Preserve the source manifests that define the dependent first-publish plan.
# Cargo deliberately cannot prepare those packages until their =VERSION sibling
# dependencies exist in the registry, so do not mislabel source inspection as a
# successful dependent .crate build.
for crate in "${publishable[@]:1}"; do
  cp "crates/$crate/Cargo.toml" "$output/manifests/$crate.source.Cargo.toml"
done
cp Cargo.toml "$output/manifests/workspace.source.Cargo.toml"

{
  printf 'workspace_version=%s\n' "$version"
  printf 'publishable_crate_count=%s\n' "${#publishable[@]}"
  printf 'verified_prepublication_archive_count=1\n'
  printf 'verified_prepublication_archive=keylix-core-%s.crate\n' "$version"
  printf 'archive_checksum_scope=readiness-only-vcs-context-dependent\n'
  printf 'final_release_checksum_source=exact-committed-keylix-community-revision\n'
  printf 'dependent_package_verification=required-after-exact-sibling-registry-publication\n'
  if [[ -f PUBLICATION-SOURCE.json ]]; then
    printf 'publication_source=PUBLICATION-SOURCE.json\n'
  else
    printf 'publication_source=clean-local-checkout\n'
  fi
} > "$output/package-evidence.txt"

if [[ -f PUBLICATION-SOURCE.json ]]; then
  cp PUBLICATION-SOURCE.json "$output/PUBLICATION-SOURCE.json"
fi

cat "$output/package-evidence.txt"
cat "$output/readiness-packages.sha256"
cat "$output/keylix-core.payload-manifest.sha256"
cat "$output/publish-plan.json"
