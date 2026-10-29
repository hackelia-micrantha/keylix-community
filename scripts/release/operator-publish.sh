#!/usr/bin/env bash
set -euo pipefail
set +x

# Local operator only. Never install in Actions, expose Cargo tokens, or tag here.
readonly official_repository='hackelia-micrantha/keylix-community'
readonly canonical_sha='bf31dd5d0a1c13f16071959d7a417bb63199bb02'
readonly canonical_tree='26b86859b51d05a73001dfa170cbb0009d9d5e79'
readonly version='0.1.0'
readonly publish_order='keylix-core keylix-dpop keylix-http keylix-oauth keylix-observe keylix-mcp'

deny() { printf 'keylix-release: DENY %s\n' "$*" >&2; exit 1; }

check_arguments() {
  case "$1" in
    preflight|publish-one|verify-registry) ;;
    *) deny 'usage: operator-publish.sh preflight|verify-registry|publish-one SHA [crate]' ;;
  esac
  [[ "$2" =~ ^[a-f0-9]{40}$ ]] || deny 'require full 40-character public commit SHA'
  if [[ "$1" == publish-one ]]; then
    case "$3" in
      keylix-core|keylix-dpop|keylix-http|keylix-oauth|keylix-observe|keylix-mcp) ;;
      *) deny 'unknown publishable crate' ;;
    esac
  fi
}

check_checkout() {
  [[ "${GITHUB_ACTIONS:-}" != true ]] || deny 'privileged publication forbidden in Actions'
  [[ "${CI:-}" != true ]] || deny 'privileged publication forbidden in CI'
  command -v git >/dev/null || deny 'git missing'
  local root current remote_main
  root="$(git rev-parse --show-toplevel)" || deny 'not a Git checkout'
  [[ "$root" == "$PWD" ]] || deny 'invoke from repository root'
  [[ "$(git branch --show-current)" == main ]] || deny 'operator checkout must be public main'
  [[ -z "$(git status --porcelain --untracked-files=all)" ]] || deny 'checkout must be clean'
  current="$(git rev-parse HEAD)"
  [[ "$current" == "$expected_sha" ]] || deny 'checkout differs from reviewed exact public SHA'
  local origin
  origin="$(git remote get-url origin)"
  case "$origin" in
    "git@github.com:$official_repository.git"|"https://github.com/$official_repository.git"|"https://github.com/$official_repository") ;;
    *) deny 'wrong public origin' ;;
  esac
  remote_main="$(git ls-remote origin refs/heads/main | cut -f1)"
  [[ "$remote_main" == "$expected_sha" ]] || deny 'public main moved from reviewed release candidate'
  [[ -z "$(git ls-remote --tags origin refs/tags/v0.1.0)" ]] \
    || deny 'v0.1.0 remote tag already exists: release is not repeatable'
  python3 -B - "$canonical_sha" "$canonical_tree" <<'PY'
import json
import sys
from pathlib import Path

source = json.loads(Path("PUBLICATION-SOURCE.json").read_text(encoding="utf-8"))
if source.get("canonical_repository") != "hackelia-micrantha/keylix":
    raise SystemExit("DENY: unexpected canonical repository")
if source.get("canonical_sha") != sys.argv[1] or source.get("canonical_tree") != sys.argv[2]:
    raise SystemExit("DENY: canonical provenance mismatch")
if source.get("publication_policy") != "allowlist-v1":
    raise SystemExit("DENY: publication policy mismatch")
PY
}

registry_status() {
  local name="$1" code
  code="$(curl --silent --show-error --location --connect-timeout 5 --max-time 15 \
    --output /dev/null --write-out '%{http_code}' \
    "https://crates.io/api/v1/crates/$name/$version")" || deny "crates.io lookup failed for $name"
  case "$code" in
    200|404) printf '%s\n' "$code" ;;
    *) deny "unexpected crates.io HTTP $code for $name" ;;
  esac
}

check_dependency_registry() {
  local crate="$1" dependent
  # Read the source of truth rather than maintaining another dependency graph.
  local deps
  deps="$(python3 -B - "$crate" <<'PY'
import sys
import tomllib
from pathlib import Path

name = sys.argv[1]
order = "keylix-core keylix-dpop keylix-http keylix-oauth keylix-observe keylix-mcp".split()
with Path("Cargo.toml").open("rb") as stream:
    manifest = tomllib.load(stream)
with Path("crates", name, "Cargo.toml").open("rb") as stream:
    crate = tomllib.load(stream)
if manifest["workspace"]["package"]["version"] != "0.1.0":
    raise SystemExit("DENY: workspace version mismatch")
if crate["package"]["name"] != name:
    raise SystemExit("DENY: crate name mismatch")
for dependency in crate.get("dependencies", {}):
    if dependency in order:
        if order.index(dependency) >= order.index(name):
            raise SystemExit("DENY: sibling dependency violates topological order")
        spec = manifest["workspace"]["dependencies"].get(dependency)
        if not isinstance(spec, dict) or spec.get("version") != "=0.1.0":
            raise SystemExit("DENY: sibling dependency not exactly pinned")
        print(dependency)
PY
)" || deny 'invalid internal dependency graph'
  for dependent in $deps; do
    [[ "$(registry_status "$dependent")" == 200 ]] \
      || deny "dependency $dependent=0.1.0 not available in crates.io"
  done
}

verify_plan() {
  python3 -B - <<'PY'
import tomllib
from pathlib import Path

expected = "keylix-core keylix-dpop keylix-http keylix-oauth keylix-observe keylix-mcp".split()
with Path("Cargo.toml").open("rb") as stream:
    root = tomllib.load(stream)
if root["workspace"]["package"]["version"] != "0.1.0":
    raise SystemExit("DENY: wrong workspace version")
for package in expected:
    with Path("crates", package, "Cargo.toml").open("rb") as stream:
        value = tomllib.load(stream)
    if value["package"]["name"] != package:
        raise SystemExit("DENY: wrong package name")
    for dep in value.get("dependencies", {}):
        if dep in expected and expected.index(dep) >= expected.index(package):
            raise SystemExit("DENY: cyclic/non-topological internal dependency")
        if dep in expected:
            spec = root["workspace"]["dependencies"].get(dep)
            if not isinstance(spec, dict) or spec.get("version") != "=0.1.0":
                raise SystemExit("DENY: sibling version not exactly 0.1.0")
print("keylix-release: six-crate version/dependency plan verified")
PY
}

confirm_publish() {
  [[ -t 0 && -t 1 && -r /dev/tty ]] || deny 'operator must use a real interactive terminal'
  local expected response
  expected="PUBLISH $crate_name $version $short_sha"
  printf '\nExact public SHA: %s\nCrate: %s@%s\nType exactly: %s\n' \
    "$expected_sha" "$crate_name" "$version" "$expected"
  IFS= read -r response </dev/tty || deny 'operator terminal unavailable'
  [[ "$response" == "$expected" ]] || deny 'operator confirmation declined'
}

check_programs() {
  for program in curl python3 cargo sha256sum git; do
    command -v "$program" >/dev/null || deny "$program unavailable"
  done
}

check_evidence_directory() {
  [[ -n "${KEYLIX_RELEASE_EVIDENCE_DIR:-}" ]] || deny 'KEYLIX_RELEASE_EVIDENCE_DIR must be explicit and outside Git checkout'
  [[ "$KEYLIX_RELEASE_EVIDENCE_DIR" == /* ]] || deny 'audit directory must be absolute'
  [[ -d "$KEYLIX_RELEASE_EVIDENCE_DIR" && ! -L "$KEYLIX_RELEASE_EVIDENCE_DIR" ]] \
    || deny 'audit directory must already exist and not be a symlink'
  case "$KEYLIX_RELEASE_EVIDENCE_DIR/" in
    "$PWD/"*) deny 'audit must be outside public Git checkout' ;;
  esac
  [[ -w "$KEYLIX_RELEASE_EVIDENCE_DIR" ]] || deny 'audit directory not writable'
  umask 077
}

main() {
  local action="${1:-}"
  expected_sha="${2:-}"
  crate_name="${3:-}"
  short_sha="$(printf '%.12s' "$expected_sha")"
  check_arguments "$action" "$expected_sha" "$crate_name"
  check_checkout
  check_programs
  verify_plan
  case "$action" in
    verify-registry)
      local name code
      for name in $publish_order; do
        code="$(registry_status "$name")"
        printf '%s@%s HTTP %s\n' "$name" "$version" "$code"
      done
      ;;
    preflight)
      check_dependency_registry keylix-core
      cargo publish --dry-run --locked -p keylix-core
      printf 'keylix-release: core local non-upload preflight PASS at %s\n' "$expected_sha"
      ;;
    publish-one)
      check_evidence_directory
      [[ "$(registry_status "$crate_name")" == 404 ]] \
        || deny "crate $crate_name@$version already exists; refuse overwrite"
      check_dependency_registry "$crate_name"
      cargo publish --dry-run --locked -p "$crate_name"
      local package_archive="target/package/$crate_name-$version.crate"
      [[ -f "$package_archive" ]] || deny 'expected locally verified package archive missing'
      local local_checksum
      local_checksum="$(sha256sum "$package_archive" | cut -d' ' -f1)"
      local receipt="$KEYLIX_RELEASE_EVIDENCE_DIR/$crate_name-$version-$expected_sha.txt"
      [[ ! -e "$receipt" ]] || deny 'refuse to overwrite an earlier receipt'
      confirm_publish
      # Record attempted authority BEFORE registry effects; retain failures.
      # Never store Cargo credentials, tokens or private source.
      (
        umask 077
        set -C
        printf 'mode=single-operator\npublic_sha=%s\ncrate=%s\nversion=%s\nlocal_archive_sha256=%s\npublication_attempted=true\nregistry_checksum=UNVERIFIED\n' \
          "$expected_sha" "$crate_name" "$version" "$local_checksum" > "$receipt"
      )
      # Deliberate explicit operator side effect: only this command uploads.
      cargo publish --locked -p "$crate_name"
      printf 'publication_cli_exit=0\n' >> "$receipt"
      printf 'keylix-release: CLI upload returned success; REGISTRY CHECKSUM STILL UNVERIFIED: %s\n' "$receipt"
      ;;
  esac
}

main "$@"
