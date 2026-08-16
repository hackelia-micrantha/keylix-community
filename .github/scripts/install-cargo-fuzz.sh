#!/usr/bin/env bash
set -euo pipefail

version="0.13.2"
destination="${1:-$HOME/.local/bin}"

case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    target="x86_64-unknown-linux-musl"
    sha256="b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c"
    ;;
  Darwin:x86_64)
    target="x86_64-apple-darwin"
    sha256="27f1565e4d71b61ba57213e86feeb1a7adde0f6072b0bea6ffc6a1466f2e7853"
    ;;
  *)
    echo "unsupported cargo-fuzz bootstrap platform: $(uname -s)/$(uname -m)" >&2
    exit 2
    ;;
esac

asset="cargo-fuzz-${version}-${target}.tar.gz"
url="https://github.com/rust-fuzz/cargo-fuzz/releases/download/${version}/${asset}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

archive="$tmp/$asset"
mkdir -p "$destination" "$tmp/extract"
curl --fail --silent --show-error --location "$url" --output "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --status || {
  echo "cargo-fuzz ${version} checksum mismatch for ${target}" >&2
  exit 1
}

tar -xzf "$archive" -C "$tmp/extract"
binary="$(find "$tmp/extract" -type f -name cargo-fuzz -print -quit)"
[[ -n "$binary" ]] || {
  echo "cargo-fuzz binary not found in verified release archive" >&2
  exit 1
}

install -m 0755 "$binary" "$destination/cargo-fuzz"
"$destination/cargo-fuzz" --version >&2
printf '%s\n' "$destination/cargo-fuzz"
