#!/usr/bin/env bash
set -euo pipefail

version="0.20.2"
destination="${1:-$HOME/.local/bin}"

case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    target="x86_64-unknown-linux-musl"
    sha256="9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f"
    ;;
  Linux:aarch64|Linux:arm64)
    target="aarch64-unknown-linux-musl"
    sha256="995c82be0defc7a025cae49a2aa2644ce8245c9a3318fc4103907c6a285e8c7d"
    ;;
  Darwin:x86_64)
    target="x86_64-apple-darwin"
    sha256="248da7f581724e470071990c088ffc55c811981715f4cbdb258621fb79f8b7a6"
    ;;
  Darwin:arm64|Darwin:aarch64)
    target="aarch64-apple-darwin"
    sha256="fe67d82a10d8597a3549364cb733a3f9cc1bfff9031b7ae46384a9f2a72090c3"
    ;;
  *)
    echo "unsupported cargo-deny bootstrap platform: $(uname -s)/$(uname -m)" >&2
    exit 2
    ;;
esac

asset="cargo-deny-${version}-${target}.tar.gz"
url="https://github.com/EmbarkStudios/cargo-deny/releases/download/${version}/${asset}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

archive="$tmp/$asset"
mkdir -p "$destination" "$tmp/extract"
curl --fail --silent --show-error --location "$url" --output "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --status || {
  echo "cargo-deny ${version} checksum mismatch for ${target}" >&2
  exit 1
}

tar -xzf "$archive" -C "$tmp/extract"
binary="$(find "$tmp/extract" -type f -name cargo-deny -print -quit)"
[[ -n "$binary" ]] || {
  echo "cargo-deny binary not found in verified release archive" >&2
  exit 1
}

install -m 0755 "$binary" "$destination/cargo-deny"
"$destination/cargo-deny" --version >&2
printf '%s\n' "$destination/cargo-deny"
