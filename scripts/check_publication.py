#!/usr/bin/env python3
"""Block accidental credential publication in the current public Keylix tree.

This inspects Git-tracked source, not Git history, external releases, or the
canonical private-to-public projection. Print paths/rules, never secret bytes.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

BLOCKED_NAMES = frozenset({
    "id_rsa", "id_ed25519", "id_ecdsa", "credentials.json",
    "secrets.yaml", "secrets.yml",
})
BLOCKED_SUFFIXES = frozenset({
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".sqlite", ".db",
})
PRIVATE_ARMOR = re.compile(
    rb"-----BEGIN (?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|"
    rb"PGP PRIVATE KEY BLOCK)-----"
)
CHUNK_BYTES = 65536
MARKER_OVERLAP_BYTES = 100
EXAMPLES = (".example", ".sample", ".template")


def sensitive_path(relative: Path) -> bool:
    name = relative.name.lower()
    if name in BLOCKED_NAMES or relative.suffix.lower() in BLOCKED_SUFFIXES:
        return True
    if name in (".env", ".dev.vars"):
        return True
    if name.startswith((".env.", ".dev.vars.")) and not name.endswith(EXAMPLES):
        return True
    return False


def contains_private_armor(path: Path) -> bool:
    overlap = b""
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_BYTES):
            combined = overlap + chunk
            if PRIVATE_ARMOR.search(combined):
                return True
            overlap = combined[-MARKER_OVERLAP_BYTES:]
    return False


def tracked_files(root: Path) -> list[Path]:
    data = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "-z"],
        check=True, capture_output=True,
    ).stdout
    return [Path(os.fsdecode(item)) for item in data.split(b"\0") if item]


def inspect(root: Path, paths: list[Path]) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for rel in sorted(paths):
        label = rel.as_posix()
        if rel.is_absolute() or ".." in rel.parts:
            findings.append((label, "unsafe path"))
            continue
        file = root / rel
        if file.is_symlink():
            findings.append((label, "tracked symlink"))
        elif not file.is_file():
            findings.append((label, "missing tracked file"))
        elif sensitive_path(rel):
            findings.append((label, "credential-like path"))
        elif contains_private_armor(file):
            findings.append((label, "private-key armor"))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        findings = inspect(args.root, tracked_files(args.root))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print("keylix-publication: inspection unavailable (" +
              type(error).__name__ + ")", file=sys.stderr)
        return 2
    if findings:
        for name, reason in findings:
            label = name.encode("unicode_escape").decode("ascii")
            print(f"keylix-publication: blocked {label}: {reason}", file=sys.stderr)
        return 1
    print("keylix-publication: current tracked tree validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
