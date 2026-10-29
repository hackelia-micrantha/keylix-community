#!/usr/bin/env python3
"""Reconstruct a reviewed private preview only after public environment approval."""
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen
import zipfile

PRIVATE = "hackelia-micrantha/keylix"
PUBLIC = "hackelia-micrantha/keylix-community"
PREVIEW_PATH = ".github/workflows/publication-preview.yml"
ROOT_PATHS = frozenset((
    "Cargo.toml", "Cargo.lock", "deny.toml", "flake.nix", "flake.lock",
    "LICENSE", "rust-toolchain.toml", "crates", "docs", "fuzz",
    "tests", "scripts", "client", "PUBLICATION-SOURCE.json",
))
SHA = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
MAX_ZIP_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def git(*args):
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    require(result.returncode == 0, "git " + args[0] + " failed: " + result.stderr[:250])
    return result.stdout.strip()


def validate_inputs(canonical, public_sha, tree, digest, run_id, artifact_id):
    for name, value in (("canonical", canonical), ("public", public_sha), ("tree", tree)):
        require(SHA.fullmatch(value) is not None, "invalid " + name + " SHA")
    require(DIGEST.fullmatch(digest) is not None, "invalid artifact digest")
    for name, value in (("run", run_id), ("artifact", artifact_id)):
        require(value.isascii() and value.isdecimal() and int(value) > 0, "invalid " + name + " ID")


def api(endpoint, token):
    req = Request("https://api.github.com" + endpoint, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Keylix-approved-publication-v1",
    })
    with urlopen(req, timeout=30) as response:
        return json.load(response)


class StopRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, url):
        return None


def download_zip(artifact_id, token):
    req = Request(
        "https://api.github.com/repos/" + PRIVATE + "/actions/artifacts/" + artifact_id + "/zip",
        headers={"Authorization": "Bearer " + token,
                 "User-Agent": "Keylix-approved-publication-v1"},
    )
    try:
        with build_opener(StopRedirect()).open(req, timeout=40) as response:
            require(response.status == 200, "unexpected ZIP response")
            data = response.read(MAX_ZIP_BYTES + 1)
    except HTTPError as error:
        if error.code not in (301, 302, 303, 307, 308):
            raise
        url = error.headers.get("Location", "")
        require(url.startswith("https://"), "insecure artifact redirect")
        # No authentication header is sent to the signed artifact storage URL.
        with urlopen(Request(url), timeout=90) as response:
            data = response.read(MAX_ZIP_BYTES + 1)
    require(0 < len(data) <= MAX_ZIP_BYTES, "ZIP is empty or oversized")
    return data


def member(zipped, name):
    # The reviewed private preview contract puts each authoritative receipt at
    # ZIP root. Nested package-evidence can legitimately repeat provenance,
    # but must never substitute for the root review authority.
    entries = [x for x in zipped.infolist() if x.filename == name]
    require(len(entries) == 1, "missing or duplicated root artifact member: " + name)
    require(entries[0].file_size <= MAX_MEMBER_BYTES, "oversized artifact member")
    return zipped.read(entries[0])


def read_preview(zipped, canonical, public_sha):
    names = ("review-inputs.txt", "publication.diff", "gitleaks.json",
             "publication.manifest.sha256", "PUBLICATION-SOURCE.json")
    files = {name: member(zipped, name) for name in names}
    receipt = files["review-inputs.txt"].decode().splitlines()
    require(receipt == [
        "canonical_sha=" + canonical, "community_base_sha=" + public_sha
    ], "reviewed immutable inputs do not match")
    require(json.loads(files["gitleaks.json"]) == [], "Gitleaks report is not clean")
    require(json.loads(files["PUBLICATION-SOURCE.json"]).get("canonical_sha") == canonical,
            "publication provenance differs from reviewed source")
    require(bool(files["publication.diff"]), "empty publication patch")
    return files


def allowed_path(path):
    if path == "PUBLICATION-SOURCE.json":
        return True
    if path in ("README.md", "PUBLICATION.md", "CONTRIBUTING.md", "SECURITY.md",
                ".gitignore", ".gitmodules") or path.startswith((".github/", ".git/", "/")):
        return False
    root = path.split("/", 1)[0]
    if root not in ROOT_PATHS:
        return False
    if root == "tests":
        return path in ("tests/fixtures/keylix-cross-uid-client.py",
                        "tests/verifier-cross-uid-vm.nix")
    if root == "scripts":
        return path.startswith("scripts/release/")
    if root == "client":
        return path.startswith("client/docs/")
    return True


def verify_candidate(files, public_sha, tree, workspace):
    require(git("rev-parse", "HEAD") == public_sha, "checkout not at reviewed public base")
    require(git("ls-remote", "origin", "refs/heads/main").split()[0] == public_sha,
            "public main moved from reviewed base")
    require(not git("status", "--porcelain", "--untracked-files=all"), "dirty checkout")
    patch = workspace / ".git" / "reviewed-publication.diff"
    try:
        patch.write_bytes(files["publication.diff"])
        for flags in (("--check", "--index", "--binary"),
                      ("--index", "--binary")):
            result = subprocess.run(["git", "apply", *flags, str(patch)],
                                    capture_output=True, check=False)
            require(result.returncode == 0, "reviewed patch did not apply cleanly")
    finally:
        patch.unlink(missing_ok=True)
    changed = [v for v in git("diff", "--cached", "--name-only", "-z").split("\0") if v]
    require(bool(changed) and all(allowed_path(p) for p in changed),
            "patch modifies public control or non-allowlisted path")
    require(git("write-tree") == tree, "reconstructed candidate Git tree mismatch")
    require((workspace / "PUBLICATION-SOURCE.json").read_bytes() ==
            files["PUBLICATION-SOURCE.json"], "publication provenance mismatch")
    result = subprocess.run(["sha256sum", "--check", "--strict"],
                            input=files["publication.manifest.sha256"],
                            capture_output=True, cwd=workspace, check=False)
    require(result.returncode == 0, "full-public-tree SHA256 manifest mismatch")
    require(git("ls-remote", "origin", "refs/heads/main").split()[0] == public_sha,
            "public main advanced after validation")


def main():
    env = os.environ
    canonical = env["CANONICAL_SHA"]
    public_sha = env["COMMUNITY_SHA"]
    tree = env["CANDIDATE_TREE"]
    digest = env["PREVIEW_ARCHIVE_SHA256"]
    run_id = env["PREVIEW_RUN_ID"]
    artifact_id = env["PREVIEW_ARTIFACT_ID"]
    validate_inputs(canonical, public_sha, tree, digest, run_id, artifact_id)
    require(env.get("GITHUB_REPOSITORY") == PUBLIC and
            env.get("GITHUB_REF") == "refs/heads/main",
            "approval workflow must run from public main")
    require(env.get("GITHUB_SHA") == git("rev-parse", "HEAD"),
            "checked-out workflow revision differs from authenticated run")
    private_token = env["KEYLIX_PRIVATE_PREVIEW_READ_TOKEN"]
    public_token = env["KEYLIX_PUBLICATION_WRITE_TOKEN"]
    require(bool(private_token) and bool(public_token),
            "protected environment credentials unavailable")
    run = api("/repos/" + PRIVATE + "/actions/runs/" + run_id, private_token)
    require(run.get("event") == "workflow_dispatch" and
            run.get("head_branch") == "main" and
            run.get("path") == PREVIEW_PATH and
            run.get("conclusion") == "success" and
            run.get("status") == "completed",
            "preview is not a successful reviewed main-branch run")
    artifact = api("/repos/" + PRIVATE + "/actions/artifacts/" + artifact_id, private_token)
    require(artifact.get("name") == "keylix-publication-" + canonical and
            artifact.get("workflow_run", {}).get("id") == int(run_id) and
            artifact.get("digest") == "sha256:" + digest and
            not artifact.get("expired"), "wrong or expired preview artifact")
    data = download_zip(artifact_id, private_token)
    require(hmac.compare_digest(hashlib.sha256(data).hexdigest(), digest),
            "actual ZIP does not match reviewed SHA-256")
    with zipfile.ZipFile(io.BytesIO(data)) as zipped:
        files = read_preview(zipped, canonical, public_sha)
    workspace = Path(env["GITHUB_WORKSPACE"])
    verify_candidate(files, public_sha, tree, workspace)
    branch = "publication/" + canonical
    require(not git("ls-remote", "--heads", "origin", "refs/heads/" + branch),
            "publication branch exists; refusing overwrite")
    git("config", "user.name", "keylix-publication[bot]")
    git("config", "user.email", "keylix-publication[bot]@users.noreply.github.com")
    git("commit", "-m", "chore(publication): project Keylix " + canonical[:12])
    require(git("rev-parse", "HEAD^{tree}") == tree, "commit tree changed")
    auth_env = dict(env, GH_TOKEN=public_token)
    subprocess.run(["gh", "auth", "setup-git"], check=True, env=auth_env)
    subprocess.run(["git", "push", "origin", "HEAD:refs/heads/" + branch],
                   check=True, env=auth_env)
    body = ("## Public environment-approved Keylix publication\n\n"
            "Canonical SHA: " + canonical + "\n"
            "Reviewed community base: " + public_sha + "\n"
            "Sealed candidate Git tree: " + tree + "\n"
            "Successful private preview run: " + run_id + "\n"
            "Reviewed artifact: " + artifact_id + "\n"
            "Artifact SHA-256: " + digest + "\n\n"
            "Environment approval preceded credential access. Replayed patch "
            "and full-tree manifest match the exact reviewed candidate. "
            "Public CI and PR review remain required; no main push.\n")
    subprocess.run([
        "gh", "pr", "create", "--repo", PUBLIC, "--base", "main",
        "--head", branch, "--title",
        "chore(publication): publish Keylix " + canonical[:12],
        "--body", body,
    ], check=True, env=auth_env)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, zipfile.BadZipFile) as error:
        print("Publication denied:", error, file=sys.stderr)
        sys.exit(1)
