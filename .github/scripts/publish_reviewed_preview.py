#!/usr/bin/env python3
"""Local-only, single-operator publication of an exact reviewed Keylix preview.

Migration bridge: this existing Python validator is reused until a vetted Rust
replacement exists; no privileged Actions workflow may run it.
"""
import argparse
import datetime
import hashlib
import hmac
import io
import json
import os
import shutil
from pathlib import Path
import re
import subprocess
import sys
import tempfile
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



def local_gh_token():
    """Use the operator's existing GitHub CLI login; never print or save its token."""
    require(shutil.which("gh") is not None, "gh CLI is required on the operator host")
    result = subprocess.run(["gh", "auth", "token"], capture_output=True,
                            text=True, check=False)
    require(result.returncode == 0 and bool(result.stdout.strip()),
            "gh is not authenticated; run gh auth login on the trusted workstation")
    return result.stdout.strip()


def check_operator_checkout():
    """Source and publishing logic must be the current trusted public main."""
    require(os.environ.get("GITHUB_ACTIONS") != "true",
            "local-only publication cannot run from GitHub Actions")
    require(os.environ.get("CI", "").lower() in ("", "false", "0"),
            "local publication cannot run in CI")
    repo = git("rev-parse", "--show-toplevel")
    require(Path(repo).resolve() == Path(__file__).resolve().parents[2],
            "invoke the trusted public script from its own public checkout")
    require(git("branch", "--show-current") == "main",
            "operator checkout must be on public main")
    require(not git("status", "--porcelain", "--untracked-files=all"),
            "operator checkout has uncommitted or untracked work")
    remote = git("remote", "get-url", "origin")
    require(remote in (
        "git@github.com:" + PUBLIC + ".git",
        "https://github.com/" + PUBLIC + ".git",
        "https://github.com/" + PUBLIC,
    ), "public origin does not match the expected official repository")
    current = git("rev-parse", "HEAD")
    actual = git("ls-remote", "origin", "refs/heads/main").split()[0]
    require(current == actual, "local public main is stale; fetch/rebase first")
    return current


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Publish reviewed Keylix preview from a trusted local console; never from Actions."
    )
    parser.add_argument("--canonical-sha", required=True)
    parser.add_argument("--community-sha", required=True)
    parser.add_argument("--candidate-tree", required=True)
    parser.add_argument("--preview-run-id", required=True)
    parser.add_argument("--preview-artifact-id", required=True)
    parser.add_argument("--preview-archive-sha256", required=True)
    parser.add_argument("--dry-run", action="store_true",
                        help="Replay and verify exactly; do not prompt, commit, push or create PR")
    parser.add_argument("--receipt", type=Path,
                        help="Write an operator audit receipt outside the Git checkout, mode 0600")
    return parser.parse_args(argv)


def record_receipt(path, details):
    if path is None:
        return
    path = path.expanduser().resolve()
    require(not path.exists(), "refuse to overwrite an existing audit receipt")
    # No secrets, private source or artifact contents are ever recorded.
    data = (json.dumps(details, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as receipt:
        receipt.write(data)


def operator_confirm(canonical, public_sha, candidate, artifact_digest):
    require(sys.stdin.isatty() and sys.stdout.isatty(),
            "publishing requires a real interactive terminal")
    print("\nPRIVATE CANONICAL:", canonical)
    print("REVIEWED PUBLIC BASE:", public_sha)
    print("VERIFIED CANDIDATE TREE:", candidate)
    print("REVIEWED ARTIFACT SHA-256:", artifact_digest)
    expected = "PUBLISH " + canonical[:12]
    try:
        with open("/dev/tty", encoding="utf-8") as console:
            print("Type exactly " + expected + " to authorize the public PR: ")
            confirmation = console.readline().strip()
    except OSError as error:
        raise RuntimeError("no trusted interactive console") from error
    require(confirmation == expected, "explicit operator confirmation declined")


def publish(args):
    validate_inputs(args.canonical_sha, args.community_sha, args.candidate_tree,
                    args.preview_archive_sha256, args.preview_run_id,
                    args.preview_artifact_id)
    public_head = check_operator_checkout()
    require(public_head == args.community_sha,
            "reviewed public base differs from the trusted current public main")
    if args.receipt is not None:
        receipt_path = args.receipt.expanduser().resolve()
        operator_root = Path.cwd().resolve()
        require(not receipt_path.exists(), "refuse existing operator receipt")
        require(operator_root not in receipt_path.parents,
                "operator receipt must be outside the source checkout")
        require(receipt_path.parent.is_dir() and
                os.access(receipt_path.parent, os.W_OK),
                "operator receipt destination must already be writable")
    token = local_gh_token()
    run = api("/repos/" + PRIVATE + "/actions/runs/" + args.preview_run_id, token)
    require(run.get("event") == "workflow_dispatch" and
            run.get("head_branch") == "main" and
            run.get("head_sha") == args.canonical_sha and
            run.get("path") == PREVIEW_PATH and
            run.get("conclusion") == "success" and
            run.get("status") == "completed",
            "private preview run is not a successful exact-source main dispatch")
    artifact = api(
        "/repos/" + PRIVATE + "/actions/artifacts/" + args.preview_artifact_id,
        token
    )
    require(artifact.get("name") == "keylix-publication-" + args.canonical_sha and
            artifact.get("workflow_run", {}).get("id") == int(args.preview_run_id) and
            artifact.get("digest") == "sha256:" + args.preview_archive_sha256 and
            not artifact.get("expired"), "preview artifact does not match reviewed receipt")
    data = download_zip(args.preview_artifact_id, token)
    require(hmac.compare_digest(hashlib.sha256(data).hexdigest(),
                                args.preview_archive_sha256),
            "actual private preview ZIP SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as zipped:
        files = read_preview(zipped, args.canonical_sha, args.community_sha)
    # Scope: an isolated throwaway Git checkout, never user's working tree.
    with tempfile.TemporaryDirectory(prefix="keylix-solo-publication-") as temporary:
        workspace = Path(temporary) / "community"
        subprocess.run([
            "git", "clone", "--quiet", "--depth", "1", "--branch", "main",
            "git@github.com:" + PUBLIC + ".git", str(workspace),
        ], check=True)
        original = Path.cwd()
        try:
            os.chdir(workspace)
            verify_candidate(files, args.community_sha, args.candidate_tree, workspace)
            branch = "publication/" + args.canonical_sha
            require(not git("ls-remote", "--heads", "origin",
                            "refs/heads/" + branch),
                    "publication branch already exists; refuse overwrite")
            receipt = {
                "mode": "dry-run" if args.dry_run else "single-operator",
                "canonical_sha": args.canonical_sha,
                "community_sha": args.community_sha,
                "candidate_tree": args.candidate_tree,
                "preview_run_id": args.preview_run_id,
                "preview_artifact_id": args.preview_artifact_id,
                "preview_archive_sha256": args.preview_archive_sha256,
                "public_workflow_revision": public_head,
                "validated_at_utc": datetime.datetime.now(
                    datetime.timezone.utc).isoformat(),
                "source": "verified GitHub preview; local operator authorization",
                "status": "validated-not-published",
            }
            if args.dry_run:
                record_receipt(args.receipt, receipt)
                print("DRY RUN PASS: verified candidate tree", args.candidate_tree,
                      "— NO BRANCH/PR CREATED")
                return
            operator_confirm(args.canonical_sha, args.community_sha,
                             args.candidate_tree, args.preview_archive_sha256)
            # Recheck remote state *after* human review/confirmation.
            require(git("ls-remote", "origin", "refs/heads/main").split()[0] ==
                    args.community_sha, "public main moved before push")
            require(not git("ls-remote", "--heads", "origin",
                            "refs/heads/" + branch),
                    "publication branch was created by another operator")
            git("config", "user.name", "keylix-publication[operator]")
            git("config", "user.email",
                "keylix-publication[operator]@users.noreply.github.com")
            git("commit", "-m",
                "chore(publication): project Keylix " + args.canonical_sha[:12])
            require(git("rev-parse", "HEAD^{tree}") == args.candidate_tree,
                    "committed public tree changed")
            # Git over SSH uses the operator's local SSH agent, not a GitHub
            # Actions secret or a repository-wide PAT.
            subprocess.run([
                "git", "push", "origin", "HEAD:refs/heads/" + branch
            ], check=True)
            body = (
                "## Explicit single-operator publication\n\n"
                "This operation was performed interactively on a trusted workstation "
                "after SHA/tree review; it is NOT two-person GitHub environment approval.\n\n"
                "Canonical SHA: " + args.canonical_sha + "\n"
                "Reviewed public base: " + args.community_sha + "\n"
                "Exact candidate tree: " + args.candidate_tree + "\n"
                "Successful private preview run: " + args.preview_run_id + "\n"
                "Reviewed private artifact ID: " + args.preview_artifact_id + "\n"
                "Verified artifact SHA-256: " + args.preview_archive_sha256 + "\n\n"
                "Public CI and independent review are REQUIRED before merge. "
                "No direct public main push, Cargo publish or release tag was performed.\n"
            )
            result = subprocess.run([
                "gh", "pr", "create", "--repo", PUBLIC, "--base", "main",
                "--head", branch, "--title",
                "chore(publication): publish Keylix " + args.canonical_sha[:12],
                "--body", body,
            ], capture_output=True, text=True, check=True)
            receipt["status"] = "public-pr-created"
            receipt["public_branch"] = branch
            receipt["public_pr_url"] = result.stdout.strip()
            record_receipt(args.receipt, receipt)
            print("PUBLIC PR CREATED:", result.stdout.strip())
            print("Public CI and review must pass before an operator merges this PR.")
        finally:
            os.chdir(original)


def main():
    publish(parse_args())


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError,
            zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        print("Publication denied:", error, file=sys.stderr)
        sys.exit(1)
