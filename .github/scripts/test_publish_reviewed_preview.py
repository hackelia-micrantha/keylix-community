"""Regression tests for the public approval-only publication replay."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

import publish_reviewed_preview as publication


def git(cwd, *args):
    return subprocess.check_output(["git", "-C", str(cwd), *args], text=True).strip()


class ApprovalBoundaryTests(unittest.TestCase):
    def test_ids_and_digests_fail_closed(self):
        good = ("a" * 40, "b" * 40, "c" * 40, "d" * 64, "100", "200")
        publication.validate_inputs(*good)
        for i, malformed in enumerate(("zz" * 20, "b" * 39, "x" * 40,
                                        "x" * 64, "0", "-1")):
            invalid = list(good)
            invalid[i] = malformed
            with self.subTest(field=i), self.assertRaises(RuntimeError):
                publication.validate_inputs(*invalid)

    def test_public_path_boundary(self):
        for name in ("Cargo.lock", "docs/SECURITY_ARCHITECTURE.md",
                     "scripts/release/package-public.sh",
                     "tests/verifier-cross-uid-vm.nix",
                     "client/docs/API.md", "PUBLICATION-SOURCE.json"):
            with self.subTest(allowed=name):
                self.assertTrue(publication.allowed_path(name))
        for name in (".github/workflows/ci.yml", "SECURITY.md", "README.md",
                     "PUBLICATION.md", ".gitmodules", "scripts/secret.py",
                     "tests/private/credentials", "client/secret.key",
                     ".env", "unknown/new.txt"):
            with self.subTest(denied=name):
                self.assertFalse(publication.allowed_path(name))

    def test_preview_archive_strict_source_and_secret_receipt(self):
        canonical, public_sha = "a" * 40, "b" * 40
        fields = {
            "review-inputs.txt": (
                "canonical_sha=" + canonical + "\n" +
                "community_base_sha=" + public_sha + "\n"
            ),
            "publication.diff": "diff --git a/Cargo.lock b/Cargo.lock\n",
            "gitleaks.json": "[]",
            "publication.manifest.sha256": "x",
            "PUBLICATION-SOURCE.json": '{"canonical_sha":"' + canonical + '"}',
            "package-evidence/PUBLICATION-SOURCE.json":
                '{"canonical_sha":"nested-not-authoritative"}',
        }
        def archive(values):
            result = io.BytesIO()
            with zipfile.ZipFile(result, "w") as zipped:
                for k, v in values.items():
                    zipped.writestr(k, v)
            result.seek(0)
            return zipfile.ZipFile(result)
        with archive(fields) as zipped:
            publication.read_preview(zipped, canonical, public_sha)
        changed = dict(fields, **{"gitleaks.json": '[{"Finding":"secret"}]'})
        with archive(changed) as zipped, self.assertRaises(RuntimeError):
            publication.read_preview(zipped, canonical, public_sha)
        changed = dict(fields, **{"review-inputs.txt": "canonical_sha=changed\n"})
        with archive(changed) as zipped, self.assertRaises(RuntimeError):
            publication.read_preview(zipped, canonical, public_sha)

    def test_exact_tree_replay_and_negative_tree(self):
        with tempfile.TemporaryDirectory(prefix="keylix-approval-test-") as tmp:
            checkout = Path(tmp) / "public"
            origin = Path(tmp) / "origin.git"
            checkout.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main", str(checkout)], check=True)
            subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)],
                           check=True)
            git(checkout, "config", "user.name", "Test")
            git(checkout, "config", "user.email", "test@example.org")
            git(checkout, "remote", "add", "origin", str(origin))
            (checkout / "Cargo.lock").write_text("before\n")
            git(checkout, "add", "-A")
            git(checkout, "commit", "-q", "-m", "base")
            base = git(checkout, "rev-parse", "HEAD")
            git(checkout, "push", "-q", "origin", "main")
            canonical = "a" * 40
            (checkout / "Cargo.lock").write_text("after\n")
            provenance = '{"canonical_sha":"' + canonical + '"}\n'
            (checkout / "PUBLICATION-SOURCE.json").write_text(provenance)
            git(checkout, "add", "-A")
            patch = subprocess.check_output(
                ["git", "-C", str(checkout), "diff", "--cached", "--binary", "HEAD"]
            )
            tree = git(checkout, "write-tree")
            files = git(checkout, "ls-files").splitlines()
            manifest = b"".join(
                (hashlib.sha256((checkout / name).read_bytes()).hexdigest() +
                 "  " + name + "\n").encode() for name in files
            )
            git(checkout, "reset", "--hard", "HEAD")
            content = {
                "publication.diff": patch,
                "PUBLICATION-SOURCE.json": provenance.encode(),
                "publication.manifest.sha256": manifest,
            }
            previous = Path.cwd()
            try:
                os.chdir(checkout)
                with self.assertRaises(RuntimeError):
                    publication.verify_candidate(content, base, "f" * 40, checkout)
                git(checkout, "reset", "--hard", "HEAD")
                publication.verify_candidate(content, base, tree, checkout)
                self.assertEqual(git(checkout, "write-tree"), tree)
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()


class LocalOperatorBoundaryTests(unittest.TestCase):
    def test_local_context_rejects_github_actions(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            with self.assertRaisesRegex(RuntimeError, "GitHub Actions"):
                publication.check_operator_checkout()

    def test_local_context_rejects_ci(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false", "CI": "true"}):
            with self.assertRaisesRegex(RuntimeError, "CI"):
                publication.check_operator_checkout()

    def test_noninteractive_publish_is_denied(self):
        from unittest.mock import patch
        with patch.object(publication.sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "interactive"):
                publication.operator_confirm("a" * 40, "b" * 40,
                                             "c" * 40, "d" * 64)

    def test_receipt_rejects_overwrite_and_never_exposes_token(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "receipt.json"
            publication.record_receipt(target, {"status": "validated-not-published"})
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("GH_TOKEN", target.read_text())
            with self.assertRaisesRegex(RuntimeError, "overwrite"):
                publication.record_receipt(target, {"status": "second"})

    def test_command_requires_explicit_dry_run_opt_in(self):
        values = ["--canonical-sha", "a" * 40,
                  "--community-sha", "b" * 40,
                  "--candidate-tree", "c" * 40,
                  "--preview-run-id", "22",
                  "--preview-artifact-id", "33",
                  "--preview-archive-sha256", "d" * 64]
        self.assertFalse(publication.parse_args(values).dry_run)
        self.assertTrue(publication.parse_args(values + ["--dry-run"]).dry_run)

    def test_no_privileged_public_actions_workflow_remains(self):
        root = Path(__file__).resolve().parents[2]
        self.assertFalse(
            (root / ".github/workflows/approve-keylix-publication.yml").exists())
        for workflow in (root / ".github/workflows").glob("*.yml"):
            content = workflow.read_text()
            self.assertNotIn("KEYLIX_PRIVATE_PREVIEW_READ_TOKEN", content)
            self.assertNotIn("KEYLIX_PUBLICATION_WRITE_TOKEN", content)

class RegistryReadinessBoundaryTests(unittest.TestCase):
    def test_first_crate_rehearses_only_non_upload_publish(self):
        root = Path(__file__).resolve().parents[2]
        script = (root / "scripts/release/package-public.sh").read_text()
        self.assertIn("cargo publish --dry-run --locked --allow-dirty -p keylix-core", script)
        self.assertIn("core_publish_dry_run=passed-no-upload", script)
        self.assertIn("core-publish-dry-run.log", script)
        self.assertNotIn("cargo publish --locked -p keylix-core", script)
        self.assertNotIn("--no-verify", script)
