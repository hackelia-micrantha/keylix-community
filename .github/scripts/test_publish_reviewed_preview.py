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
