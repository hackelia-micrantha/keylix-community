"""Regression tests for public Keylix source publication checks."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

GUARD_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_publication.py"
SPEC = importlib.util.spec_from_file_location("keylix_publication", GUARD_PATH)
assert SPEC and SPEC.loader
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class PublicationTests(unittest.TestCase):
    def test_blocks_common_credentials_without_blocking_public_contracts(self):
        for item in (
            ".env", ".env.production", ".dev.vars", ".dev.vars.staging",
            "certs/identity.key", "keys/id_ed25519",
            "secrets.yaml", "config/secrets.yml", "export/user.p12",
            "state/data.sqlite", "backup/credentials.json",
        ):
            with self.subTest(item=item):
                self.assertTrue(guard.sensitive_path(Path(item)))
        for item in (
            ".env.example", ".dev.vars.template", "crates/keylix-dpop/src/lib.rs",
            "fuzz/corpus/dpop_parse_verify/independent.proof",
            "docs/public-key.asc", "fixtures/public.crt", "Cargo.lock",
        ):
            with self.subTest(item=item):
                self.assertFalse(guard.sensitive_path(Path(item)))

    def test_pgp_private_armor_across_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = b"-----BEGIN " + b"PGP PRIVATE KEY BLOCK-----"
            (root / "private.asc").write_bytes(
                b"Z" * (guard.CHUNK_BYTES - 4) + marker
            )
            self.assertEqual(
                guard.inspect(root, [Path("private.asc")]),
                [("private.asc", "private-key armor")],
            )

    def test_private_pem_in_unusual_extension(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "artifact.proof").write_bytes(
                b"prefix\n" + b"-----BEGIN " + b"PRIVATE KEY-----\nsynthetic"
            )
            self.assertEqual(
                guard.inspect(root, [Path("artifact.proof")]),
                [("artifact.proof", "private-key armor")],
            )

    def test_public_pgp_keys_and_signatures_remain_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pub.asc").write_bytes(
                b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture"
            )
            (root / "sig.asc").write_bytes(
                b"-----BEGIN PGP SIGNATURE-----\nfixture"
            )
            self.assertEqual(
                guard.inspect(root, [Path("pub.asc"), Path("sig.asc")]), []
            )

    def test_missing_and_symlinked_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target").write_text("safe")
            (root / "link").symlink_to(root / "target")
            self.assertEqual(
                guard.inspect(root, [Path("missing"), Path("link")]),
                [("link", "tracked symlink"), ("missing", "missing tracked file")],
            )

    def test_parent_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(
                guard.inspect(Path(temp), [Path("../outside")]),
                [("../outside", "unsafe path")],
            )


if __name__ == "__main__":
    unittest.main()
