"""Fail-closed crates.io version-status checks for the local operator CLI."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/operator-publish.sh"


class RegistryStatusTests(unittest.TestCase):
    @staticmethod
    def _exercise(script_body: str, action: str, status: str):
        # Load function definitions without invoking the CLI's irreversible main.
        # The real checkout, registry, cargo binary and operator TTY are untouched.
        library, invocation = script_body.rsplit('main "$@"', 1)
        if invocation.strip():
            raise AssertionError("unexpected code after operator CLI main invocation")
        with tempfile.TemporaryDirectory(prefix="keylix-registry-") as temp:
            directory = Path(temp)
            # Inject a shell function, not an untrusted executable PATH entry.
            # The synthetic curl never reaches a network or registry endpoint.
            fake_curl = (
                'curl() {\n'
                '  printf "%s\\n" "$@" > "$KEYLIX_TEST_CURL_ARGS"\n'
                '  if [ "$KEYLIX_TEST_STATUS" = network-failure ]; then return 7; fi\n'
                '  printf "%s\\n" "$KEYLIX_TEST_STATUS"\n'
                '}\n'
            )
            arguments = directory / "curl-args.txt"
            env = dict(os.environ)
            env["KEYLIX_TEST_CURL_ARGS"] = str(arguments)
            env["KEYLIX_TEST_STATUS"] = status
            result = subprocess.run(
                ["bash", "-c", library + "\n" + fake_curl + action],
                env=env, cwd=ROOT, capture_output=True, text=True, check=False,
            )
            return result, arguments.read_text() if arguments.exists() else ""

    def test_http_statuses_are_distinct_and_safe(self):
        script = SCRIPT.read_text(encoding="utf-8")
        for status in ("403", "429", "503", "network-failure"):
            with self.subTest(status=status):
                result, args = self._exercise(
                    script, "require_unpublished keylix-core", status
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("status unavailable", result.stderr)
                self.assertNotIn("already exists", result.stderr)
                self.assertIn("--user-agent", args)
                self.assertIn("keylix-release/0.1", args)
                self.assertNotIn("curl/", args)

        absent, args = self._exercise(script, "require_unpublished keylix-core", "404")
        self.assertEqual(absent.returncode, 0, absent.stderr)
        self.assertIn("--user-agent", args)

        present, _ = self._exercise(script, "require_unpublished keylix-core", "200")
        self.assertNotEqual(present.returncode, 0)
        self.assertIn("already exists", present.stderr)

    def test_existing_dependency_lookup_does_not_misreport_403(self):
        script = SCRIPT.read_text(encoding="utf-8")
        result, _ = self._exercise(
            script, "check_dependency_registry keylix-dpop preflight", "403"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("status unavailable for dependency keylix-core", result.stderr)
        self.assertNotIn("not available in crates.io", result.stderr)


if __name__ == "__main__":
    unittest.main()
