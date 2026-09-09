#!/usr/bin/env python3
"""Exercise the exact toolchain gate with repository drift and isolated tools."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ToolchainContractTest(unittest.TestCase):
    """Reject drift without downloading or executing an alternative toolchain."""

    def test_repository_and_mutations(self):
        """Run the same gate against good input and independent contract drift."""
        cases = (
            (None, None, None, True),
            ("go.mod", "toolchain go1.27.1", "toolchain go1.27.2", False),
            ("Dockerfile", "golang:1.27.1", "golang:1.27.2", False),
            (".github/workflows/unit_tests.yaml", "go-version: 1.27.1", "go-version: 1.27.2", False),
            ("README.md", "Go 1.27.1", "Go 1.26.6", False),
            ("Makefile", "export GOEXPERIMENT := runtimesecret", "export GOEXPERIMENT :=", False),
            ("scripts/run-go-fuzz.sh", "GOEXPERIMENT=runtimesecret go test", "go test", False),
        )
        for path, old, new, succeeds in cases:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                fixture = Path(directory)
                for name in ("go.mod", "Makefile", "README.md", "AGENTS.md", "Dockerfile", "Dockerfile.debug", "Dockerfile.blocklist"):
                    shutil.copy2(ROOT / name, fixture / name)
                for name in ("scripts", ".github", ".junie", "contrib/plugins/geoip", "contrib/plugins/dkim2-intelligence", "contrib/identity-proxy-e2e/scripts"):
                    shutil.copytree(ROOT / name, fixture / name)
                if path:
                    target = fixture / path
                    original = target.read_text()
                    self.assertIn(old, original)
                    target.write_text(original.replace(old, new))
                result = subprocess.run(
                    ["sh", str(ROOT / "scripts/check-go-toolchain-contract.sh"), str(fixture)],
                    text=True, capture_output=True,
                )
                self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)

    def test_resolved_patch_drift(self):
        """Reject a later resolved patch even when module declarations are correct."""
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "go"
            fake.write_text('#!/bin/sh\necho "go version go1.27.2 darwin/amd64"\n')
            fake.chmod(0o755)
            result = subprocess.run(
                ["sh", str(ROOT / "scripts/check-go-toolchain-contract.sh")],
                env=dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"]),
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("resolved toolchain", result.stderr)

    def test_make_propagates_experiment_without_caller_environment(self):
        """Execute Make test recipes with a fake Go tool that checks its environment."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "go"
            fake.write_text('#!/bin/sh\n[ "$GOEXPERIMENT" = runtimesecret ] || exit 91\ncase "$1" in\nlist) echo ./fixture ;;\ntest) echo experiment-ok ;;\nesac\n')
            fake.chmod(0o755)
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"])
            environment.pop("GOEXPERIMENT", None)
            for target in ("test", "race", "msan"):
                with self.subTest(target=target):
                    result = subprocess.run(["make", target], cwd=ROOT, env=environment, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("experiment-ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
