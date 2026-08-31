#!/usr/bin/env python3

"""Verify release-major and public protobuf compatibility guard contracts."""

from pathlib import Path
import subprocess
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
RELEASE_SCRIPT = REPOSITORY_ROOT / "scripts" / "release-semver-metadata.sh"
DESCRIPTOR_SCRIPT = REPOSITORY_ROOT / "scripts" / "check-grpc-descriptor-compatibility.sh"


class ReleaseContractTests(unittest.TestCase):
    """Exercise release identity and descriptor guard boundaries."""

    def test_release_tag_major_matches_module_major(self) -> None:
        accepted = subprocess.run(
            [str(RELEASE_SCRIPT), "v4.0.0-alpha.1"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        rejected = subprocess.run(
            [str(RELEASE_SCRIPT), "v3.2.0"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
        self.assertIn("module major v4", rejected.stderr)

    def test_descriptor_guard_protects_policy_wire_contract(self) -> None:
        script = DESCRIPTOR_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("public-policy-protobuf-baseline.pb", script)
        self.assertIn("/api/policy/v1/policy.proto", script)
        self.assertIn("github.com/croessner/nauthilus/v4/api/policy/v1", script)

    def test_repository_has_no_stale_v3_imports(self) -> None:
        stale_module = "github.com/croessner/nauthilus/" + "v3"
        listed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        actual = []

        for relative_path in listed.stdout.splitlines():
            if (
                relative_path.startswith(("vendor/", "temp/"))
                or relative_path.endswith(".pb")
            ):
                continue

            contents = (REPOSITORY_ROOT / relative_path).read_text(
                encoding="utf-8", errors="ignore"
            )
            for line_number, line in enumerate(contents.splitlines(), start=1):
                if stale_module in line:
                    actual.append(f"{relative_path}:{line_number}:{line}")

        actual_paths = {
            line.split(":", maxsplit=1)[0] for line in actual
        }
        allowed_paths = {
            "scripts/check-grpc-descriptor-compatibility.sh",
            "server/docs/v4_module_migration.md",
        }

        self.assertEqual(actual_paths, allowed_paths, actual)
        self.assertTrue(
            any("legacy_module_root=" in line for line in actual),
            actual,
        )


if __name__ == "__main__":
    unittest.main()
