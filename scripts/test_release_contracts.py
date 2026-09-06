#!/usr/bin/env python3

"""Verify release-major and public protobuf compatibility guard contracts."""

from pathlib import Path
import os
import re
import subprocess
import tempfile
import textwrap
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
RELEASE_SCRIPT = REPOSITORY_ROOT / "scripts" / "release-semver-metadata.sh"
DESCRIPTOR_SCRIPT = REPOSITORY_ROOT / "scripts" / "check-grpc-descriptor-compatibility.sh"


class ReleaseContractTests(unittest.TestCase):
    """Exercise release identity and descriptor guard boundaries."""

    def test_base_digests_follow_release_dockerfile_and_fail_closed(self) -> None:
        """Current tooling must inspect the released compiler and propagate registry failures."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dockerfile = root / "Dockerfile"
            dockerfile.write_text("FROM --platform=$TARGETPLATFORM golang:1.26.6-alpine3.24 AS builder\nFROM alpine:3.24\n")
            docker = root / "docker"
            docker.write_text('#!/bin/sh\n[ "${FAIL_REGISTRY:-0}" = 0 ] || exit 7\nprintf "%s" "$4"\n')
            docker.chmod(0o700)
            for fails in (False, True):
                result = subprocess.run(
                    [str(REPOSITORY_ROOT / "scripts/docker-base-digests.sh"), "--dockerfile", str(dockerfile)],
                    env=dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                             FAIL_REGISTRY=str(int(fails)), GOLANG_IMAGE="golang:1.27.0-alpine3.24"),
                    capture_output=True, text=True, check=False,
                )
                if fails:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("golang_image=golang:1.26.6-alpine3.24\n", result.stdout)

    def test_stable_refresh_validates_the_released_module(self) -> None:
        """An older stable release retains its own module-major authority."""
        with tempfile.TemporaryDirectory() as directory:
            module_file = Path(directory) / "release.go.mod"
            module_file.write_text("module example.test/service/v3\n", encoding="utf-8")
            result = subprocess.run(
                [str(RELEASE_SCRIPT), "--module-file", str(module_file), "v3.1.1"],
                cwd=REPOSITORY_ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("tag_major=v3\n", result.stdout)
            self.assertIn("tag_minor=v3.1\n", result.stdout)

            mismatch = subprocess.run(
                [str(RELEASE_SCRIPT), "--module-file", str(module_file), "v4.0.0"],
                cwd=REPOSITORY_ROOT, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertEqual(mismatch.stdout, "")

    def test_stable_workflow_metadata_fails_closed(self) -> None:
        """Execute the actual workflow shell with a released v3 module fixture."""
        workflow = (REPOSITORY_ROOT / ".github/workflows/docker-stable-build.yaml").read_text()
        step = workflow.split("      - name: Extract release metadata\n", 1)[1]
        body = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n  build:", 1)[0])
        body = re.sub(r"\$\{\{.*?\}\}", "fixture", body)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "workflow-src").symlink_to(REPOSITORY_ROOT, target_is_directory=True)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            git = fake_bin / "git"
            git.write_text(
                '#!/bin/sh\ncase "$3" in\n'
                'rev-list) echo release-commit ;;\n'
                'show) echo "module example.test/service/v3" ;;\n'
                '*) exit 99 ;;\nesac\n'
            )
            git.chmod(0o700)
            for tag, succeeds in [("v3.1.1", True), ("v4.0.0", False)]:
                output = root / "output"
                output.write_text("")
                environment = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}",
                                   GITHUB_OUTPUT=str(output), RELEASE_TAG=tag,
                                   REBUILD_SUFFIX="rebuild-20260906", OCI_IMAGE_DESCRIPTION="fixture")
                result = subprocess.run(["bash", "-euo", "pipefail", "-c", body],
                                        cwd=root, env=environment, capture_output=True,
                                        text=True, check=False)
                if succeeds:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    tags = output.read_text().split("tags<<EOF\n", 1)[1].split("\nEOF", 1)[0].splitlines()
                    self.assertIn("ghcr.io/fixture/nauthilus:v3.1", tags)
                    self.assertFalse(any(value.endswith(":") for value in tags))
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(output.read_text(), "")

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
