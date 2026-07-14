#!/usr/bin/env python3
"""Verify that repository-wide Make targets never operate on vendored packages."""

from pathlib import Path
import re
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE_PATH = REPOSITORY_ROOT / "Makefile"
GO_COMMAND_TARGETS = ("fix", "vet", "test", "race", "msan", "govulncheck")


def makefile_recipe(makefile: str, target: str) -> str:
    """Return the recipe lines declared directly below a Make target."""
    lines = makefile.splitlines()
    target_pattern = re.compile(rf"^{re.escape(target)}(?:\s+[^:]*)?:")

    for index, line in enumerate(lines):
        if not target_pattern.match(line):
            continue

        recipe = []

        for candidate in lines[index + 1 :]:
            if candidate.startswith("\t"):
                recipe.append(candidate.strip())
                continue

            if candidate.strip() == "":
                continue

            break

        return "\n".join(recipe)

    raise AssertionError(f"Make target not found: {target}")


def makefile_dependencies(makefile: str, target: str) -> tuple[str, ...]:
    """Return the dependency names declared for a Make target."""
    target_pattern = re.compile(rf"^{re.escape(target)}:[ \t]*([^\n#]*)", re.MULTILINE)
    match = target_pattern.search(makefile)

    if match is None:
        raise AssertionError(f"Make target not found: {target}")

    return tuple(match.group(1).split())


class MakefilePackageScopeTest(unittest.TestCase):
    """Keep package-wide Make targets on one explicit non-vendor package set."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load the canonical Makefile once for all contract checks."""
        cls.makefile = MAKEFILE_PATH.read_text(encoding="utf-8")

    def test_shared_package_list_excludes_vendor(self) -> None:
        """Require the shared package query to filter vendored package paths."""
        self.assertRegex(
            self.makefile,
            r"(?m)^GO_PACKAGES\s*[:?+]?=\s*\$\(shell go list \./\.\.\. \| grep -v /vendor/\)$",
        )

        self.assertRegex(
            self.makefile,
            r"(?m)^GO_PACKAGE_DIRS\s*[:?+]?=.*\$\(GO_PACKAGES\).*$",
        )

    def test_scoped_targets_use_shared_package_list(self) -> None:
        """Require every repository-wide analysis target to reuse GO_PACKAGES."""
        for target in GO_COMMAND_TARGETS:
            with self.subTest(target=target):
                recipe = makefile_recipe(self.makefile, target)

                self.assertIn("$(GO_PACKAGES)", recipe)
                self.assertNotIn("./...", recipe)

        guardrails_recipe = makefile_recipe(self.makefile, "guardrails")

        self.assertIn("$(GO_PACKAGE_DIRS)", guardrails_recipe)
        self.assertIn("$(GO_PACKAGES)", guardrails_recipe)
        self.assertNotIn("./...", guardrails_recipe)

    def test_build_does_not_mutate_sources(self) -> None:
        """Keep the normal build path independent from the mutating fix target."""
        self.assertNotIn("fix", makefile_dependencies(self.makefile, "build"))


if __name__ == "__main__":
    unittest.main()
