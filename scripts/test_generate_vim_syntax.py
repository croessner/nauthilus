#!/usr/bin/env python3
#
# Copyright (C) 2026 Christian Roessner
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Regression tests for the Vim syntax generator."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent


class GenerateVimSyntaxTest(unittest.TestCase):
    """Tests for the schema-driven Vim syntax generator."""

    def test_generator_includes_nested_keys_from_schema(self) -> None:
        """The generated syntax must include nested keys hidden by empty default lists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "nauthilus.vim"
            subprocess.run(
                [
                    "python3",
                    "scripts/generate-vim-syntax.py",
                    "--output",
                    str(output_path),
                ],
                cwd=ROOT_DIR,
                check=True,
            )

            generated = output_path.read_text(encoding="utf-8")

        self.assertIn(r"\zsscript_path\ze:", generated)
        self.assertNotIn(r"\zswhen_no_auth\ze:", generated)
        self.assertNotIn(r"\zswhen_authenticated\ze:", generated)
        self.assertNotIn(r"\zswhen_unauthenticated\ze:", generated)
        self.assertNotIn(r"\zsdepends_on\ze:", generated)
        self.assertIn(r"\zsname\ze:", generated)
        self.assertIn(r"\zsmappings\ze:", generated)

    def test_generator_highlights_config_env_placeholders_distinctly(self) -> None:
        """Environment placeholders must be distinct from Nauthilus macros."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "nauthilus.vim"
            subprocess.run(
                [
                    "python3",
                    "scripts/generate-vim-syntax.py",
                    "--output",
                    str(output_path),
                ],
                cwd=ROOT_DIR,
                check=True,
            )

            generated = output_path.read_text(encoding="utf-8")

        self.assertIn("nauthilusEnvVariable", generated)
        self.assertIn(r"\$\@<!\${[A-Za-z_][A-Za-z0-9_]*}", generated)
        self.assertIn(
            "contains=nauthilusEnvVariable,nauthilusMacro",
            generated,
        )
        self.assertIn("hi def link nauthilusEnvVariable", generated)


if __name__ == "__main__":
    unittest.main()
