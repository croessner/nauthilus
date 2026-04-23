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

"""Generate Vim syntax highlighting rules from the config schema."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT_DIR / "contrib" / "vim" / "syntax" / "nauthilus.vim"
GO_RUN_CMD = ("go", "run", "./scripts/list_config_syntax_keys")

GENERATED_NOTICE = (
    '" Comment:      Generated from the config schema; do not edit manually'
)
DYNAMIC_L3_PATTERNS = ("description_[A-Za-z0-9_-]\\+",)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate contrib/vim/syntax/nauthilus.vim from the config schema."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output path for the generated Vim syntax file.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the generated output differs from the checked-in file.",
    )
    parser.add_argument(
        "--schema-file",
        type=Path,
        help="Use an existing schema JSON file instead of running the Go helper.",
    )

    return parser.parse_args()


def load_schema_keys(schema_file: Path | None) -> tuple[list[str], list[str], list[str]]:
    """Load grouped schema keys from a file or by executing the Go helper."""
    if schema_file is not None:
        payload = schema_file.read_text(encoding="utf-8")
    else:
        gocache_dir = ROOT_DIR / ".cache" / "go-build"
        gocache_dir.mkdir(parents=True, exist_ok=True)

        env = os.environ.copy()
        env.setdefault("GOEXPERIMENT", "runtimesecret")
        env.setdefault("GEXPERIMENT", "runtimesecret")
        env.setdefault("GOCACHE", str(gocache_dir))

        try:
            result = subprocess.run(
                GO_RUN_CMD,
                cwd=ROOT_DIR,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
        except subprocess.CalledProcessError as exc:
            if exc.stderr:
                print(exc.stderr.strip(), file=sys.stderr)
            else:
                print(f"failed to run {' '.join(GO_RUN_CMD)}", file=sys.stderr)

            raise SystemExit(exc.returncode) from exc

        payload = result.stdout

    data = json.loads(payload)

    return data["roots"], data["level2"], data["level3"]


def vim_escape(key: str) -> str:
    """Escape a key for safe usage inside a Vim regex."""
    escaped = re.escape(key)

    return escaped.replace("-", r"\-")


def render_keyword_lines(group: str, indent_pattern: str, keys: list[str]) -> list[str]:
    """Render exact Vim syntax match lines for the given key set."""
    lines = []
    for key in keys:
        lines.append(
            f"syntax match {group} /^{indent_pattern}\\zs{vim_escape(key)}\\ze:/"
        )

    return lines


def render_vim_syntax(
    roots: list[str],
    level2: list[str],
    level3: list[str],
) -> str:
    """Render the complete Vim syntax file."""
    lines = [
        '" Vim syntax file',
        '" Language:     Nauthilus configuration (YAML-based)',
        '" Maintainer:   Christian Roessner <christian@roessner.email>',
        GENERATED_NOTICE,
        "",
        'if exists("b:current_syntax")',
        "  finish",
        "endif",
        "",
        '" Case sensitive matching',
        "syntax case match",
        "",
        '" Sync from start for consistency',
        "syntax sync fromstart",
        "",
        '" --- Level Keywords ---',
        "",
        '" L1: Root',
    ]

    lines.extend(render_keyword_lines("nauthilusKeyL1", "", roots))
    lines.extend(
        [
            "",
            '" L2: Second level',
        ]
    )
    lines.extend(render_keyword_lines("nauthilusKeyL2", "  ", level2))
    lines.extend(
        [
            "",
            '" L3+: Third level and deeper',
        ]
    )
    lines.extend(
        render_keyword_lines(
            "nauthilusKeyL3",
            r"\(\s\{4,\}\|\s\+-\s\+\)",
            level3,
        )
    )

    for pattern in DYNAMIC_L3_PATTERNS:
        lines.append(
            "syntax match nauthilusKeyL3 "
            f"/^\\(\\s\\{{4,\\}}\\|\\s\\+-\\s\\+\\)\\zs{pattern}\\ze:/"
        )

    lines.extend(
        [
            "",
            '" --- Special Values ---',
            "syntax keyword nauthilusBoolean true",
            "syntax keyword nauthilusBoolean false",
            "syntax keyword nauthilusBoolean yes",
            "syntax keyword nauthilusBoolean no",
            "syntax keyword nauthilusHttpMethod GET POST PUT DELETE PATCH HEAD OPTIONS CONNECT TRACE",
            "",
            '" --- Matches ---',
            'syntax match nauthilusComment "#.*$"',
            'syntax match nauthilusNumber  "\\<\\d\\+\\>"',
            '" IPv4 and IPv6 Addresses/Networks, UUIDs and Go Durations',
            r'syntax match nauthilusIP "\<\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\%(\/\d\{1,2}\)\?\>"',
            'syntax match nauthilusIP "\\<\\%([0-9A-Fa-f]\\{1,4}:\\)\\{1,7}\\%([0-9A-Fa-f]\\{1,4}\\|:\\)\\%(\\/\\d\\{1,3}\\)\\?\\>"',
            'syntax match nauthilusIP "\\<\\%([0-9A-Fa-f]\\{1,4}:\\)\\{0,6}:[0-9A-Fa-f]\\{1,4}\\%(\\/\\d\\{1,3}\\)\\?\\>"',
            'syntax match nauthilusIP "\\<::\\%([0-9A-Fa-f]\\{1,4}\\)\\?\\%(\\/\\d\\{1,3}\\)\\?\\>"',
            'syntax match nauthilusUUID "\\<[0-9a-fA-F]\\{8\\}-[0-9a-fA-F]\\{4\\}-4[0-9a-fA-F]\\{3\\}-[89abAB][0-9a-fA-F]\\{3\\}-[0-9a-fA-F]\\{12\\}\\>"',
            'syntax match nauthilusDuration "\\<-\\?\\%(\\d\\+\\%(\\.\\d\\+\\)\\?\\%(ns\\|us\\|µs\\|ms\\|s\\|m\\|h\\)\\)\\+\\>"',
            'syntax match nauthilusString  "\\".*\\"" contains=nauthilusMacro',
            "syntax match nauthilusString  \"'.*'\" contains=nauthilusMacro",
            'syntax match nauthilusDelimiter ":"',
            "",
            '" LDAP Filter highlighting',
            'syntax region nauthilusLdapFilter start="(" end=")" contains=nauthilusLdapFilter,nauthilusLdapOperator,nauthilusMacro',
            'syntax match nauthilusLdapOperator "[&|!<>~=:]" contained',
            "",
            '" Macros/Variables',
            'syntax region nauthilusMacro matchgroup=nauthilusMacroDelimiter start="%[LURT]*{" end="}" contains=nauthilusMacroVar oneline',
            'syntax region nauthilusMacro matchgroup=nauthilusMacroDelimiter start="\\${" end="}" contains=nauthilusMacroVar oneline',
            "syntax match nauthilusMacroVar /[^}]\\+/ contained",
            "",
            '" --- Highlighting ---',
            '" We use forced colors to ensure they match the requested hierarchy',
            '" but we also link them to standard groups for fallback.',
            "",
            "hi def link nauthilusKeyL1 Function",
            "hi def link nauthilusKeyL2 Type",
            "hi def link nauthilusKeyL3 Statement",
            "hi def link nauthilusBoolean Boolean",
            "hi def link nauthilusHttpMethod Special",
            "hi def link nauthilusComment Comment",
            "hi def link nauthilusNumber Number",
            "hi def link nauthilusIP Number",
            "hi def link nauthilusUUID Number",
            "hi def link nauthilusDuration Number",
            "hi def link nauthilusString String",
            "hi def link nauthilusDelimiter Delimiter",
            "hi def link nauthilusLdapFilter Special",
            "hi def link nauthilusLdapOperator Operator",
            "hi def link nauthilusMacro Special",
            "hi def link nauthilusMacroDelimiter Special",
            "hi def link nauthilusMacroVar Special",
            "",
            '" Direct color assignments for the requested hierarchy',
            "hi nauthilusKeyL1 ctermfg=4 guifg=#000080 gui=bold",
            "hi nauthilusKeyL2 ctermfg=10 guifg=#00ff00",
            "hi nauthilusKeyL3 ctermfg=11 guifg=#ffff00",
            "hi nauthilusHttpMethod ctermfg=208 guifg=#ff8700 gui=bold",
            "hi nauthilusMacro ctermfg=141 guifg=#af87ff gui=bold",
            "hi nauthilusMacroDelimiter ctermfg=141 guifg=#af87ff gui=bold",
            "hi nauthilusMacroVar ctermfg=141 guifg=#af87ff gui=bold",
            "",
            'let b:current_syntax = "nauthilus"',
            "",
        ]
    )

    return "\n".join(lines)


def main() -> int:
    """Run the generator or check mode."""
    args = parse_args()
    output_path = args.output.resolve()
    generated = render_vim_syntax(*load_schema_keys(args.schema_file))

    if args.check:
        current = ""
        if output_path.exists():
            current = output_path.read_text(encoding="utf-8")

        if current != generated:
            print(
                f"{output_path} is out of date. Run: python3 scripts/generate-vim-syntax.py",
                file=sys.stderr,
            )

            return 1

        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(generated, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
