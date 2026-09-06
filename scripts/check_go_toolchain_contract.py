#!/usr/bin/env python3
"""Validate active declarations and the resolved toolchain without changing state."""

from pathlib import Path
import re
import subprocess
import sys


def validate(root):
    """Return bounded diagnostics for missing or inconsistent build contracts."""
    errors = []
    module = (root / "go.mod").read_text()
    for declaration in ("go 1.27", "toolchain go1.27.0"):
        if declaration not in module.splitlines():
            errors.append("go.mod: missing " + declaration)
    result = subprocess.run(["go", "version"], cwd=root, capture_output=True, text=True)
    if result.returncode or not re.match(r"go version go1\.27\.0\s", result.stdout):
        errors.append("resolved toolchain must be exactly go1.27.0")
    for path in sorted(root.glob("Dockerfile*")):
        content = path.read_text()
        images = re.findall(r"golang:([^\s]+)", content)
        if any(not re.match(r"1\.27\.0(?:-|$)", image) for image in images):
            errors.append(path.name + ": builder must use Go 1.27.0")
    for path in sorted((root / ".github/workflows").glob("*")):
        content = path.read_text()
        versions = re.findall(r"go-version(?:-input)?:\s*([^\n]+)", content)
        if any(value.strip(" '\"") != "1.27.0" for value in versions):
            errors.append(path.name + ": CI must use Go 1.27.0")
        if versions and "runtimesecret" not in content:
            errors.append(path.name + ": CI experiment missing")
    for name in ("README.md", ".junie/guidelines.md", "AGENTS.md"):
        content = (root / name).read_text()
        if "Go 1.27.0" not in content or "newer stable Go 1.27 patch" in content:
            errors.append(name + ": exact Go 1.27.0 requirement missing")
        if re.search(r"Go 1\.26", content):
            errors.append(name + ": obsolete Go declaration")
    makefile = (root / "Makefile").read_text()
    if "export GOEXPERIMENT := runtimesecret" not in makefile:
        errors.append("Makefile: internal experiment export missing")
    provenance = (root / "scripts/docker-base-digests.sh").read_text()
    if "golang:1.27.0-" not in provenance:
        errors.append("builder provenance: exact Go image missing")
    for directory in (root / "scripts", root / "contrib"):
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or not (path.suffix == ".sh" or path.name == "Makefile"):
                continue
            content = path.read_text()
            exported = re.search(r"export GOEXPERIMENT[ :=]+[\"']?runtimesecret", content)
            for line in content.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                if re.search(r"(?:\bgo|\$\(GO\))\s+test\b", line):
                    if not exported and "GOEXPERIMENT=runtimesecret" not in line:
                        errors.append(str(path.relative_to(root)) + ": test experiment missing")
    return errors


if __name__ == "__main__":
    failures = validate(Path(sys.argv[1]).resolve())
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        sys.exit(1)
    print("Exact Go 1.27.0 toolchain contract verified")
