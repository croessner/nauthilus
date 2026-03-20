#!/usr/bin/env bash
set -euo pipefail

required_files=(
  "POLICY.md"
  ".junie/guidelines.md"
  "AGENTS.md"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "${file}" ]]; then
    echo "Missing required file: ${file}" >&2
    exit 1
  fi
done

required_patterns=(
  "MUST: For Lua issues, create a Lua reproducer test first"
  "MUST: For Go issues, create a focused Go reproducer test first"
  "MUST: Apply DRY strictly"
  "MUST: Follow OOP-oriented design"
  "MUST: Write code comments and technical docs in English"
  "Definition Of Done"
)

for pattern in "${required_patterns[@]}"; do
  if ! grep -Fq "${pattern}" POLICY.md; then
    echo "POLICY.md is missing required policy marker: ${pattern}" >&2
    exit 1
  fi
done

echo "Policy documents and markers are present"
