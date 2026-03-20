#!/usr/bin/env bash
set -euo pipefail

pr_body_file="${1:-}"

if [[ -z "${pr_body_file}" || ! -f "${pr_body_file}" ]]; then
  echo "Usage: $0 <pr-body-file>" >&2
  exit 1
fi

required_checkboxes=(
  "- [x] I added a reproducer test first for bugfixes (Lua: Lua test with `testdata` JSON when applicable; Go: focused Go test), or documented why no reproducer test was possible."
  "- [x] I verified DRY compliance and removed or consolidated duplicate logic."
  "- [x] I verified OOP-oriented structure (small responsibilities, clear boundaries, composition where appropriate)."
  "- [x] I ensured all new/changed technical comments and docs are in English."
  "- [x] I ran `make guardrails` locally."
)

for checkbox in "${required_checkboxes[@]}"; do
  if ! grep -Fqi "${checkbox}" "${pr_body_file}"; then
    echo "Missing checked mandatory PR guardrail: ${checkbox}" >&2
    exit 1
  fi
done

echo "Mandatory PR guardrails are all checked"
