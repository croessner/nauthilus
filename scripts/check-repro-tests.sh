#!/usr/bin/env bash
set -euo pipefail

base_ref="${1:-}"

if [[ -z "${base_ref}" ]]; then
  echo "Usage: $0 <base-ref>" >&2
  exit 1
fi

if ! git rev-parse --verify "${base_ref}" >/dev/null 2>&1; then
  echo "Base ref not found: ${base_ref}" >&2
  exit 1
fi

mapfile -t changed_files < <(git diff --name-only "${base_ref}...HEAD")

if [[ ${#changed_files[@]} -eq 0 ]]; then
  echo "No changed files detected between ${base_ref} and HEAD"
  exit 0
fi

go_source_changed=false
go_test_changed=false
lua_source_changed=false
lua_test_changed=false

for file in "${changed_files[@]}"; do
  if [[ "${file}" == vendor/* ]]; then
    continue
  fi

  if [[ "${file}" == *.go && "${file}" != *_test.go ]]; then
    go_source_changed=true
  fi

  if [[ "${file}" == *_test.go ]]; then
    go_test_changed=true
  fi

  if [[ "${file}" == *.lua && "${file}" != testdata/* ]]; then
    lua_source_changed=true
  fi

  if [[ "${file}" == testdata/*.json || "${file}" == testdata/**/*.json || "${file}" == *_test.lua || "${file}" == */tests/* || "${file}" == */test/* ]]; then
    lua_test_changed=true
  fi
done

if [[ "${go_source_changed}" == true && "${go_test_changed}" == false ]]; then
  echo "Go source changed but no Go reproducer test change detected (_test.go)." >&2
  echo "Add/update a focused Go reproducer test first." >&2
  exit 1
fi

if [[ "${lua_source_changed}" == true && "${lua_test_changed}" == false ]]; then
  echo "Lua source changed but no Lua reproducer test evidence detected (testdata JSON or Lua test files)." >&2
  echo "Add/update a Lua reproducer test first (prefer JSON fixtures in testdata)." >&2
  exit 1
fi

echo "Reproducer test guardrail passed"
