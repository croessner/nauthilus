#!/usr/bin/env bash
set -euo pipefail

manifest_path="${FUZZ_TARGET_MANIFEST:-testdata/fuzz-targets.tsv}"

usage() {
  echo "Usage: $0 --list | --target <name> [--fuzztime <duration>]" >&2
}

# validate_manifest checks the authoritative fuzz target registry.
validate_manifest() {
  if [[ ! -f "${manifest_path}" ]]; then
    echo "Fuzz target manifest not found: ${manifest_path}" >&2
    exit 1
  fi

  awk -F '|' '
    BEGIN { valid = 1 }
    /^#/ || NF == 0 { next }
    NF != 7 {
      printf "Invalid fuzz target row at line %d: expected 7 fields\n", NR > "/dev/stderr"
      valid = 0
      next
    }
    $1 !~ /^Fuzz[A-Za-z0-9_]+$/ {
      printf "Invalid fuzz target name at line %d: %s\n", NR, $1 > "/dev/stderr"
      valid = 0
    }
    $2 !~ /^\.\/[A-Za-z0-9_.\/-]+$/ {
      printf "Invalid fuzz target package at line %d: %s\n", NR, $2 > "/dev/stderr"
      valid = 0
    }
    $3 != "go" || $4 !~ /^[1-9][0-9]*(s|m|h)$/ ||
      $5 !~ /^[1-9][0-9]*$/ || $6 !~ /^[1-9][0-9]*$/ ||
      $7 != "synthetic" {
      printf "Invalid fuzz target metadata at line %d\n", NR > "/dev/stderr"
      valid = 0
    }
    seen[$1]++ {
      printf "Duplicate fuzz target at line %d: %s\n", NR, $1 > "/dev/stderr"
      valid = 0
    }
    END { exit valid ? 0 : 1 }
  ' "${manifest_path}"
}

# list_targets prints registered target names in manifest order.
list_targets() {
  awk -F '|' '/^#/ || NF == 0 { next } { print $1 }' "${manifest_path}"
}

target_name=""
fuzz_time=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)
      if [[ $# -ne 1 ]]; then
        usage
        exit 2
      fi

      validate_manifest
      list_targets
      exit 0
      ;;
    --target)
      if [[ $# -lt 2 ]]; then
        usage
        exit 2
      fi

      target_name="$2"
      shift 2
      ;;
    --fuzztime)
      if [[ $# -lt 2 ]]; then
        usage
        exit 2
      fi

      fuzz_time="$2"
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${target_name}" ]]; then
  usage
  exit 2
fi

if [[ -n "${fuzz_time}" && ! "${fuzz_time}" =~ ^[1-9][0-9]*(s|m|h)$ ]]; then
  echo "Invalid fuzz duration: ${fuzz_time}" >&2
  exit 2
fi

validate_manifest

target_row="$(awk -F '|' -v target="${target_name}" '$1 == target { print; found++ } END { if (found != 1) exit 1 }' "${manifest_path}")" || {
  echo "Unknown fuzz target: ${target_name}" >&2
  exit 2
}

IFS='|' read -r selected_target selected_package _ selected_budget selected_parallel _ _ <<< "${target_row}"

if [[ -n "${fuzz_time}" ]]; then
  selected_budget="${fuzz_time}"
fi

GOEXPERIMENT=runtimesecret go test "${selected_package}" \
  -run '^$' \
  -fuzz "^${selected_target}$" \
  -fuzztime "${selected_budget}" \
  -parallel "${selected_parallel}"
