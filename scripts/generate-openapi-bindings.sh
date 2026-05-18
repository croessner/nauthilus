#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

generator_pkg="github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"

bindings=(
  "management|server/openapi/oapi-management-bindings.yaml|server/openapi/openapi.yaml|server/openapi/generated/management/bindings.gen.go"
  "idp|server/openapi/oapi-idp-client.yaml|server/openapi/idp.yaml|server/openapi/generated/idp/client.gen.go"
)

usage() {
  echo "Usage: $0 [--check]" >&2
}

generate_with_config() {
  local config_file="$1"
  local spec_file="$2"

  cd "${repo_root}"
  go run -mod=vendor "${generator_pkg}" --config "${config_file}" "${spec_file}"
}

generate_binding() {
  local name="$1"
  local config_path="$2"
  local spec_path="$3"
  local output_path="$4"

  case "${check_mode}" in
    "false")
      generate_with_config "${config_path}" "${spec_path}"
      ;;
    "true")
      check_binding "${name}" "${config_path}" "${spec_path}" "${output_path}"
      ;;
  esac
}

check_binding() {
  local name="$1"
  local config_path="$2"
  local spec_path="$3"
  local output_path="$4"
  local tmp_dir
  local tmp_config
  local tmp_output

  tmp_dir="$(mktemp -d)"
  tmp_config="${tmp_dir}/$(basename "${config_path}")"
  tmp_output="${tmp_dir}/$(basename "${output_path}")"

  rewrite_output_path "${repo_root}/${config_path}" "${tmp_output}" > "${tmp_config}"
  if ! generate_with_config "${tmp_config}" "${spec_path}"; then
    rm -rf "${tmp_dir}"
    return 1
  fi

  if ! cmp -s "${repo_root}/${output_path}" "${tmp_output}"; then
    echo "Generated OpenAPI ${name} bindings are stale. Run: make generate-openapi-bindings" >&2
    diff -u "${repo_root}/${output_path}" "${tmp_output}" >&2 || true
    rm -rf "${tmp_dir}"
    exit 1
  fi

  rm -rf "${tmp_dir}"
  echo "OpenAPI ${name} bindings are up to date"
}

rewrite_output_path() {
  local config_file="$1"
  local output_path="$2"

  awk -v output="${output_path}" '
    /^output:/ {
      print "output: " output
      found = 1
      next
    }
    { print }
    END {
      if (!found) {
        print "output: " output
      }
    }
  ' "${config_file}"
}

case "${1:-}" in
  "")
    check_mode=false
    ;;
  "--check")
    check_mode=true
    ;;
  *)
    usage
    exit 2
    ;;
esac

for binding in "${bindings[@]}"; do
  IFS="|" read -r name config_path spec_path output_path <<< "${binding}"
  generate_binding "${name}" "${config_path}" "${spec_path}" "${output_path}"
done
