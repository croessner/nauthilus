#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
check_mode=false

proto_files=(
  "api/common/v1/common.proto"
  "api/auth/v1/auth.proto"
  "api/identity/v1/identity_backend.proto"
)

case "${1:-}" in
  "")
    ;;
  --check)
    check_mode=true
    shift
    ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac

if [[ $# -ne 0 ]]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc not found in PATH" >&2
  exit 1
fi

if ! command -v protoc-gen-go >/dev/null 2>&1; then
  echo "protoc-gen-go not found in PATH" >&2
  exit 1
fi

if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
  echo "protoc-gen-go-grpc not found in PATH" >&2
  exit 1
fi

cd "${repo_root}"

output_root="${repo_root}"
if [[ "${check_mode}" == true ]]; then
  output_root="$(mktemp -d)"
  trap 'rm -rf "${output_root}"' EXIT
fi

protoc \
  --proto_path=. \
  --go_out="${output_root}" \
  --go_opt=paths=source_relative \
  --go-grpc_out="${output_root}" \
  --go-grpc_opt=paths=source_relative \
  "${proto_files[@]}"

if [[ "${check_mode}" == true ]]; then
  drift=false
  generated_count=0

  while IFS= read -r -d '' generated_file; do
    ((generated_count += 1))
    relative_path="${generated_file#"${output_root}/"}"
    if ! diff -u "${repo_root}/${relative_path}" "${generated_file}"; then
      drift=true
    fi
  done < <(find "${output_root}/api" -type f -name '*.pb.go' -print0)

  if [[ ${generated_count} -eq 0 ]]; then
    echo "gRPC generation produced no Go bindings" >&2
    exit 1
  fi

  if [[ "${drift}" == true ]]; then
    echo "committed gRPC bindings are out of date; run make generate-grpc-proto" >&2
    exit 1
  fi

  echo "Committed gRPC bindings are up to date"
fi
