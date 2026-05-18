#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

proto_files=(
  "server/grpcapi/common/v1/common.proto"
  "server/grpcapi/auth/v1/auth.proto"
  "server/grpcapi/identity/v1/identity_backend.proto"
)

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

protoc \
  --proto_path=. \
  --go_out=. \
  --go_opt=paths=source_relative \
  --go-grpc_out=. \
  --go-grpc_opt=paths=source_relative \
  "${proto_files[@]}"
