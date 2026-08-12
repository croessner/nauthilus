#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
baseline_descriptor="${repo_root}/server/grpcapi/internal/prototest/testdata/public-protobuf-baseline.pb"
compatibility_tmp="$(mktemp -d)"
legacy_root="${compatibility_tmp}/legacy"
current_descriptor="${compatibility_tmp}/public-protobuf-current.pb"
legacy_proto_root="server/grpcapi"
legacy_module_root="github.com/croessner/nauthilus/v3/${legacy_proto_root}"

trap 'rm -rf -- "${compatibility_tmp}"' EXIT

if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc not found in PATH" >&2
  exit 1
fi

if [[ ! -f "${baseline_descriptor}" ]]; then
  echo "frozen public protobuf descriptor not found: ${baseline_descriptor}" >&2
  exit 1
fi

mkdir -p \
  "${legacy_root}/${legacy_proto_root}/common/v1" \
  "${legacy_root}/${legacy_proto_root}/auth/v1" \
  "${legacy_root}/${legacy_proto_root}/identity/v1"

# Render current sources with their former ownership metadata so only wire
# descriptor semantics participate in the frozen comparison.
sed \
  -e "s#github.com/croessner/nauthilus/v3/api/common/v1#${legacy_module_root}/common/v1#" \
  "${repo_root}/api/common/v1/common.proto" \
  >"${legacy_root}/${legacy_proto_root}/common/v1/common.proto"

sed \
  -e "s#api/common/v1/common.proto#${legacy_proto_root}/common/v1/common.proto#" \
  -e "s#github.com/croessner/nauthilus/v3/api/auth/v1#${legacy_module_root}/auth/v1#" \
  "${repo_root}/api/auth/v1/auth.proto" \
  >"${legacy_root}/${legacy_proto_root}/auth/v1/auth.proto"

sed \
  -e "s#api/common/v1/common.proto#${legacy_proto_root}/common/v1/common.proto#" \
  -e "s#github.com/croessner/nauthilus/v3/api/identity/v1#${legacy_module_root}/identity/v1#" \
  "${repo_root}/api/identity/v1/identity_backend.proto" \
  >"${legacy_root}/${legacy_proto_root}/identity/v1/identity_backend.proto"

cd "${legacy_root}"

protoc \
  --proto_path=. \
  --include_imports \
  --descriptor_set_out="${current_descriptor}" \
  "${legacy_proto_root}/common/v1/common.proto" \
  "${legacy_proto_root}/auth/v1/auth.proto" \
  "${legacy_proto_root}/identity/v1/identity_backend.proto"

if ! cmp -s "${baseline_descriptor}" "${current_descriptor}"; then
  echo "public protobuf wire descriptors drifted from the frozen baseline" >&2
  exit 1
fi

echo "Public protobuf wire descriptors match the frozen baseline"
