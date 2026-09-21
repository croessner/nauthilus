#!/usr/bin/env bash
# Reject compiler drift before generating or comparing public bindings.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/protobuf-toolchain.env"
if [[ "$(protoc --version)" != "libprotoc ${PROTOC_VERSION}" ]]; then
  echo "protoc ${PROTOC_VERSION} is required" >&2
  exit 1
fi
if [[ "$(protoc-gen-go --version)" != "protoc-gen-go v${PROTOC_GEN_GO_VERSION}" ]]; then
  echo "protoc-gen-go ${PROTOC_GEN_GO_VERSION} is required" >&2
  exit 1
fi
if [[ "$(protoc-gen-go-grpc --version)" != "protoc-gen-go-grpc ${PROTOC_GEN_GO_GRPC_VERSION}" ]]; then
  echo "protoc-gen-go-grpc ${PROTOC_GEN_GO_GRPC_VERSION} is required" >&2
  exit 1
fi
