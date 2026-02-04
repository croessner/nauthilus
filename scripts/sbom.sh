#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEFAULT_OUTPUT_PREFIX="nauthilus"

OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/sbom}"
OUTPUT_PREFIX="${OUTPUT_PREFIX:-${DEFAULT_OUTPUT_PREFIX}}"
OUTPUT_PREFIX_SET=false
SOURCE_DIR="${SOURCE_DIR:-${ROOT_DIR}}"
SKIP_SOURCE=false
FILE_TARGET=""
DOCKER_IMAGE=""
SKIP_DOCKER=false
DOCKER_PULL="${DOCKER_PULL:-false}"
SYFT_VERSION="${SYFT_VERSION:-v1.16.0}"
SYFT_BIN="${SYFT_BIN:-${ROOT_DIR}/bin/syft}"

pretty_print_json() {
  local target="$1"
  local tmp

  tmp="${target}.tmp"

  if command -v jq >/dev/null 2>&1; then
    jq . "${target}" > "${tmp}"
    mv "${tmp}" "${target}"
    return
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool "${target}" > "${tmp}"
    mv "${tmp}" "${target}"
    return
  fi

  if command -v python >/dev/null 2>&1; then
    python -m json.tool "${target}" > "${tmp}"
    mv "${tmp}" "${target}"
    return
  fi

  echo "No JSON formatter found (jq/python3/python) to pretty-print ${target}" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: scripts/sbom.sh [options]

Options:
  --output-dir <path>       Output directory for SBOM files (default: ./sbom)
  --output-prefix <name>    File name prefix for SBOMs (default: nauthilus)
  --source-dir <path>       Directory to scan (default: repo root)
  --skip-source             Skip source directory SBOM
  --file <path>             Generate SBOM for a file (e.g. .deb/.rpm/.tar.gz)
  --docker-image <image>    Generate SBOM for a Docker image
  --docker-pull <true|false>Pull image before SBOM generation (default: false)
  --skip-docker             Skip Docker image SBOM
  --syft-version <version>  Syft version to install if missing (default: v1.16.0)
  --syft-bin <path>         Path to syft binary (default: ./bin/syft)
  -h, --help                Show this help
USAGE
}

ensure_syft() {
  if [ -x "${SYFT_BIN}" ]; then
    return
  fi

  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to install syft" >&2
    exit 1
  fi

  mkdir -p "$(dirname "${SYFT_BIN}")"

  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$(dirname "${SYFT_BIN}")" "${SYFT_VERSION}"

  if [ ! -x "${SYFT_BIN}" ]; then
    echo "syft installation failed" >&2
    exit 1
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --output-prefix)
      OUTPUT_PREFIX="$2"
      OUTPUT_PREFIX_SET=true
      shift 2
      ;;
    --source-dir)
      SOURCE_DIR="$2"
      shift 2
      ;;
    --skip-source)
      SKIP_SOURCE=true
      shift
      ;;
    --file)
      FILE_TARGET="$2"
      shift 2
      ;;
    --docker-image)
      DOCKER_IMAGE="$2"
      shift 2
      ;;
    --docker-pull)
      DOCKER_PULL="$2"
      shift 2
      ;;
    --skip-docker)
      SKIP_DOCKER=true
      shift
      ;;
    --syft-version)
      SYFT_VERSION="$2"
      shift 2
      ;;
    --syft-bin)
      SYFT_BIN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -n "${FILE_TARGET}" ] && [ "${OUTPUT_PREFIX_SET}" = false ] && [ "${OUTPUT_PREFIX}" = "${DEFAULT_OUTPUT_PREFIX}" ]; then
  OUTPUT_PREFIX=$(basename "${FILE_TARGET}")
fi

ensure_syft

mkdir -p "${OUTPUT_DIR}"

if [ "${SKIP_SOURCE}" = false ]; then
  if [ ! -d "${SOURCE_DIR}" ]; then
    echo "Source directory not found: ${SOURCE_DIR}" >&2
    exit 1
  fi

  "${SYFT_BIN}" "dir:${SOURCE_DIR}" -o "spdx-json=${OUTPUT_DIR}/${OUTPUT_PREFIX}-source.spdx.json"
  pretty_print_json "${OUTPUT_DIR}/${OUTPUT_PREFIX}-source.spdx.json"
fi

if [ -n "${FILE_TARGET}" ]; then
  if [ ! -f "${FILE_TARGET}" ]; then
    echo "File not found: ${FILE_TARGET}" >&2
    exit 1
  fi

  "${SYFT_BIN}" "file:${FILE_TARGET}" -o "spdx-json=${OUTPUT_DIR}/${OUTPUT_PREFIX}.spdx.json"
  pretty_print_json "${OUTPUT_DIR}/${OUTPUT_PREFIX}.spdx.json"
fi

if [ "${SKIP_DOCKER}" = false ] && [ -n "${DOCKER_IMAGE}" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for Docker image SBOMs" >&2
    exit 1
  fi

  if [ "${DOCKER_PULL}" = "true" ]; then
    docker pull "${DOCKER_IMAGE}"
  fi

  "${SYFT_BIN}" "${DOCKER_IMAGE}" -o "spdx-json=${OUTPUT_DIR}/${OUTPUT_PREFIX}-image.spdx.json"
  pretty_print_json "${OUTPUT_DIR}/${OUTPUT_PREFIX}-image.spdx.json"
fi