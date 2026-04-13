#!/usr/bin/env bash
set -euo pipefail

image=""
expected_alpine_digest=""
expected_golang_digest=""

usage() {
  cat <<'USAGE'
Usage: scripts/docker-stable-refresh-check.sh [options]

Options:
  --image <image>                       Stable image tag to inspect.
  --expected-alpine-digest <digest>    Current Alpine base image digest.
  --expected-golang-digest <digest>    Current Go builder image digest.
  -h, --help                           Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      image="$2"
      shift 2
      ;;
    --expected-alpine-digest)
      expected_alpine_digest="$2"
      shift 2
      ;;
    --expected-golang-digest)
      expected_golang_digest="$2"
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

if [[ -z "${image}" || -z "${expected_alpine_digest}" || -z "${expected_golang_digest}" ]]; then
  usage >&2
  exit 1
fi

if ! docker pull "${image}" >/dev/null 2>&1; then
  echo "reason=image-missing"
  echo "should_rebuild=true"
  exit 0
fi

existing_alpine_digest="$(
  docker inspect --format '{{ index .Config.Labels "io.nauthilus.base.alpine.digest" }}' "${image}" 2>/dev/null || true
)"
existing_golang_digest="$(
  docker inspect --format '{{ index .Config.Labels "io.nauthilus.base.golang.digest" }}' "${image}" 2>/dev/null || true
)"

echo "existing_alpine_digest=${existing_alpine_digest}"
echo "existing_golang_digest=${existing_golang_digest}"

if [[ -z "${existing_alpine_digest}" || -z "${existing_golang_digest}" ]]; then
  echo "reason=missing-base-digest-labels"
  echo "should_rebuild=true"
  exit 0
fi

if [[ "${existing_alpine_digest}" != "${expected_alpine_digest}" ]]; then
  echo "reason=alpine-digest-changed"
  echo "should_rebuild=true"
  exit 0
fi

if [[ "${existing_golang_digest}" != "${expected_golang_digest}" ]]; then
  echo "reason=golang-digest-changed"
  echo "should_rebuild=true"
  exit 0
fi

echo "reason=up-to-date"
echo "should_rebuild=false"
