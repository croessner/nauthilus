#!/usr/bin/env bash
set -euo pipefail

alpine_image="${ALPINE_IMAGE:-alpine:3.23}"
golang_image="${GOLANG_IMAGE:-golang:1.26-alpine3.23}"

hash_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256
    return
  fi

  echo "No SHA-256 tool found (sha256sum/shasum)." >&2
  exit 1
}

manifest_digest() {
  local image="$1"
  local digest

  digest="$(
    docker buildx imagetools inspect "${image}" --raw \
      | hash_cmd \
      | awk '{print $1}'
  )"

  printf 'sha256:%s\n' "${digest}"
}

printf 'alpine_image=%s\n' "${alpine_image}"
printf 'alpine_digest=%s\n' "$(manifest_digest "${alpine_image}")"
printf 'golang_image=%s\n' "${golang_image}"
printf 'golang_digest=%s\n' "$(manifest_digest "${golang_image}")"
