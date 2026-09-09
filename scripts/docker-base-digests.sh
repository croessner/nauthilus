#!/usr/bin/env bash
set -euo pipefail

alpine_image="${ALPINE_IMAGE:-alpine:3.24}"
golang_image="${GOLANG_IMAGE:-golang:1.27.1-alpine3.24}"

# Read one literal upstream image per family from the selected source Dockerfile.
dockerfile_image() {
  local family="$1" dockerfile="$2" image
  image="$(awk -v family="${family}:" '
    toupper($1) == "FROM" {
      i = 2
      if ($i ~ /^--platform=/) i++
      if (index($i, family) == 1) print $i
    }
  ' "${dockerfile}")"
  if [[ ! "${image}" =~ ^${family}:[a-zA-Z0-9_.:@-]+$ ]]; then
    echo "Expected one literal ${family} base image in ${dockerfile}." >&2
    return 1
  fi
  printf '%s\n' "${image}"
}

if [[ $# -gt 0 ]]; then
  if [[ $# -ne 2 || "$1" != "--dockerfile" ]]; then
    echo "Usage: $0 [--dockerfile path]" >&2
    exit 1
  fi
  alpine_image="$(dockerfile_image alpine "$2")"
  golang_image="$(dockerfile_image golang "$2")"
fi

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
  )" || return 1

  printf 'sha256:%s\n' "${digest}"
}

alpine_digest="$(manifest_digest "${alpine_image}")"
golang_digest="$(manifest_digest "${golang_image}")"

printf 'alpine_image=%s\n' "${alpine_image}"
printf 'alpine_digest=%s\n' "${alpine_digest}"
printf 'golang_image=%s\n' "${golang_image}"
printf 'golang_digest=%s\n' "${golang_digest}"
