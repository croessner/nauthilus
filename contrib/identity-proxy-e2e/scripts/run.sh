#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"
COMPOSE=(docker compose --project-directory "${ROOT_DIR}" -f "${ROOT_DIR}/docker-compose.yml")

usage() {
  cat <<'EOF'
Usage: contrib/identity-proxy-e2e/scripts/run.sh <command>

Commands:
  prepare        Generate local certificates and signing keys under .work/.
  profile-check  Assert split-profile invariants with the Go harness.
  build-image    Build the current workspace image used by the E2E stack.
  up             Prepare material, build the image unless skipped, and start the stack.
  rpc            Run gRPC positive and negative checks against the running stack.
  redis-check    Prove authority and edge Redis are isolated at the Compose network layer.
  browser        Run the Playwright browser smoke against the running stack.
  smoke          Reset the stack, then run profile-check, gRPC, Redis, browser, and post-browser checks.
  down           Stop and remove the E2E stack.

Environment:
  NAUTHILUS_E2E_SKIP_BUILD=1   Reuse NAUTHILUS_E2E_IMAGE instead of building.
  NAUTHILUS_E2E_IMAGE=...      Image used by docker-compose.
  NAUTHILUS_E2E_FORCE=1        Regenerate key material in prepare.
EOF
}

prepare() {
  "${ROOT_DIR}/scripts/prepare-materials.sh"
}

profile_check() {
  (
    cd "${REPO_DIR}"
    GOEXPERIMENT=runtimesecret GOCACHE="${GOCACHE:-/tmp/nauthilus-go-cache}" go test ./contrib/identity-proxy-e2e
  )
}

build_image() {
  if [[ "${NAUTHILUS_E2E_SKIP_BUILD:-}" == "1" ]]; then
    echo "Skipping image build; using ${NAUTHILUS_E2E_IMAGE:-nauthilus:identity-proxy-e2e}."
    return
  fi

  docker build -t "${NAUTHILUS_E2E_IMAGE:-nauthilus:identity-proxy-e2e}" "${REPO_DIR}"
}

wait_for_http() {
  local url="$1"
  local label="$2"

  for _ in $(seq 1 60); do
    if curl -kfsS "${url}" >/dev/null 2>&1; then
      echo "${label} is ready at ${url}."
      return
    fi

    sleep 1
  done

  echo "${label} did not become ready at ${url}." >&2
  return 1
}

up() {
  prepare
  build_image
  "${COMPOSE[@]}" up -d
  wait_for_http "https://127.0.0.1:18080/ping" "edge-a"
  wait_for_http "https://127.0.0.1:18082/ping" "edge-b"
  wait_for_http "http://127.0.0.1:18081/ping" "authority"
}

rpc_pre_browser() {
  (
    cd "${REPO_DIR}"
    GOEXPERIMENT=runtimesecret GOCACHE="${GOCACHE:-/tmp/nauthilus-go-cache}" go run ./contrib/identity-proxy-e2e/cmd/smoke --mode pre-browser
  )
}

rpc_post_browser() {
  (
    cd "${REPO_DIR}"
    GOEXPERIMENT=runtimesecret GOCACHE="${GOCACHE:-/tmp/nauthilus-go-cache}" go run ./contrib/identity-proxy-e2e/cmd/smoke --mode post-browser
  )
}

redis_check() {
  if "${COMPOSE[@]}" exec -T authority-redis redis-cli -h edge-redis -p 6379 ping >/dev/null 2>&1; then
    echo "authority Redis can reach edge Redis; expected isolation." >&2
    return 1
  fi

  echo "ok redis-network-separation-authority"

  if "${COMPOSE[@]}" exec -T edge-redis redis-cli -h authority-redis -p 6379 ping >/dev/null 2>&1; then
    echo "edge Redis can reach authority Redis; expected isolation." >&2
    return 1
  fi

  echo "ok redis-network-separation-edge"
}

browser() {
  node "${ROOT_DIR}/scripts/browser-e2e.js"
}

reset_stack() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}

smoke() {
  profile_check
  reset_stack
  up
  rpc_pre_browser
  redis_check
  browser
  rpc_post_browser
}

down() {
  "${COMPOSE[@]}" down -v --remove-orphans
}

command="${1:-}"
case "${command}" in
  prepare)
    prepare
    ;;
  profile-check)
    profile_check
    ;;
  build-image)
    build_image
    ;;
  up)
    up
    ;;
  rpc)
    rpc_pre_browser
    ;;
  redis-check)
    redis_check
    ;;
  browser)
    browser
    ;;
  smoke)
    smoke
    ;;
  down)
    down
    ;;
  ""|help|--help|-h)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
