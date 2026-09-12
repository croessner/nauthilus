#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"
COMPOSE=(docker compose --project-directory "${ROOT_DIR}" -f "${ROOT_DIR}/docker-compose.yml")
PGO_DIR="${ROOT_DIR}/.work/pgo"
PGO_PIDS=()

usage() {
  cat <<'USAGE'
Usage: contrib/identity-proxy-e2e/scripts/run.sh <command>

Commands:
  prepare        Generate local certificates and signing keys under .work/.
  profile-check  Assert split-profile invariants with the Go harness.
  build-image    Build the current workspace image used by the E2E stack.
  up             Prepare material, build the image unless skipped, and start the stack.
  rpc            Run gRPC and generated OpenAPI management checks against the running stack.
  redis-check    Prove authority and edge Redis are isolated at the Compose network layer.
  browser        Run the Playwright browser smoke against the running stack.
  smoke          Reset the stack, then run profile-check, gRPC, Redis, browser, and post-browser checks.
  down           Stop and remove the E2E stack.

Environment:
  NAUTHILUS_E2E_SKIP_BUILD=1   Reuse NAUTHILUS_E2E_IMAGE instead of building.
  NAUTHILUS_E2E_IMAGE=...      Image used by docker-compose.
  NAUTHILUS_E2E_FORCE=1        Regenerate key material in prepare.
  NAUTHILUS_E2E_SAML_URL=...   Override the SAML SP login URL; set empty to skip SAML.
  NAUTHILUS_E2E_PGO=1          Capture and merge CPU profiles while the smoke workload runs.
  NAUTHILUS_E2E_PGO_SECONDS=N  CPU profile duration per Nauthilus instance (default: 30).
USAGE
}

pgo_enabled() {
  [[ "${NAUTHILUS_E2E_PGO:-0}" == "1" ]]
}

prepare_pgo_capture() {
  if ! pgo_enabled; then
    return
  fi

  if ! [[ "${NAUTHILUS_E2E_PGO_SECONDS:-30}" =~ ^[1-9][0-9]*$ ]]; then
    echo "NAUTHILUS_E2E_PGO_SECONDS must be a positive integer." >&2
    return 2
  fi

  export NAUTHILUS_E2E_ENABLE_PPROF=true
  mkdir -p "${PGO_DIR}"
  rm -f \
    "${PGO_DIR}/authority.pprof" \
    "${PGO_DIR}/edge-a.pprof" \
    "${PGO_DIR}/edge-b.pprof" \
    "${PGO_DIR}/candidate.pgo" \
    "${PGO_DIR}/candidate.pgo.tmp"
}

start_pgo_capture() {
  if ! pgo_enabled; then
    return
  fi

  local seconds="${NAUTHILUS_E2E_PGO_SECONDS:-30}"
  local max_time=$((seconds + 15))

  echo "Capturing ${seconds}s PGO CPU profiles from authority, edge-a, and edge-b."

  curl -fsS --max-time "${max_time}" \
    "http://127.0.0.1:18081/debug/pprof/profile?seconds=${seconds}" \
    -o "${PGO_DIR}/authority.pprof" &
  PGO_PIDS+=("$!")

  curl -kfsS --max-time "${max_time}" \
    "https://127.0.0.1:18080/debug/pprof/profile?seconds=${seconds}" \
    -o "${PGO_DIR}/edge-a.pprof" &
  PGO_PIDS+=("$!")

  curl -kfsS --max-time "${max_time}" \
    "https://127.0.0.1:18082/debug/pprof/profile?seconds=${seconds}" \
    -o "${PGO_DIR}/edge-b.pprof" &
  PGO_PIDS+=("$!")
}

cancel_pgo_capture() {
  local pid

  for pid in "${PGO_PIDS[@]}"; do
    kill "${pid}" >/dev/null 2>&1 || true
  done

  for pid in "${PGO_PIDS[@]}"; do
    wait "${pid}" >/dev/null 2>&1 || true
  done

  PGO_PIDS=()
}

finish_pgo_capture() {
  if ! pgo_enabled; then
    return
  fi

  local status=0
  local pid

  for pid in "${PGO_PIDS[@]}"; do
    wait "${pid}" || status=$?
  done
  PGO_PIDS=()

  if [[ "${status}" -ne 0 ]]; then
    echo "Failed to collect one or more PGO CPU profiles." >&2
    return "${status}"
  fi

  (
    cd "${REPO_DIR}"
    go tool pprof -proto \
      "${PGO_DIR}/authority.pprof" \
      "${PGO_DIR}/edge-a.pprof" \
      "${PGO_DIR}/edge-b.pprof" \
      > "${PGO_DIR}/candidate.pgo.tmp"
    mv "${PGO_DIR}/candidate.pgo.tmp" "${PGO_DIR}/candidate.pgo"
    go tool pprof -top "${PGO_DIR}/candidate.pgo" >/dev/null
  )

  echo "PGO candidate written to ${PGO_DIR}/candidate.pgo"
  echo "Review it before promoting it to server/default.pgo."
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
  "${COMPOSE[@]}" up -d authority edge-a edge-b
  wait_for_http "https://127.0.0.1:18080/ping" "edge-a"
  wait_for_http "https://127.0.0.1:18082/ping" "edge-b"
  wait_for_http "http://127.0.0.1:18081/ping" "authority"
  "${COMPOSE[@]}" up -d saml-sp
  wait_for_http "https://127.0.0.1:19095/" "saml-sp"
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
  "${COMPOSE[@]}" down -v --remove-orphans
}

smoke() {
  local status=0

  profile_check
  reset_stack
  prepare_pgo_capture
  up
  start_pgo_capture

  rpc_pre_browser || status=$?
  if [[ "${status}" -eq 0 ]]; then
    redis_check || status=$?
  fi
  if [[ "${status}" -eq 0 ]]; then
    browser || status=$?
  fi
  if [[ "${status}" -eq 0 ]]; then
    rpc_post_browser || status=$?
  fi

  if [[ "${status}" -eq 0 ]]; then
    finish_pgo_capture || status=$?
  else
    cancel_pgo_capture
  fi

  return "${status}"
}

down() {
  cancel_pgo_capture
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
