#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"
COMPOSE=(docker compose --project-directory "${ROOT_DIR}" -f "${ROOT_DIR}/docker-compose.yml")
PGO_DIR="${ROOT_DIR}/.work/pgo"
PLUGIN_RELOAD_DIR="${ROOT_DIR}/.work/plugin-reload"
PLUGIN_RELOAD_URL="http://127.0.0.1:38083"
# Seconds the PGO workload runs before the profiles start (token, connections, account provisioning) and after they
# end, so every sampled second carries request traffic.
PGO_LOAD_WARMUP_SECONDS=3
PGO_LOAD_TAIL_SECONDS=5
PGO_PIDS=()
# Second-factor outcomes the browser smoke must leave in nauthilus.auth_events as method|result|reason|flow_effect.
CLICKHOUSE_EXPECTED_EVENTS=(
  "totp|success|verified|step_up_completed"
  "totp|success|verified|primary_failure_kept"
  "totp|invalid|invalid_code|none"
  "totp|rate_limited|attempt_limit|none"
  "recovery_codes|success|verified|step_up_completed"
  "recovery_codes|success|verified|primary_failure_kept"
  "recovery_codes|invalid|invalid_code|none"
  "webauthn|success|verified|step_up_completed"
  "webauthn|invalid|assertion_rejected|none"
  # OIDC authorization-code completion: code issued after a login on the flow, code redeemed at the token endpoint.
  "|success|authenticated_in_flow|code_issued"
  "|success|tokens_issued|tokens_issued"
)
# Synthetic credentials of the support history check (config/edge-a.yml); never real accounts.
HISTORY_READER_PASSWORD="e2e-history-reader"
HISTORY_CLIENT_ID="split-e2e-support"
HISTORY_CLIENT_SECRET="split-e2e-support-secret"

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
  plugin-reload  Prove that SIGHUP applies native plugin config and refuses artifact changes.
  clickhouse-events  Prove that browser MFA flows produced the expected auth_events rows in ClickHouse.
  clickhouse-history Prove browser OIDC completion events reach the history API and the owner Python client.
  smoke          Reset the stack, then run profile-check, gRPC, Redis, browser, and post-browser checks
                 (with NAUTHILUS_E2E_PGO=1 followed by the PGO authentication workload).
  down           Stop and remove the E2E stack.

Environment:
  NAUTHILUS_E2E_SKIP_BUILD=1   Reuse NAUTHILUS_E2E_IMAGE instead of building.
  NAUTHILUS_E2E_IMAGE=...      Image used by docker-compose.
  NAUTHILUS_E2E_FORCE=1        Regenerate key material in prepare.
  NAUTHILUS_E2E_SAML_URL=...   Override the SAML SP login URL; set empty to skip SAML.
  NAUTHILUS_E2E_PGO=1          After the checks pass, run an authentication workload and merge its CPU profiles.
  NAUTHILUS_E2E_PGO_SECONDS=N  CPU profile duration per Nauthilus instance (default: 30).
  NAUTHILUS_E2E_PGO_MIN_SAMPLES=N  Minimum CPU samples a candidate must carry (default: 1000).
USAGE
}

# Report whether this run requests CPU profile capture.
pgo_enabled() {
  [[ "${NAUTHILUS_E2E_PGO:-0}" == "1" ]]
}

# Validate capture settings and discard candidates from earlier runs.
prepare_pgo_capture() {
  if ! pgo_enabled; then
    return
  fi

  if ! [[ "${NAUTHILUS_E2E_PGO_SECONDS:-30}" =~ ^[1-9][0-9]*$ ]]; then
    echo "NAUTHILUS_E2E_PGO_SECONDS must be a positive integer." >&2
    return 2
  fi

  if ! [[ "${NAUTHILUS_E2E_PGO_MIN_SAMPLES:-1000}" =~ ^[1-9][0-9]*$ ]]; then
    echo "NAUTHILUS_E2E_PGO_MIN_SAMPLES must be a positive integer." >&2
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

# Start one bounded profile request and retain its process for cleanup.
capture_pgo_profile() {
  local name="$1"
  local url="$2"
  local seconds="${NAUTHILUS_E2E_PGO_SECONDS:-30}"
  local max_time=$((seconds + 15))
  shift 2

  curl "$@" -fsS --max-time "${max_time}" \
    "${url}/debug/pprof/profile?seconds=${seconds}" \
    -o "${PGO_DIR}/${name}.pprof" &
  PGO_PIDS+=("$!")
}

# Collect CPU profiles of all three instances concurrently.
start_pgo_capture() {
  echo "Capturing ${NAUTHILUS_E2E_PGO_SECONDS:-30}s PGO CPU profiles from authority, edge-a, and edge-b."
  capture_pgo_profile authority http://127.0.0.1:38081
  capture_pgo_profile edge-a https://127.0.0.1:38080 -k
  capture_pgo_profile edge-b https://127.0.0.1:38082 -k
}

# Stop and reap every outstanding profile request.
cancel_pgo_capture() {
  local pid

  for pid in ${PGO_PIDS[@]+"${PGO_PIDS[@]}"}; do
    kill "${pid}" >/dev/null 2>&1 || true
  done

  for pid in ${PGO_PIDS[@]+"${PGO_PIDS[@]}"}; do
    wait "${pid}" >/dev/null 2>&1 || true
  done

  PGO_PIDS=()
}

# Publish a candidate only after capture, merge, and profile validation succeed.
finish_pgo_capture() {
  if ! pgo_enabled; then
    return
  fi

  local status=0
  local pid

  for pid in ${PGO_PIDS[@]+"${PGO_PIDS[@]}"}; do
    wait "${pid}" || status=$?
  done
  PGO_PIDS=()

  if [[ "${status}" -ne 0 ]]; then
    echo "Failed to collect one or more PGO CPU profiles." >&2
    return "${status}"
  fi

  (
    cd "${REPO_DIR}" || exit $?
    go tool pprof -proto \
      "${PGO_DIR}/authority.pprof" \
      "${PGO_DIR}/edge-a.pprof" \
      "${PGO_DIR}/edge-b.pprof" \
      > "${PGO_DIR}/candidate.pgo.tmp" || exit $?
    go tool pprof -top "${PGO_DIR}/candidate.pgo.tmp" >/dev/null || exit $?
    require_pgo_samples "${PGO_DIR}/candidate.pgo.tmp" || exit $?
    mv "${PGO_DIR}/candidate.pgo.tmp" "${PGO_DIR}/candidate.pgo" || exit $?
  ) || return $?

  echo "PGO candidate written to ${PGO_DIR}/candidate.pgo"
  echo "The PGO refresh workflow promotes release candidates to server/default.pgo."
}

# Refuse a candidate whose CPU samples cannot describe a hot path: a profile of idle instances only adds noise to the
# compiler's decisions.
require_pgo_samples() {
  local profile="$1"
  local minimum="${NAUTHILUS_E2E_PGO_MIN_SAMPLES:-1000}"
  local samples

  samples="$(go tool pprof -sample_index=samples -top -nodecount=1 "${profile}" |
    sed -n 's/.*Total samples = \([0-9][0-9]*\).*/\1/p')"

  if [[ -z "${samples}" || "${samples}" -lt "${minimum}" ]]; then
    echo "PGO candidate carries ${samples:-no} CPU samples; at least ${minimum} are required." >&2
    return 1
  fi

  echo "PGO candidate carries ${samples} CPU samples."
}

# Run the authentication workload of the PGO capture. The load client is built first, the profiles start after a
# short warm-up, and the workload outlasts them, so the candidate samples request handling instead of idle time.
pgo_workload() {
  if ! pgo_enabled; then
    return
  fi

  local seconds="${NAUTHILUS_E2E_PGO_SECONDS:-30}"
  local load_client="${PGO_DIR}/pgo-load"
  local load_pid
  local status=0

  (
    cd "${REPO_DIR}" &&
      GOEXPERIMENT=runtimesecret GOCACHE="${GOCACHE:-/tmp/nauthilus-go-cache}" \
        go build -mod=vendor -o "${load_client}" ./contrib/identity-proxy-e2e/cmd/smoke
  ) || return $?

  (
    cd "${REPO_DIR}" &&
      exec "${load_client}" --mode pgo-load \
        --load-duration "$((seconds + PGO_LOAD_WARMUP_SECONDS + PGO_LOAD_TAIL_SECONDS))s" \
        --edge-client-id "${HISTORY_CLIENT_ID}" --edge-client-secret "${HISTORY_CLIENT_SECRET}"
  ) &
  load_pid=$!

  sleep "${PGO_LOAD_WARMUP_SECONDS}"
  start_pgo_capture
  wait "${load_pid}" || status=$?

  if [[ "${status}" -ne 0 ]]; then
    echo "The PGO authentication workload failed." >&2
    cancel_pgo_capture

    return "${status}"
  fi

  finish_pgo_capture
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

# Print every host port the run binds: the ports published by the Compose file and the browser callback port.
e2e_host_ports() {
  "${COMPOSE[@]}" config | awk '$1 == "published:" { gsub(/"/, "", $2); print $2 }'
  echo "${NAUTHILUS_E2E_CALLBACK_PORT:-39094}"
}

# Report whether something already accepts connections on one loopback port.
host_port_in_use() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1
}

# Fail fast when a host port of the stack is taken by anything but this stack, naming the owning container.
check_host_ports() {
  local own owners port busy=0

  own="$("${COMPOSE[@]}" ps -q 2>/dev/null | sort)"

  for port in $(e2e_host_ports | sort -un); do
    if ! host_port_in_use "${port}"; then
      continue
    fi

    owners="$(docker ps -q --filter "publish=${port}" | sort)"
    if [[ -n "${owners}" && -z "$(comm -23 <(echo "${owners}") <(echo "${own}"))" ]]; then
      continue
    fi

    echo "Host port ${port} is already in use${owners:+ by container(s) $(docker ps --filter "publish=${port}" --format '{{.Names}}' | paste -sd, -)}." >&2
    busy=1
  done

  if [[ "${busy}" -ne 0 ]]; then
    echo "Stop the listed services before running the identity-proxy E2E stack." >&2
    return 1
  fi
}

up() {
  prepare
  check_host_ports
  build_image
  "${COMPOSE[@]}" up -d authority edge-a edge-b
  wait_for_http "https://127.0.0.1:38080/ping" "edge-a"
  wait_for_http "https://127.0.0.1:38082/ping" "edge-b"
  wait_for_http "http://127.0.0.1:38081/ping" "authority"
  "${COMPOSE[@]}" up -d saml-sp
  wait_for_http "https://127.0.0.1:39095/" "saml-sp"
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

# Write the plugin reload config from its fixture, applying optional sed expressions.
write_plugin_reload_config() {
  mkdir -p "${PLUGIN_RELOAD_DIR}"
  sed -e '' "$@" "${ROOT_DIR}/config/plugin-reload.yml" >"${PLUGIN_RELOAD_DIR}/nauthilus.yml.tmp"
  mv "${PLUGIN_RELOAD_DIR}/nauthilus.yml.tmp" "${PLUGIN_RELOAD_DIR}/nauthilus.yml"
}

# Print one clickhouse reload outcome counter, or 0 before the first observation.
plugin_reload_metric() {
  local result="$1"

  curl -fsS "${PLUGIN_RELOAD_URL}/metrics" |
    awk -v series="plugin_reconfigure_total{module=\"clickhouse\",result=\"${result}\"}" \
      '$1 == series { value = $2 } END { print (value == "" ? 0 : value) }'
}

# Wait until one clickhouse reload outcome counter reaches the expected value.
wait_for_plugin_reload_metric() {
  local result="$1"
  local want="$2"

  for _ in $(seq 1 30); do
    if [[ "$(plugin_reload_metric "${result}")" == "${want}" ]]; then
      return
    fi

    sleep 1
  done

  echo "plugin_reconfigure_total{result=${result}} did not reach ${want}." >&2
  return 1
}

# Print the start time of the plugin reload container to detect restarts.
plugin_reload_started_at() {
  docker inspect -f '{{.State.StartedAt}}' "$("${COMPOSE[@]}" ps -q plugin-reload)"
}

# Apply a config-only change and an artifact change through SIGHUP on one running instance.
plugin_reload() {
  local started

  write_plugin_reload_config
  "${COMPOSE[@]}" up -d plugin-reload-redis plugin-reload
  wait_for_http "${PLUGIN_RELOAD_URL}/ping" "plugin-reload"
  started="$(plugin_reload_started_at)"

  write_plugin_reload_config -e 's/flush_interval: 0s/flush_interval: 2s/'
  "${COMPOSE[@]}" kill -s HUP plugin-reload
  wait_for_plugin_reload_metric reloaded 1

  if ! "${COMPOSE[@]}" logs plugin-reload | grep "clickhouse flush worker updated" | grep -q "running"; then
    echo "The clickhouse flush worker did not start after the config reload." >&2
    return 1
  fi

  echo "ok plugin-config-reload-applied"

  write_plugin_reload_config -e 's/flush_interval: 0s/flush_interval: 2s/' -e 's#plugins/clickhouse.so#plugins/geoip.so#'
  "${COMPOSE[@]}" kill -s HUP plugin-reload
  wait_for_plugin_reload_metric restart_required 1

  if [[ "$(plugin_reload_metric reloaded)" != "1" ]]; then
    echo "The artifact change was applied by a reload." >&2
    return 1
  fi

  echo "ok plugin-artifact-change-restart-required"

  if [[ "$(plugin_reload_started_at)" != "${started}" ]]; then
    echo "The plugin reload instance restarted during the reload checks." >&2
    return 1
  fi

  echo "ok plugin-reload-without-restart"
}

# Query the disposable E2E ClickHouse and print tab-separated rows.
clickhouse_query() {
  "${COMPOSE[@]}" exec -T clickhouse clickhouse-client --query "$1" --format TSV
}

# Prove that the browser MFA flows produced secret-free auth_events rows with the expected outcome vocabulary.
clickhouse_events_check() {
  local evidence="${ROOT_DIR}/.work/clickhouse-auth-events.tsv"
  local summary=""
  local previous=""

  # Wait until two polls past the event flush interval return the same summary.
  for _ in $(seq 1 30); do
    summary="$(clickhouse_query "SELECT method, result, reason, flow_effect, fail_latched, protocol, count() FROM nauthilus.auth_events GROUP BY method, result, reason, flow_effect, fail_latched, protocol ORDER BY method, result, reason, fail_latched, protocol")"
    if [[ -n "${summary}" && "${summary}" == "${previous}" ]]; then
      break
    fi
    previous="${summary}"
    sleep 2
  done

  mkdir -p "${ROOT_DIR}/.work"
  printf '%s\n' "${summary}" > "${evidence}"
  echo "auth_events summary (method result reason flow_effect fail_latched protocol count):"
  printf '%s\n' "${summary}"

  if [[ -z "${summary}" ]]; then
    echo "The browser MFA flows left no auth_events rows in ClickHouse." >&2
    return 1
  fi

  local expected
  for expected in "${CLICKHOUSE_EXPECTED_EVENTS[@]}"; do
    if ! awk -F '\t' -v want="${expected}" '($1 "|" $2 "|" $3 "|" $4) == want { found = 1 } END { exit !found }' <<<"${summary}"; then
      echo "Missing auth_events outcome: ${expected}" >&2
      return 1
    fi
  done

  local invalid
  invalid="$(clickhouse_query "SELECT count() FROM nauthilus.auth_events WHERE length(event_id) != 32 OR event_version != 1 OR (protocol IN ('oidc', 'saml') AND length(flow_ref) != 32) OR (protocol = 'account' AND flow_ref != '')")"
  if [[ "${invalid}" != "0" ]]; then
    echo "auth_events contains ${invalid} rows that violate the event identity or flow_ref contract." >&2
    return 1
  fi

  echo "ok clickhouse-auth-events"
}

# Provision the documented read-only history account in the disposable ClickHouse with the synthetic password.
provision_history_reader() {
  sed "s/CHANGE_ME_PASSWORD/${HISTORY_READER_PASSWORD}/" "${REPO_DIR}/contrib/clickhouse-kubernetes/history-reader.sql" |
    "${COMPOSE[@]}" exec -T clickhouse clickhouse-client --multiquery
}

# Run the owner Python client against the edge-a history API with the synthetic support console.
history_client() {
  NAUTHILUS_URL="https://127.0.0.1:38080" python3 "${REPO_DIR}/contrib/client/nauthilus-admin.py" --insecure \
    --token-cache off --client-id "${HISTORY_CLIENT_ID}" --client-secret "${HISTORY_CLIENT_SECRET}" \
    --scopes "nauthilus:authenticate nauthilus:history_read nauthilus:history_detail" "$@"
}

# Prove the OIDC completion path end to end: browser authorization-code flows -> auth_events in ClickHouse -> the
# read-only history API of edge-a -> the owner Python client. The edges record step events only (password rows are
# written by the authority, which has no analytics effect here), so the history is partial and flows report
# PRIMARY_ROW_NOT_RECORDED; the completion evidence is what this check proves.
clickhouse_history_check() {
  local evidence="${ROOT_DIR}/.work/history-attempts.json"
  local account="" status=0

  provision_history_reader

  for _ in $(seq 1 30); do
    account="$(clickhouse_query "SELECT account FROM nauthilus.auth_events WHERE event_type = 'oidc.code_redemption' AND result = 'success' AND deployment = 'e2e' AND account != '' GROUP BY account ORDER BY count() DESC, account LIMIT 1")"
    [[ -n "${account}" ]] && break
    sleep 2
  done

  if [[ -z "${account}" ]]; then
    echo "The browser OIDC flows left no successful code redemption in ClickHouse." >&2
    return 1
  fi

  mkdir -p "${ROOT_DIR}/.work"
  history_client --output json support attempts search --account "${account}" --since 2h --all \
    --audit-reference e2e-history >"${evidence}" || status=$?
  if [[ "${status}" -ne 0 && "${status}" -ne 3 ]]; then
    echo "The history search failed with exit code ${status}." >&2
    return 1
  fi

  python3 - "${evidence}" <<'PY' || return 1
import json, sys

answer = json.load(open(sys.argv[1]))
attempts = answer.get("attempts") or []
done = [a for a in attempts if (a.get("completion") or {}).get("state") == "tokens_issued"]
if not done:
    sys.exit("no attempt reports completion.state tokens_issued")
for attempt in done:
    steps = attempt.get("steps") or {}
    codes = [event.get("code") for event in attempt.get("events") or []]
    if attempt.get("outcome") != "succeeded" or attempt.get("outcome_basis") != "oidc_tokens_issued" or \
            not attempt.get("final_outcome_observed") or steps.get("code_redemption") != "recorded" or \
            "TOKENS_ISSUED" not in codes:
        sys.exit("inconsistent completed attempt: " + json.dumps(attempt)[:600])
    stages = [event.get("stage") for event in attempt.get("events") or []]
    if "token_exchange" not in stages or any(event.get("factor") for event in attempt.get("events") or []
                                             if event.get("stage") in ("authorization", "token_exchange")):
        sys.exit("completion events must keep their own stages without factor blocks")
if answer["history"].get("oidc_completion_events_since") is None:
    sys.exit("history.oidc_completion_events_since missing")
if "FLOW_COMPLETION_RECORDED_FOR_OIDC_AUTHORIZATION_CODE_ONLY" not in answer["history"].get("known_limits", []):
    sys.exit("known limits do not name the recorded completion scope")
states = sorted({(a.get("completion") or {}).get("state") or "-" for a in attempts})
sources = sorted({(a.get("completion") or {}).get("authentication") or "-" for a in attempts})
print(f"history attempts={len(attempts)} completed={len(done)} states={states} authentication={sources}")
PY

  local detail
  detail="$(python3 -c 'import json,sys; a=[x for x in json.load(open(sys.argv[1]))["attempts"] if (x.get("completion") or {}).get("state")=="tokens_issued"][0]; print(a["attempt_id"], a["started_at"])' "${evidence}")"
  echo "history search (compact):"
  history_client support attempts search --account "${account}" --since 2h --all --summary || [[ $? -eq 3 ]]
  echo "history detail of one completed flow (compact):"
  history_client support attempts detail --attempt-id "${detail%% *}" --around "${detail##* }" \
    --account "${account}" --summary || [[ $? -eq 3 ]]

  echo "ok clickhouse-history"
}

reset_stack() {
  "${COMPOSE[@]}" down -v --remove-orphans
}

# Run the complete smoke sequence and retain profile-capture failures.
smoke() {
  local status=0

  profile_check
  reset_stack
  prepare_pgo_capture
  up

  rpc_pre_browser || status=$?
  if [[ "${status}" -eq 0 ]]; then
    redis_check || status=$?
  fi
  if [[ "${status}" -eq 0 ]]; then
    browser || status=$?
  fi
  if [[ "${status}" -eq 0 ]]; then
    clickhouse_events_check || status=$?
  fi
  if [[ "${status}" -eq 0 ]]; then
    clickhouse_history_check || status=$?
  fi
  if [[ "${status}" -eq 0 ]]; then
    rpc_post_browser || status=$?
  fi
  if [[ "${status}" -eq 0 ]]; then
    plugin_reload || status=$?
  fi

  if [[ "${status}" -eq 0 ]]; then
    pgo_workload || status=$?
  fi

  return "${status}"
}

# Reap local capture processes before removing the isolated Compose stack.
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
  plugin-reload)
    plugin_reload
    ;;
  clickhouse-events)
    clickhouse_events_check
    ;;
  clickhouse-history)
    clickhouse_history_check
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
