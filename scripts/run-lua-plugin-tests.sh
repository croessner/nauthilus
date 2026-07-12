#!/usr/bin/env bash
set -euo pipefail

export GOEXPERIMENT="${GOEXPERIMENT:-runtimesecret}"

run_test() {
  local script="$1"
  local callback="$2"
  local mock="$3"

  echo "[lua-test] ${script} (${callback})"
  go run ./server --test-lua "${script}" --test-callback "${callback}" --test-mock "${mock}"
}

run_test testdata/lua/plugins/action_analytics_wrapper.lua action testdata/lua/plugins/action_analytics_test.json
run_test testdata/lua/plugins/action_analytics_policy_facts_wrapper.lua action testdata/lua/plugins/action_analytics_policy_facts_test.json
run_test testdata/lua/plugins/action_bruteforce_header_wrapper.lua action testdata/lua/plugins/action_bruteforce_header_test.json
run_test testdata/lua/plugins/action_failed_login_tracker_wrapper.lua action testdata/lua/plugins/action_failed_login_tracker_test.json
run_test testdata/lua/plugins/action_test_context_chain_bruteforce_reject_wrapper.lua action testdata/lua/plugins/action_test_context_chain_bruteforce_reject_test.json
run_test testdata/lua/plugins/action_test_context_chain_environment_reject_wrapper.lua action testdata/lua/plugins/action_test_context_chain_environment_reject_test.json
run_test testdata/lua/plugins/action_test_context_chain_no_auth_without_environment_wrapper.lua action testdata/lua/plugins/action_test_context_chain_no_auth_without_environment_test.json
run_test testdata/lua/plugins/action_test_context_chain_oidc_post_action_only_wrapper.lua action testdata/lua/plugins/action_test_context_chain_oidc_post_action_only_test.json
run_test testdata/lua/plugins/environment_blocklist_wrapper.lua environment testdata/lua/plugins/environment_blocklist_test.json
run_test testdata/lua/plugins/environment_failed_login_hotspot_wrapper.lua environment testdata/lua/plugins/environment_failed_login_hotspot_test.json
run_test testdata/lua/plugins/backend_backend_wrapper.lua backend testdata/lua/plugins/backend_backend_test.json
run_test testdata/lua/plugins/subject_test_context_chain_wrapper.lua subject testdata/lua/plugins/subject_test_context_chain_test.json
run_test testdata/lua/plugins/subject_test_context_chain_no_auth_without_environment_wrapper.lua subject testdata/lua/plugins/subject_test_context_chain_no_auth_without_environment_test.json
run_test testdata/lua/plugins/subject_geoip_reputation_preexisting_wrapper.lua subject testdata/lua/plugins/subject_geoip_reputation_preexisting_test.json
run_test testdata/lua/plugins/cache_flush_wrapper.lua cache_flush testdata/lua/plugins/cache_flush_test.json
