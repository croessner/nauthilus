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
run_test testdata/lua/plugins/action_bruteforce_header_wrapper.lua action testdata/lua/plugins/action_bruteforce_header_test.json
run_test testdata/lua/plugins/action_failed_login_tracker_wrapper.lua action testdata/lua/plugins/action_failed_login_tracker_test.json
run_test testdata/lua/plugins/action_test_context_chain_feature_reject_wrapper.lua action testdata/lua/plugins/action_test_context_chain_feature_reject_test.json
run_test testdata/lua/plugins/feature_blocklist_wrapper.lua feature testdata/lua/plugins/feature_blocklist_test.json
run_test testdata/lua/plugins/backend_backend_wrapper.lua backend testdata/lua/plugins/backend_backend_test.json
run_test testdata/lua/plugins/filter_test_context_chain_wrapper.lua filter testdata/lua/plugins/filter_test_context_chain_test.json
run_test testdata/lua/plugins/cache_flush_wrapper.lua cache_flush testdata/lua/plugins/cache_flush_test.json
