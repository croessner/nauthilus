// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package luatest

import (
	"path/filepath"
	"testing"
)

// redisKeyLayoutFixture names one bundled-plugin fixture that runs under testdata/lua/plugins/lib/redis_layout_probe.lua.
type redisKeyLayoutFixture struct {
	name     string
	wrapper  string
	mock     string
	callback string
}

// TestBundledLuaPluginRedisKeyLayout runs the bundled monitoring, protection, notification, and hook plugins against
// miniredis with the layout probe. The probe fails a fixture when a multi-key script would be rewritten on Redis
// Cluster, when a plugin passes the custom pool name instead of its connection, when a plugin touches a retired key,
// or when a reader misses data written under the documented key names.
func TestBundledLuaPluginRedisKeyLayout(t *testing.T) {
	t.Chdir(repositoryRootForLuaFixtures(t))

	fixtures := []redisKeyLayoutFixture{
		{"account centric monitoring", "subject_account_centric_monitoring_wrapper.lua", "subject_account_centric_monitoring_test.json", "subject"},
		{"global pattern monitoring", "environment_global_pattern_monitoring_wrapper.lua", "environment_global_pattern_monitoring_test.json", "environment"},
		{"account long-window metrics", "environment_account_longwindow_metrics_wrapper.lua", "environment_account_longwindow_metrics_test.json", "environment"},
		{"soft delay", "subject_soft_delay_wrapper.lua", "subject_soft_delay_test.json", "subject"},
		{"account protection mode", "subject_account_protection_mode_wrapper.lua", "subject_account_protection_mode_test.json", "subject"},
		{"dynamic response without username", "action_dynamic_response_wrapper.lua", "action_dynamic_response_no_username_test.json", "action"},
		{"dynamic response for attacked account", "action_dynamic_response_wrapper.lua", "action_dynamic_response_attacked_test.json", "action"},
		{"haveibeenpwnd notification", "action_haveibeenpwnd_wrapper.lua", "action_haveibeenpwnd_test.json", "action"},
		{"brute-force test hook", "hook_distributed_brute_force_test_wrapper.lua", "hook_distributed_brute_force_test_test.json", "hook"},
		{"brute-force admin hook", "hook_distributed_brute_force_admin_wrapper.lua", "hook_distributed_brute_force_admin_test.json", "hook"},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			runRedisKeyLayoutFixture(t, fixture)
		})
	}
}

// runRedisKeyLayoutFixture executes one wrapper with its JSON mock and fails on any Lua or expectation error.
func runRedisKeyLayoutFixture(t *testing.T, fixture redisKeyLayoutFixture) {
	t.Helper()

	fixtureDir := filepath.Join("testdata", "lua", "plugins")

	runner, err := NewTestRunner(filepath.Join(fixtureDir, fixture.wrapper), fixture.callback, filepath.Join(fixtureDir, fixture.mock))
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success || len(result.Errors) > 0 {
		t.Fatalf("fixture failed: errors=%v logs=%v", result.Errors, result.Logs)
	}
}

// repositoryRootForLuaFixtures returns the repository root, where wrappers resolve server/lua-plugins.d paths.
func repositoryRootForLuaFixtures(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join(filepath.Dir(luaPluginFixturePath(t, "README.md")), "..", "..", ".."))
	if err != nil {
		t.Fatalf("failed to resolve repository root: %v", err)
	}

	return root
}
