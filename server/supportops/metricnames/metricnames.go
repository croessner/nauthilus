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

// Package metricnames is the metric vocabulary the operational diagnostics read: counter families, label names, and
// label values. The instance-local runtime source reads them from the in-process registry and the Prometheus source
// queries them over HTTP, so both name each series exactly once here. The families are defined in server/stats,
// server/policy/observability, server/pluginruntime, and the ClickHouse plugin.
package metricnames

import (
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// Counter families.
const (
	LDAPErrors            = "ldap_errors_total"
	RedisTimeouts         = "redis_connection_timeouts_total"
	AuthEvents            = "plugin_auth_events_total"
	PolicyTechnical       = "policy_check_technical_errors_total"
	PluginCalls           = "plugin_calls_total"
	LuaVMReplaced         = "lua_vm_replaced_total"
	AuthApplicationErrors = "auth_application_errors_total"

	// VersionInfo is the core gauge every instance sets at startup; it proves that a scrape keeps core metrics.
	VersionInfo = "nauthilus_version_info"
)

// Label names.
const (
	LabelOp             = "op"
	LabelCode           = "code"
	LabelOutcome        = "outcome"
	LabelResult         = "result"
	LabelExtensionPoint = "extension_point"
	LabelKey            = "key"
)

// Label values and name patterns.
const (
	// OutcomeDropped is the plugin_auth_events_total outcome of a host diagnostic event that was not delivered.
	OutcomeDropped = "dropped"

	// BackendExtensionPoint is the plugin_calls_total extension point of native authentication backends.
	BackendExtensionPoint = string(pluginregistry.ComponentKindBackend)

	// LuaBackendPoolPrefix prefixes the lua_vm_replaced_total key of a Lua backend VM pool.
	LuaBackendPoolPrefix = definitions.LuaBackendPoolKeyPrefix

	// ClickHouseFlushFamilyPattern matches the plugin's scoped flush counters of every row and event stream. It is an
	// RE2 expression without anchors, so it fits both a Go regexp (anchored by the caller) and a PromQL name matcher.
	ClickHouseFlushFamilyPattern = `nauthilus_plugin_(?:[a-z0-9_]+_)?clickhouse(?:_[a-z0-9_]+)?_flush_batches_total`

	// ClickHouseQueueFamilyPattern matches the plugin's scoped enqueue counters of every row and event stream.
	ClickHouseQueueFamilyPattern = `nauthilus_plugin_(?:[a-z0-9_]+_)?clickhouse(?:_[a-z0-9_]+)?_queued_rows_total`
)

var (
	// PluginFailureResults are the plugin_calls_total results that mean a faulty plugin backend call. Canceled calls
	// are client outcomes and admission-limited calls are host capacity limits, so they do not count.
	PluginFailureResults = []string{definitions.PluginCallResultError, definitions.PluginCallResultPanic, definitions.PluginCallResultTimeout}

	// ClickHouseFlushFailures are the flush results that lose or delay rows.
	ClickHouseFlushFailures = []string{"http_error", "status_error", "no_url"}

	// ClickHouseQueueLosses are the enqueue results that never reach ClickHouse.
	ClickHouseQueueLosses = []string{"dropped", "dropped_reject_limit", "encode_error"}
)
