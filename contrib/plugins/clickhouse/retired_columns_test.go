// Copyright (C) 2026 Christian Roessner
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

package main

import (
	"testing"

	"github.com/croessner/nauthilus/v4/pluginapi/v1/exchange"
)

// retiredLegacyColumns are the logins columns without producer that the plugin no longer exports
// (DIAGNOSTIC_CONTRACT.md §3, schema.sql "Retire unused legacy columns").
var retiredLegacyColumns = []string{
	"reputation_score", "reputation_positive_score", "reputation_negative_score", "reputation_ip_score",
	"reputation_asn_score", "reputation_country_score", "reputation_asn_country_score", "reputation_samples",
	"reputation_source", "reputation_decision",
	"gp_attempts", "gp_unique_ips", "gp_unique_users", "gp_ips_per_user",
	"prot_active", "prot_reason", "prot_backoff", "prot_delay_ms",
	"dyn_threat", "dyn_response",
}

// TestRowOmitsRetiredLegacyColumns pins that the encoded row carries none of the retired keys, even when the runtime
// exchange maps that once fed them are present, while the current diagnostic fields stay.
func TestRowOmitsRetiredLegacyColumns(t *testing.T) {
	row := singleRowForRequest(t, requestOptions{runtimeValues: map[string]any{
		exchange.KeyGeoIPReputation:   map[string]any{"score": 0.375, "source": "redis", "decision": "block", "samples": 3},
		exchange.KeyGlobalPattern:     map[string]any{"attempts": 11, "unique_ips": 2, "unique_users": 3, "ips_per_user": 1.5},
		exchange.KeyAccountProtection: map[string]any{"active": true, "reason": "test", "backoff_level": 2, "delay_ms": 50},
		exchange.KeyDynamicResponse:   map[string]any{"threat_level": 4, "response": "slow"},
	}})

	for _, column := range retiredLegacyColumns {
		if _, ok := row[column]; ok {
			t.Errorf("row still exports retired column %q", column)
		}
	}

	// Decision sources are still derived from the same exchange maps (pluginapi exchange.addExchangeMapSources);
	// retiring the columns must not change them.
	assertStringField(t, row, "decision_sources", "account_protection")

	for _, column := range []string{"session", "contract_version", "event_id", "outcome", "outcome_marker",
		"decision_sources", "reputation_assessments", "reputation_truncated", "flow_ref", "geoip_country",
		"brute_force_tolerated", "transport_status"} {
		if _, ok := row[column]; !ok {
			t.Errorf("row lost current diagnostic column %q", column)
		}
	}
}
