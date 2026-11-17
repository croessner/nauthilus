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

package config

import (
	"strings"
	"testing"
	"time"
)

// TestHistoryConfigurationDefaultsAndValidation pins defaults and the required reader boundary.
func TestHistoryConfigurationDefaultsAndValidation(t *testing.T) {
	disabled := &FileSettings{}
	if disabled.GetHistory().GetClickHouse().IsEnabled() || disabled.validateHistory() != nil {
		t.Fatal("an absent history section must stay disabled and valid")
	}

	section := &HistoryClickHouseSection{URL: "http://clickhouse:8123/"}
	if section.GetDatabase() != "nauthilus" || section.GetBudgetMode() != HistoryBudgetModeQuerySettings ||
		section.GetMaxExecutionTime() >= section.GetTimeout() || section.GetMaxRowsToRead() == 0 {
		t.Fatalf("defaults = %+v", section)
	}

	for name, tc := range map[string]struct {
		section HistoryClickHouseSection
		want    string
	}{
		"missing user and deployment": {HistoryClickHouseSection{URL: "http://ch:8123/"}, "username and storage.history.clickhouse.deployment"},
		"bad database":                {HistoryClickHouseSection{URL: "http://ch:8123/", Username: "r", Deployment: "d", Database: "x.y"}, "plain identifier"},
		"execution above timeout": {HistoryClickHouseSection{URL: "http://ch:8123/", Username: "r", Deployment: "d",
			Timeout: 5 * time.Second, MaxExecutionTime: 6 * time.Second}, "shorter than"},
	} {
		t.Run(name, func(t *testing.T) {
			settings := &FileSettings{Storage: &StorageSection{History: HistorySection{ClickHouse: tc.section}}}
			if err := settings.validateHistory(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateHistory() = %v, want %q", err, tc.want)
			}
		})
	}

	valid := &FileSettings{Storage: &StorageSection{History: HistorySection{ClickHouse: HistoryClickHouseSection{
		URL: "http://ch:8123/", Username: "reader", Deployment: "prod"}}}}
	if err := valid.validateHistory(); err != nil {
		t.Fatalf("validateHistory() = %v", err)
	}
}
