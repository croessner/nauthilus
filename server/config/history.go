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
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/secret"
)

const (
	// HistoryBudgetModeQuerySettings sends every read budget with each query; the reader user needs readonly=2.
	HistoryBudgetModeQuerySettings = "query_settings"

	// HistoryBudgetModeProfile relies on the reader user's settings profile (readonly=1) and verifies it.
	HistoryBudgetModeProfile = "profile"

	defaultHistoryDatabase         = "nauthilus"
	defaultHistoryTimeout          = 15 * time.Second
	defaultHistoryMaxExecutionTime = 8 * time.Second
	defaultHistoryMaxRowsToRead    = uint64(5_000_000)
	defaultHistoryMaxBytesToRead   = uint64(2 << 30)
	defaultHistoryMaxResponseBytes = int64(8 << 20)
)

// historyIdentifierPattern restricts the database name to a plain ClickHouse identifier.
var historyIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// HistorySection configures read-only access to recorded authentication history.
type HistorySection struct {
	ClickHouse HistoryClickHouseSection `mapstructure:"clickhouse" validate:"omitempty"`
}

// HistoryClickHouseSection configures the bounded ClickHouse reader of the support history service.
type HistoryClickHouseSection struct {
	Password         secret.Value  `mapstructure:"password" validate:"omitempty"`
	URL              string        `mapstructure:"url" validate:"omitempty,url"`
	Database         string        `mapstructure:"database" validate:"omitempty,printascii"`
	Username         string        `mapstructure:"username" validate:"omitempty,printascii,excludesall= "`
	Deployment       string        `mapstructure:"deployment" validate:"omitempty,printascii"`
	BudgetMode       string        `mapstructure:"budget_mode" validate:"omitempty,oneof=query_settings profile"`
	Timeout          time.Duration `mapstructure:"timeout" validate:"omitempty,gt=0,max=1m"`
	MaxExecutionTime time.Duration `mapstructure:"max_execution_time" validate:"omitempty,gt=0,max=1m"`
	MaxRowsToRead    uint64        `mapstructure:"max_rows_to_read" validate:"omitempty,gt=0"`
	MaxBytesToRead   uint64        `mapstructure:"max_bytes_to_read" validate:"omitempty,gt=0"`
	MaxResponseBytes int64         `mapstructure:"max_response_bytes" validate:"omitempty,gt=0,max=67108864"`
}

// GetHistory returns the support history configuration; the empty section disables the capability.
func (f *FileSettings) GetHistory() *HistorySection {
	if f == nil || f.Storage == nil {
		return &HistorySection{}
	}

	return &f.Storage.History
}

// GetClickHouse returns the ClickHouse reader settings.
func (s *HistorySection) GetClickHouse() *HistoryClickHouseSection {
	if s == nil {
		return &HistoryClickHouseSection{}
	}

	return &s.ClickHouse
}

// IsEnabled reports whether a ClickHouse history source is configured.
func (s *HistoryClickHouseSection) IsEnabled() bool {
	return s != nil && strings.TrimSpace(s.URL) != ""
}

// GetURL returns the ClickHouse HTTP endpoint.
func (s *HistoryClickHouseSection) GetURL() string {
	if s == nil {
		return ""
	}

	return strings.TrimSpace(s.URL)
}

// GetDatabase returns the database that holds the diagnostic tables.
func (s *HistoryClickHouseSection) GetDatabase() string {
	if s == nil || strings.TrimSpace(s.Database) == "" {
		return defaultHistoryDatabase
	}

	return strings.TrimSpace(s.Database)
}

// GetUsername returns the dedicated read-only ClickHouse user.
func (s *HistoryClickHouseSection) GetUsername() string {
	if s == nil {
		return ""
	}

	return strings.TrimSpace(s.Username)
}

// GetPassword returns the reader password.
func (s *HistoryClickHouseSection) GetPassword() secret.Value {
	if s == nil {
		return secret.Value{}
	}

	return s.Password
}

// GetDeployment returns the writer deployment label this instance may read.
func (s *HistoryClickHouseSection) GetDeployment() string {
	if s == nil {
		return ""
	}

	return strings.TrimSpace(s.Deployment)
}

// GetBudgetMode returns how read budgets are enforced.
func (s *HistoryClickHouseSection) GetBudgetMode() string {
	if s == nil || s.BudgetMode == "" {
		return HistoryBudgetModeQuerySettings
	}

	return s.BudgetMode
}

// GetTimeout returns the time budget of one history operation.
func (s *HistoryClickHouseSection) GetTimeout() time.Duration {
	if s == nil || s.Timeout <= 0 {
		return defaultHistoryTimeout
	}

	return s.Timeout
}

// GetMaxExecutionTime returns the per-query ClickHouse execution limit.
func (s *HistoryClickHouseSection) GetMaxExecutionTime() time.Duration {
	if s == nil || s.MaxExecutionTime <= 0 {
		return defaultHistoryMaxExecutionTime
	}

	return s.MaxExecutionTime
}

// GetMaxRowsToRead returns the per-query row read budget.
func (s *HistoryClickHouseSection) GetMaxRowsToRead() uint64 {
	if s == nil || s.MaxRowsToRead == 0 {
		return defaultHistoryMaxRowsToRead
	}

	return s.MaxRowsToRead
}

// GetMaxBytesToRead returns the per-query byte read budget.
func (s *HistoryClickHouseSection) GetMaxBytesToRead() uint64 {
	if s == nil || s.MaxBytesToRead == 0 {
		return defaultHistoryMaxBytesToRead
	}

	return s.MaxBytesToRead
}

// GetMaxResponseBytes returns the client-side cap of one query response body.
func (s *HistoryClickHouseSection) GetMaxResponseBytes() int64 {
	if s == nil || s.MaxResponseBytes <= 0 {
		return defaultHistoryMaxResponseBytes
	}

	return s.MaxResponseBytes
}

// validateHistory requires the identity and data boundary of an enabled history reader.
func (f *FileSettings) validateHistory() error {
	clickHouse := f.GetHistory().GetClickHouse()
	if !clickHouse.IsEnabled() {
		return nil
	}

	var missing []string

	if clickHouse.GetUsername() == "" {
		missing = append(missing, "storage.history.clickhouse.username")
	}

	if clickHouse.GetDeployment() == "" {
		missing = append(missing, "storage.history.clickhouse.deployment")
	}

	if len(missing) > 0 {
		return fmt.Errorf("%s are required when storage.history.clickhouse.url is set", strings.Join(missing, " and "))
	}

	if !historyIdentifierPattern.MatchString(clickHouse.GetDatabase()) {
		return fmt.Errorf("storage.history.clickhouse.database must be a plain identifier")
	}

	if clickHouse.GetMaxExecutionTime() >= clickHouse.GetTimeout() {
		return fmt.Errorf("storage.history.clickhouse.max_execution_time must be shorter than storage.history.clickhouse.timeout")
	}

	return nil
}
