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

package clickhousestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

// probeTTL bounds how long self-check, presence, and cutover probes are reused.
const probeTTL = 5 * time.Minute

// Store implements the attempt and ban stores over one bounded reader.
type Store struct {
	prefixesAt time.Time
	client     *client
	now        func() time.Time
	probes     map[string]cachedProbe
	prefixes   []supporthistory.Prefix
	deployment string
	mu         sync.Mutex
}

// cachedProbe is one cached probe answer.
type cachedProbe struct {
	at       time.Time
	since    *time.Time
	presence supporthistory.SourcePresence
	known    bool
}

var (
	_ supporthistory.AttemptStore = (*Store)(nil)
	_ supporthistory.BanStore     = (*Store)(nil)
)

// New creates a reader bound to one deployment.
func New(config Config) (*Store, error) {
	if strings.TrimSpace(config.Deployment) == "" {
		return nil, errors.New("support history reader requires a deployment")
	}

	reader, err := newClient(config)
	if err != nil {
		return nil, err
	}

	return &Store{client: reader, deployment: strings.TrimSpace(config.Deployment), now: time.Now,
		probes: map[string]cachedProbe{}}, nil
}

// Deployment returns the writer deployment every query is bound to.
func (s *Store) Deployment() string {
	return s.deployment
}

// cached returns a fresh cached probe.
func (s *Store) cached(key string) (cachedProbe, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	probe, ok := s.probes[key]

	return probe, ok && s.now().Sub(probe.at) < probeTTL
}

// remember stores a probe answer.
func (s *Store) remember(key string, probe cachedProbe) {
	s.mu.Lock()
	defer s.mu.Unlock()

	probe.at = s.now()
	s.probes[key] = probe
}

// effectiveSettings is the session view the reader verifies before it reads anything.
type effectiveSettings struct {
	Readonly        optInt   `json:"readonly"`
	MaxRows         optInt   `json:"max_rows"`
	MaxBytes        optInt   `json:"max_bytes"`
	MaxTime         optFloat `json:"max_time"`
	ReadOverflow    string   `json:"read_overflow"`
	ResultOverflow  string   `json:"result_overflow"`
	TimeoutOverflow string   `json:"timeout_overflow"`
}

// SelfCheck verifies that the reader is read-only, throws on every overflow, and enforces the read budget.
func (s *Store) SelfCheck(ctx context.Context) error {
	if probe, ok := s.cached("selfcheck"); ok && probe.known {
		return nil
	}

	var settings effectiveSettings

	rows := 0

	err := s.client.query(ctx, "SELECT getSetting('readonly') AS readonly, getSetting('max_rows_to_read') AS max_rows, "+
		"getSetting('max_bytes_to_read') AS max_bytes, toFloat64(getSetting('max_execution_time')) AS max_time, "+
		"toString(getSetting('read_overflow_mode')) AS read_overflow, "+
		"toString(getSetting('result_overflow_mode')) AS result_overflow, "+
		"toString(getSetting('timeout_overflow_mode')) AS timeout_overflow", nil, func(raw json.RawMessage) error {
		rows++

		return json.Unmarshal(raw, &settings)
	})
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("%w: settings probe", supporthistory.ErrSourceUnavailable)
	}

	if err = s.client.verify(settings); err != nil {
		return err
	}

	s.remember("selfcheck", cachedProbe{known: true})

	return nil
}

// verify checks the effective session settings against the mode and the configured budget.
func (c *client) verify(settings effectiveSettings) error {
	if settings.Readonly.int() < 1 {
		return fmt.Errorf("%w: reader account is writable", supporthistory.ErrReaderUnsafe)
	}

	if settings.ReadOverflow != overflowThrow || settings.ResultOverflow != overflowThrow ||
		settings.TimeoutOverflow != overflowThrow {
		return fmt.Errorf("%w: overflow modes must throw", supporthistory.ErrReaderUnsafe)
	}

	if c.mode == BudgetQuerySettings || c.profileEnforcesBudget(settings) {
		return nil
	}

	return fmt.Errorf("%w: profile does not enforce the configured budget", supporthistory.ErrReaderUnsafe)
}

// profileEnforcesBudget reports whether every effective profile budget is set and within the configured budget.
func (c *client) profileEnforcesBudget(settings effectiveSettings) bool {
	maxTime := 0.0
	if settings.MaxTime.value != nil {
		maxTime = *settings.MaxTime.value
	}

	return settings.MaxRows.int() > 0 && uint64(settings.MaxRows.int()) <= c.budget.MaxRowsToRead &&
		settings.MaxBytes.int() > 0 && uint64(settings.MaxBytes.int()) <= c.budget.MaxBytesToRead &&
		maxTime > 0 && maxTime <= c.budget.MaxExecutionTime.Seconds()
}

// presenceStatements are the cheap existence probes per source within its retention.
var presenceStatements = map[supporthistory.Source]struct {
	table  string
	filter string
}{
	supporthistory.SourceLogins:       {"logins", "ts >= now64(3) - INTERVAL 7 DAY"},
	supporthistory.SourceAuthEvents:   {"auth_events", "event_type = 'mfa.verification' AND ts >= now64(3) - INTERVAL 7 DAY"},
	supporthistory.SourceBanLifecycle: {"bruteforce_lifecycle", "1"},
	supporthistory.SourceBanAttempts:  {"bruteforce_attempts", "1"},
	supporthistory.SourceBanSummary:   {"bruteforce_attempt_summary", "1"},
}

// Presence reports whether a source holds rows of the deployment within its retention.
func (s *Store) Presence(ctx context.Context, source supporthistory.Source) supporthistory.SourcePresence {
	probe, ok := presenceStatements[source]
	if !ok {
		return supporthistory.PresenceUnknown
	}

	if cached, fresh := s.cached("presence:" + string(source)); fresh {
		return cached.presence
	}

	stmt := newStatement(s.deployment)
	stmt.where(probe.filter)

	rows := 0
	err := s.client.query(ctx, "SELECT 1 AS present FROM "+s.client.table(probe.table)+stmt.whereClause()+" LIMIT 1",
		stmt.params(), func(json.RawMessage) error {
			rows++

			return nil
		})

	presence := supporthistory.PresenceRows

	switch {
	case errors.Is(err, supporthistory.ErrSourceNotInstalled):
		presence = supporthistory.PresenceNotInstalled
	case err != nil:
		return supporthistory.PresenceUnknown
	case rows == 0:
		presence = supporthistory.PresenceNoRows
	}

	s.remember("presence:"+string(source), cachedProbe{presence: presence})

	return presence
}

// ContractRowsSince returns the first contract row in [from, until) of the deployment; the ordered probe stops at
// the first match, and a failed or over-budget probe reports known=false.
func (s *Store) ContractRowsSince(ctx context.Context, from, until time.Time) (*time.Time, bool) {
	key := "cutover:" + from.Truncate(time.Hour).Format(time.RFC3339) + ":" + until.Truncate(time.Hour).Format(time.RFC3339)
	if cached, fresh := s.cached(key); fresh {
		return cached.since, cached.known
	}

	stmt := newStatement(s.deployment)
	stmt.timeRange("ts", from, until)
	stmt.where("contract_version >= 1")

	var since *time.Time

	err := s.client.query(ctx, "SELECT toUnixTimestamp64Milli(ts) AS ts_ms FROM "+s.client.table("logins")+
		stmt.whereClause()+" ORDER BY ts LIMIT 1", stmt.params(), func(raw json.RawMessage) error {
		var row struct {
			TS optInt `json:"ts_ms"`
		}

		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		since = optMillis(row.TS)

		return nil
	})
	if err != nil {
		return nil, false
	}

	s.remember(key, cachedProbe{since: since, known: true})

	return since, true
}
