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
	"net/netip"
	"strconv"
	"time"

	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

// lifecycleColumns are the selected bruteforce_lifecycle columns.
const lifecycleColumns = "toUnixTimestamp64Milli(ts) AS ts_ms, event_id, kind, instance, request_id, network, " +
	"ip_family, cidr, rule, rule_fingerprint, stored_rule, bucket_id, period_seconds, ban_time_seconds, " +
	"failed_requests, window_index, window_current, window_previous, total, effective_limit, " +
	"if(isNull(expires_at), NULL, toUnixTimestamp64Milli(assumeNotNull(expires_at))) AS expires_ms, release_source, " +
	"operator_client_id, operator_auth_method, keys_removed"

// countedColumns are the selected contribution columns of bruteforce_attempts.
const countedColumns = "toUnixTimestamp64Milli(ts) AS ts_ms, event_id, request_id, client_ip, window_index, " +
	"window_current, crossed, count_source, claimed_username, account, account_known, ban_active, protocol"

// maxRecordedPrefixes bounds the distinct prefixes read from evidence tables.
const maxRecordedPrefixes = 256

// Prefixes returns the distinct prefixes recorded in lifecycle rows and summary networks of the deployment; a
// complete answer is cached for the probe period.
func (s *Store) Prefixes(ctx context.Context) ([]supporthistory.Prefix, error) {
	s.mu.Lock()
	cached, fresh := s.prefixes, s.now().Sub(s.prefixesAt) < probeTTL
	s.mu.Unlock()

	if fresh && cached != nil {
		return cached, nil
	}

	prefixes, err := s.readPrefixes(ctx)
	if err == nil {
		s.mu.Lock()
		s.prefixes, s.prefixesAt = prefixes, s.now()
		s.mu.Unlock()
	}

	return prefixes, err
}

// readPrefixes reads the distinct prefixes of the lifecycle and summary tables.
func (s *Store) readPrefixes(ctx context.Context) ([]supporthistory.Prefix, error) {
	stmt := newStatement(s.deployment)

	var prefixes []supporthistory.Prefix

	err := s.client.query(ctx, "SELECT DISTINCT ip_family, cidr FROM "+s.client.table("bruteforce_lifecycle")+
		stmt.whereClause()+" LIMIT "+strconv.Itoa(maxRecordedPrefixes), stmt.params(), func(raw json.RawMessage) error {
		var row struct {
			Family optInt `json:"ip_family"`
			CIDR   optInt `json:"cidr"`
		}

		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		prefixes = append(prefixes, supporthistory.Prefix{Family: int(row.Family.int()), Bits: int(row.CIDR.int())})

		return nil
	})
	if err != nil {
		return nil, err
	}

	summary := newStatement(s.deployment)
	summaryErr := s.client.query(ctx, "SELECT DISTINCT network FROM "+s.client.table("bruteforce_attempt_summary")+
		summary.whereClause()+" LIMIT "+strconv.Itoa(maxRecordedPrefixes*16), summary.params(), func(raw json.RawMessage) error {
		var row struct {
			Network string `json:"network"`
		}

		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		if prefix, parseErr := netip.ParsePrefix(row.Network); parseErr == nil {
			family := 6
			if prefix.Addr().Is4() {
				family = 4
			}

			prefixes = append(prefixes, supporthistory.Prefix{Family: family, Bits: prefix.Bits()})
		}

		return nil
	})

	if prefixes == nil {
		prefixes = []supporthistory.Prefix{}
	}

	return prefixes, summaryErr
}

// Lifecycle returns the deduplicated, newest lifecycle rows of the networks, at most PerNetwork per network, so a
// hammered network never evicts the rows of another one and recent bans are never cut.
func (s *Store) Lifecycle(ctx context.Context, query supporthistory.LifecycleQuery) ([]supporthistory.LifecycleRecord, error) {
	if len(query.Networks) == 0 {
		return nil, nil
	}

	stmt := newStatement(s.deployment)
	stmt.where("network IN " + stmt.texts(query.Networks))
	stmt.timeRange("ts", query.From, query.Until)

	perNetwork := max(1, query.PerNetwork)
	inner := "SELECT " + lifecycleColumns + " FROM " + s.client.table("bruteforce_lifecycle") + stmt.whereClause() +
		" ORDER BY ts DESC, event_id DESC LIMIT 1 BY event_id"
	sql := "SELECT * FROM (" + inner + ") ORDER BY network, ts_ms DESC, event_id DESC LIMIT " + strconv.Itoa(perNetwork) +
		" BY network LIMIT " + strconv.Itoa(perNetwork*len(query.Networks))

	var records []supporthistory.LifecycleRecord

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row lifecycleRow
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		records = append(records, row.record())

		return nil
	})

	return records, err
}

// Contributions returns the counted rows of one activation with the contract §13.4 reference predicate.
func (s *Store) Contributions(ctx context.Context, query supporthistory.ContributionQuery) ([]supporthistory.CountedRecord, error) {
	stmt := newStatement(s.deployment)
	stmt.where("network = " + stmt.text(query.Network))
	stmt.where("bucket_id = " + stmt.text(query.BucketID))
	stmt.where("kind = 'counted'")
	stmt.timeRange("ts", query.From, query.Until)

	index := stmt.integer(query.WindowIndex)
	stmt.where("((window_index = " + index + " AND window_current <= " + stmt.integer(query.Current) + ") OR " +
		"(window_index = " + index + " - 1 AND window_current <= " + stmt.integer(query.Previous) + "))")

	if query.ResetAfter != nil {
		stmt.where("ts > " + stmt.instant(*query.ResetAfter))
	}

	if query.ResetBefore != nil {
		stmt.where("ts < " + stmt.instant(*query.ResetBefore))
	}

	if start := query.Start; start != nil {
		stmt.where(lexicographicFrom([]string{"window_index", "window_current", tsColumn, eventIDColumn},
			[]string{stmt.integer(start.WindowIndex), stmt.integer(start.WindowCurrent), stmt.instant(start.At),
				stmt.text(start.EventID)}))
	}

	sql := "SELECT " + countedColumns + " FROM " + s.client.table("bruteforce_attempts") + stmt.whereClause() +
		" ORDER BY window_index, window_current, ts, event_id, " + rowTieBreak + " LIMIT 1 BY event_id LIMIT " +
		strconv.Itoa(max(1, query.Limit))

	var records []supporthistory.CountedRecord

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row countedRow
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		records = append(records, row.record())

		return nil
	})

	return records, err
}

// hitColumns are the selected ban_hit columns of bruteforce_attempts; claimed names and addresses are not needed to
// link a request to the ban that rejected it.
const hitColumns = "toUnixTimestamp64Milli(ts) AS ts_ms, event_id, request_id, network, rule, bucket_id, hit_source"

// RequestHits returns the ban_hit rows of known requests: network IN keeps the read on the primary key and the
// request_id bloom index prunes granules; replays are removed with LIMIT 1 BY event_id.
func (s *Store) RequestHits(ctx context.Context, query supporthistory.RequestHitQuery) ([]supporthistory.HitRecord, error) {
	if len(query.Networks) == 0 || len(query.RequestIDs) == 0 {
		return nil, nil
	}

	stmt := newStatement(s.deployment)
	stmt.where("network IN " + stmt.texts(query.Networks))
	stmt.where("kind = 'ban_hit'")
	stmt.where("request_id IN " + stmt.texts(query.RequestIDs))
	stmt.timeRange("ts", query.From, query.Until)

	sql := "SELECT " + hitColumns + " FROM " + s.client.table("bruteforce_attempts") + stmt.whereClause() +
		" ORDER BY ts, event_id LIMIT 1 BY event_id LIMIT " + strconv.Itoa(max(1, query.Limit))

	var records []supporthistory.HitRecord

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row struct {
			TS        optInt `json:"ts_ms"`
			EventID   string `json:"event_id"`
			RequestID string `json:"request_id"`
			Network   string `json:"network"`
			Rule      string `json:"rule"`
			BucketID  string `json:"bucket_id"`
			HitSource string `json:"hit_source"`
		}

		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		records = append(records, supporthistory.HitRecord{At: millis(row.TS), EventID: row.EventID,
			RequestID: row.RequestID, Network: row.Network, Rule: row.Rule, BucketID: row.BucketID,
			HitSource: row.HitSource})

		return nil
	})

	return records, err
}

// WindowSummaries folds the hourly aggregates of bucket windows.
func (s *Store) WindowSummaries(ctx context.Context, query supporthistory.SummaryQuery) ([]supporthistory.WindowSummary, error) {
	stmt := newStatement(s.deployment)
	stmt.where("network = " + stmt.text(query.Network))
	stmt.where("bucket_id = " + stmt.text(query.BucketID))
	stmt.where("kind = " + stmt.text(query.Kind))
	stmt.where("window_index IN " + stmt.integers(query.WindowIndexes))

	sql := "SELECT window_index, sum(events) AS events, min(min_current) AS min_current, max(max_current) AS max_current, " +
		"uniqMerge(claimed_names) AS names FROM " + s.client.table("bruteforce_attempt_summary") + stmt.whereClause() +
		" GROUP BY window_index ORDER BY window_index"

	var summaries []supporthistory.WindowSummary

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row struct {
			WindowIndex optInt `json:"window_index"`
			Events      optInt `json:"events"`
			MinCurrent  optInt `json:"min_current"`
			MaxCurrent  optInt `json:"max_current"`
			Names       optInt `json:"names"`
		}

		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		summaries = append(summaries, supporthistory.WindowSummary{WindowIndex: row.WindowIndex.int(),
			Events: row.Events.int(), MinCurrent: row.MinCurrent.value, MaxCurrent: row.MaxCurrent.value,
			ClaimedNames: row.Names.int()})

		return nil
	})

	return summaries, err
}

// lifecycleRow is the JSON shape of one lifecycle row.
type lifecycleRow struct {
	TS                 optInt   `json:"ts_ms"`
	Expires            optInt   `json:"expires_ms"`
	WindowIndex        optInt   `json:"window_index"`
	WindowCurrent      optInt   `json:"window_current"`
	WindowPrevious     optInt   `json:"window_previous"`
	Total              optFloat `json:"total"`
	EffectiveLimit     optFloat `json:"effective_limit"`
	KeysRemoved        optInt   `json:"keys_removed"`
	PeriodSeconds      optInt   `json:"period_seconds"`
	BanTimeSeconds     optInt   `json:"ban_time_seconds"`
	FailedRequests     optInt   `json:"failed_requests"`
	EventID            string   `json:"event_id"`
	Kind               string   `json:"kind"`
	Instance           string   `json:"instance"`
	RequestID          string   `json:"request_id"`
	Network            string   `json:"network"`
	Rule               string   `json:"rule"`
	RuleFingerprint    string   `json:"rule_fingerprint"`
	StoredRule         string   `json:"stored_rule"`
	BucketID           string   `json:"bucket_id"`
	ReleaseSource      string   `json:"release_source"`
	OperatorClientID   string   `json:"operator_client_id"`
	OperatorAuthMethod string   `json:"operator_auth_method"`
}

// record converts the decoded row.
func (r lifecycleRow) record() supporthistory.LifecycleRecord {
	return supporthistory.LifecycleRecord{At: millis(r.TS), ExpiresAt: optMillis(r.Expires),
		WindowIndex: r.WindowIndex.value, WindowCurrent: r.WindowCurrent.value, WindowPrevious: r.WindowPrevious.value,
		Total: r.Total.value, EffectiveLimit: r.EffectiveLimit.value, KeysRemoved: r.KeysRemoved.value,
		EventID: r.EventID, Kind: r.Kind, Instance: r.Instance, RequestID: r.RequestID, Network: r.Network,
		Rule: r.Rule, RuleFingerprint: r.RuleFingerprint, StoredRule: r.StoredRule, BucketID: r.BucketID,
		ReleaseSource: r.ReleaseSource, OperatorClientID: r.OperatorClientID, OperatorAuthMethod: r.OperatorAuthMethod,
		PeriodSeconds: r.PeriodSeconds.int(), BanTimeSeconds: r.BanTimeSeconds.int(), FailedRequests: r.FailedRequests.int()}
}

// countedRow is the JSON shape of one contribution row.
type countedRow struct {
	TS              optInt  `json:"ts_ms"`
	WindowIndex     optInt  `json:"window_index"`
	WindowCurrent   optInt  `json:"window_current"`
	Crossed         optBool `json:"crossed"`
	AccountKnown    optBool `json:"account_known"`
	BanActive       optBool `json:"ban_active"`
	EventID         string  `json:"event_id"`
	RequestID       string  `json:"request_id"`
	ClientIP        string  `json:"client_ip"`
	CountSource     string  `json:"count_source"`
	ClaimedUsername string  `json:"claimed_username"`
	Account         string  `json:"account"`
	Protocol        string  `json:"protocol"`
}

// record converts the decoded row.
func (r countedRow) record() supporthistory.CountedRecord {
	return supporthistory.CountedRecord{At: millis(r.TS), WindowIndex: r.WindowIndex.value,
		WindowCurrent: r.WindowCurrent.value, Crossed: r.Crossed.value, AccountKnown: r.AccountKnown.value,
		BanActive: r.BanActive.value, EventID: r.EventID, RequestID: r.RequestID, ClientIP: r.ClientIP, CountSource: r.CountSource,
		ClaimedUsername: r.ClaimedUsername, Account: r.Account, Protocol: r.Protocol}
}

// kindFilters renders the shared filters of a kind aggregation, including excluded instance intervals.
func kindFilters(stmt *statement, query supporthistory.KindQuery) {
	stmt.where("network IN " + stmt.texts(query.Networks))
	stmt.where("kind = " + stmt.text(query.Kind))

	if len(query.Exclude) == 0 {
		return
	}

	networks := make([]string, 0, len(query.Exclude))
	froms := make([]time.Time, 0, len(query.Exclude))
	untils := make([]time.Time, 0, len(query.Exclude))

	for _, interval := range query.Exclude {
		networks, froms, untils = append(networks, interval.Network), append(froms, interval.From), append(untils, interval.Until)
	}

	stmt.where("NOT arrayExists((n, f, u) -> network = n AND ts >= f AND ts < u, " + stmt.texts(networks) + ", " +
		stmt.instants(froms) + ", " + stmt.instants(untils) + ")")
}
