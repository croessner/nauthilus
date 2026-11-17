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
	"strconv"

	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

// KindCounts aggregates one volume kind from deduplicated raw rows or, with Summary, from the hourly aggregate.
func (s *Store) KindCounts(ctx context.Context, query supporthistory.KindQuery) (supporthistory.KindAggregate, error) {
	aggregate := supporthistory.KindAggregate{BySource: map[string]int64{}}
	if len(query.Networks) == 0 {
		return aggregate, nil
	}

	if query.Summary {
		return s.summaryCounts(ctx, query)
	}

	stmt := newStatement(s.deployment)
	kindFilters(stmt, query)
	stmt.timeRange("ts", query.From, query.Until)

	subject := "toUInt64(0)"
	if query.Subject != nil {
		subject = "countIf(" + subjectHitCondition(stmt, *query.Subject) + ")"
	}

	inner := "SELECT hit_source, claimed_username, account FROM " + s.client.table("bruteforce_attempts") +
		stmt.whereClause() + " LIMIT 1 BY event_id"
	sql := "SELECT count() AS total, uniqExactIf(claimed_username, claimed_username != '') AS names, " + subject +
		" AS subject_hits, sumMap([hit_source], [toUInt64(1)]) AS by_source FROM (" + inner + ")"

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row struct {
			Total    optInt             `json:"total"`
			Names    optInt             `json:"names"`
			Subject  optInt             `json:"subject_hits"`
			BySource [2]json.RawMessage `json:"by_source"`
		}

		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		aggregate.Total, aggregate.DistinctNames = row.Total.int(), row.Names.value
		if query.Subject != nil {
			aggregate.SubjectHits = row.Subject.value
		}

		return decodeSourceMap(row.BySource, aggregate.BySource)
	})
	if err != nil || query.Claimants <= 0 {
		return aggregate, err
	}

	aggregate.Claimants, err = s.claimants(ctx, inner, stmt, query.Claimants)

	return aggregate, err
}

// subjectHitCondition renders the subject predicate of volume rows (claimed name or known account).
func subjectHitCondition(stmt *statement, match supporthistory.SubjectMatch) string {
	var logins, accounts string

	if len(match.Logins) > 0 {
		logins = "claimed_username IN " + stmt.texts(match.Logins)
	}

	if len(match.Accounts) > 0 {
		accounts = "(account != '' AND account IN " + stmt.texts(match.Accounts) + ")"
	}

	return anyOf(logins, accounts)
}

// decodeSourceMap decodes the sumMap tuple ([keys], [values]).
func decodeSourceMap(raw [2]json.RawMessage, target map[string]int64) error {
	if raw[0] == nil || raw[1] == nil {
		return nil
	}

	var (
		keys   []string
		values []optInt
	)

	if err := json.Unmarshal(raw[0], &keys); err != nil {
		return err
	}

	if err := json.Unmarshal(raw[1], &values); err != nil {
		return err
	}

	for index := range keys {
		if index < len(values) {
			target[keys[index]] = values[index].int()
		}
	}

	return nil
}

// claimants returns the most frequent claimed names behind the networks (detail projection only).
func (s *Store) claimants(ctx context.Context, inner string, stmt *statement, limit int) ([]supporthistory.ClaimantRecord, error) {
	sql := "SELECT claimed_username, account, count() AS hits FROM (" + inner + ") GROUP BY claimed_username, account " +
		"ORDER BY hits DESC, claimed_username, account LIMIT " + strconv.Itoa(limit)

	var claimants []supporthistory.ClaimantRecord

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row struct {
			ClaimedUsername string `json:"claimed_username"`
			Account         string `json:"account"`
			Hits            optInt `json:"hits"`
		}

		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		claimants = append(claimants, supporthistory.ClaimantRecord{ClaimedUsername: row.ClaimedUsername,
			Account: row.Account, Hits: row.Hits.int()})

		return nil
	})

	return claimants, err
}

// summaryCounts aggregates a kind from the hourly summary; counts are upper bounds and the interval is hour-aligned.
func (s *Store) summaryCounts(ctx context.Context, query supporthistory.KindQuery) (supporthistory.KindAggregate, error) {
	aggregate := supporthistory.KindAggregate{BySource: map[string]int64{}}
	stmt := newStatement(s.deployment)
	stmt.where("network IN " + stmt.texts(query.Networks))
	stmt.where("kind = " + stmt.text(query.Kind))
	stmt.where("hour >= toStartOfHour(" + stmt.instant(query.From) + ")")
	stmt.where("hour < " + stmt.instant(query.Until))

	sql := "SELECT sum(events) AS total, uniqMerge(claimed_names) AS names FROM " +
		s.client.table("bruteforce_attempt_summary") + stmt.whereClause()

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row struct {
			Total optInt `json:"total"`
			Names optInt `json:"names"`
		}

		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		aggregate.Total, aggregate.DistinctNames = row.Total.int(), row.Names.value

		return nil
	})

	return aggregate, err
}
