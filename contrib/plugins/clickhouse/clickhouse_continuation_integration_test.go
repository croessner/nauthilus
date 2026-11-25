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

//go:build clickhouse_integration

package main

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/clickhousestore"
)

// TestClickHouseHistoryContinuesEveryInnerList pages the latched flow's events across both sources and the shared-IP
// ban's contributions and claimants one item at a time through the provisioned reader, so the keyset and offset
// reads of the store reach every stored item exactly once.
func TestClickHouseHistoryContinuesEveryInnerList(t *testing.T) {
	env := startHistoryEnv(t)

	for _, claimant := range []string{"0", "1"} {
		env.db.exec(env.db.scoped("INSERT INTO nauthilus.bruteforce_attempts SELECT * REPLACE (concat(event_id, '-" +
			claimant + "') AS event_id, 'claimant" + claimant + "@example.test' AS claimed_username) " +
			"FROM nauthilus.bruteforce_attempts WHERE kind = 'ban_hit' AND position(event_id, '-') = 0"))
	}

	service := historyService(t, env, provisionReader(t, env.db, "2", clickhousestore.BudgetQuerySettings))
	caller := historyCaller(definitions.ScopeHistoryRead)
	latched := searchAll(t, env, service, caller)["fl1."+historyFlowLatched]

	detail := supporthistory.AttemptDetailRequest{SchemaVersion: "1", AttemptID: latched.AttemptID,
		Around: latched.StartedAt, EventsPage: &supporthistory.PageRequest{Limit: 1}}
	events := map[string]struct{}{}

	for pages := 0; ; pages++ {
		result, err := service.GetAttempt(t.Context(), caller, detail)
		if err != nil || result.Attempt == nil || len(result.Attempt.Events) != 1 || pages > len(latched.Events) {
			t.Fatalf("GetAttempt(page %d) = %+v, %v, want one event per page", pages, result, err)
		}

		event := result.Attempt.Events[0]
		if _, repeated := events[*event.EventID]; repeated || event.Sequence != pages+1 {
			t.Fatalf("page %d event %s sequence %d repeats or skips", pages, *event.EventID, event.Sequence)
		}

		events[*event.EventID] = struct{}{}

		if result.Attempt.EventsPage.NextCursor == nil {
			break
		}

		detail.EventsPage.Cursor = *result.Attempt.EventsPage.NextCursor
	}

	if len(events) != len(latched.Events) {
		t.Fatalf("paged events = %d, want every event of the attempt %d", len(events), len(latched.Events))
	}

	assertInnerList(t, service, env, supporthistory.InnerListContributions, 3, func(ban supporthistory.Ban) (int, *string) {
		return len(ban.Contributions.Items), ban.Contributions.NextCursor
	})
	assertInnerList(t, service, env, supporthistory.InnerListClaimants, 3, func(ban supporthistory.Ban) (int, *string) {
		return len(ban.Hits.Claimants), ban.Hits.ClaimantsNextCursor
	})
}

// assertInnerList pages one inner list of the shared-IP ban one item at a time and checks the item count.
func assertInnerList(t *testing.T, service *supporthistory.Service, env historyEnv, list string, want int,
	read func(supporthistory.Ban) (int, *string)) {
	t.Helper()

	request := supporthistory.BanSearchRequest{SchemaVersion: "1", Target: supporthistory.BanTarget{IP: "198.51.100.17"},
		Filter: supporthistory.BanSearchFilter{From: env.now.Add(-3 * time.Hour), Until: env.now}}

	first, err := service.SearchBans(t.Context(), historyCaller(definitions.ScopeHistoryRead), request)
	if err != nil || len(first.Bans) != 1 {
		t.Fatalf("SearchBans() = %+v, %v, want the shared-IP ban", first, err)
	}

	request.InnerPage = &supporthistory.BanInnerPageRequest{BanRef: first.Bans[0].BanRef, List: list, Limit: 1}
	listed := 0

	for pages := 0; pages <= want; pages++ {
		result, pageErr := service.SearchBans(t.Context(), historyCaller(definitions.ScopeHistoryRead), request)
		if pageErr != nil || len(result.Bans) != 1 {
			t.Fatalf("SearchBans(%s page %d) = %+v, %v", list, pages, result, pageErr)
		}

		count, next := read(result.Bans[0])
		listed += count

		if next == nil {
			if listed != want {
				t.Fatalf("%s listed %d items, want %d", list, listed, want)
			}

			return
		}

		request.InnerPage.Cursor = *next
	}

	t.Fatalf("%s paging did not terminate", list)
}
