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

package supporthistory_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

// removedProjectionMembers are JSON members that only existed for the removed redacting projection.
var removedProjectionMembers = []string{`"redacted"`, `"identities_redacted"`, `"events_withheld"`, `"withheld"`}

// historyScopes are the scopes that release the full diagnostic data.
var historyScopes = []string{definitions.ScopeHistoryRead, definitions.ScopeHistoryDetail}

// assertNoRedactionMembers fails when the JSON form of a value still carries a redaction member.
func assertNoRedactionMembers(t *testing.T, name string, value any) {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	for _, member := range removedProjectionMembers {
		if strings.Contains(string(encoded), member) {
			t.Fatalf("%s carries %s: %s", name, member, encoded)
		}
	}
}

// TestEveryHistoryScopeSeesTheFullAttempts pins that both history scopes see other identities in a flow and the
// complete latched second-factor evidence.
func TestEveryHistoryScopeSeesTheFullAttempts(t *testing.T) {
	for _, scope := range historyScopes {
		t.Run(scope, func(t *testing.T) {
			attempts, _ := attemptsByID(t, newService(t, fixtureStore(t)), caller(scope))

			other := attempts["fl1."+strings.Repeat("1", 32)].Events[1].Identity
			if stringValue(other.SuppliedLogin) != "mallory@example.test" || other.SubjectMatch {
				t.Fatalf("other identity = %+v, want the released foreign login", other)
			}

			latched := attempts["fl1."+strings.Repeat("2", 32)]
			if latched.OutcomeBasis != "primary_failure_kept" || len(latched.Events) != 4 ||
				latched.Steps.SecondFactor != "recorded" || latched.Projection != "detail" {
				t.Fatalf("latched attempt = %+v, want all factor events", latched)
			}

			for id, attempt := range attempts {
				assertNoRedactionMembers(t, id, attempt)
			}
		})
	}
}

// TestEveryHistoryScopeSeesTheFullBanEvidence pins that both history scopes see the claimed usernames, client
// addresses, and accounts of shared-address contributions and the operator of a lifecycle event.
func TestEveryHistoryScopeSeesTheFullBanEvidence(t *testing.T) {
	for _, scope := range historyScopes {
		t.Run(scope, func(t *testing.T) {
			result := searchBans(t, sharedIPStore(banNow.Add(-2*time.Hour)), scope)
			for _, item := range result.Bans[0].Contributions.Items {
				if item.ClaimedUsername == nil || item.ClientIP == nil {
					t.Fatalf("contribution %+v hides the identities behind the shared address", item)
				}
			}

			if operator := result.Releases[0].OperatorClientID; stringValue(operator) != "ops-client" {
				t.Fatalf("release operator = %v, want ops-client", operator)
			}

			assertNoRedactionMembers(t, "ban search", result)

			store := withRecordedSubject(ctxStore(ctxNow.Add(-time.Hour), banOther))
			entry := onlyContext(t, ctxService(t, store, nil), scope, "detailed")
			attribution := entry.Bans[0].Attribution

			if len(attribution.ContributingAccounts) != 1 || attribution.ContributingAccounts[0] != banOther.account {
				t.Fatalf("contributing accounts = %v, want %s", attribution.ContributingAccounts, banOther.account)
			}

			if account := entry.Bans[0].Detail.Contributions.Items[0].Account; stringValue(account) != banOther.account {
				t.Fatalf("detail contribution account = %v, want %s", account, banOther.account)
			}

			assertNoRedactionMembers(t, "ban context", entry)
		})
	}
}

// TestBanSubjectIsReadableWithTheReadScope pins that history_read may name a ban subject.
func TestBanSubjectIsReadableWithTheReadScope(t *testing.T) {
	store := sharedIPStore(banNow.Add(-2 * time.Hour))

	result, err := banService(t, store).SearchBans(t.Context(), caller(definitions.ScopeHistoryRead),
		supporthistory.BanSearchRequest{SchemaVersion: "1", Target: supporthistory.BanTarget{IP: "198.51.100.17"},
			Subject: &supporthistory.Subject{Login: "bob@example.test"},
			Filter:  supporthistory.BanSearchFilter{From: banNow.Add(-3 * time.Hour), Until: banNow}})
	if err != nil || len(result.Bans) != 1 {
		t.Fatalf("SearchBans() = %+v, %v, want the ban explained for the subject", result, err)
	}
}
