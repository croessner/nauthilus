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

package bruteforce

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	model "github.com/croessner/nauthilus/server/model/bruteforce"
	restdto "github.com/croessner/nauthilus/server/model/rest"
	management "github.com/croessner/nauthilus/server/openapi/generated/management"
	"github.com/croessner/nauthilus/server/openapi/requesttest"
)

const (
	bruteForceTypedBoundaryAccount  = "alice@example.test"
	bruteForceTypedBoundaryIP       = "203.0.113.10"
	bruteForceTypedBoundaryOIDCCID  = "synthetic-client"
	bruteForceTypedBoundaryProtocol = "imap"
	bruteForceTypedBoundaryRule     = "rule-a"
	bruteForceTypedBoundarySession  = "bruteforce-boundary-session"
	bruteForceTypedBoundaryStatus   = "1 keys flushed"
)

func TestBruteForceFilterGeneratedModelBridgesCurrentDTO(t *testing.T) {
	accounts := []string{bruteForceTypedBoundaryAccount}
	ipAddresses := []string{bruteForceTypedBoundaryIP}
	generated := management.BruteForceFilterRequest{
		Accounts:    &accounts,
		IpAddresses: &ipAddresses,
	}
	current := model.FilterCmd{}

	requesttest.RoundTripJSON(t, generated, &current)

	assertBruteForceFilterRequestBridge(t, current)
}

func TestBruteForceFlushGeneratedModelBridgesCurrentDTO(t *testing.T) {
	protocol := bruteForceTypedBoundaryProtocol
	oidcCID := bruteForceTypedBoundaryOIDCCID
	generated := management.BruteForceFlushRequest{
		IpAddress: bruteForceTypedBoundaryIP,
		OidcCid:   &oidcCID,
		Protocol:  &protocol,
		RuleName:  bruteForceTypedBoundaryRule,
	}
	current := model.FlushRuleCmd{}

	requesttest.RoundTripJSON(t, generated, &current)

	assertBruteForceFlushRequestBridge(t, current, generated)
}

func TestBruteForceFlushResponseBridgesGeneratedModel(t *testing.T) {
	removedKeys := []string{"t:bruteforce:rule-a:203.0.113.10"}
	current := restdto.Result{
		GUID:      bruteForceTypedBoundarySession,
		Object:    definitions.CatBruteForce,
		Operation: definitions.ServFlush,
		Result: model.FlushRuleCmdStatus{
			IPAddress:   bruteForceTypedBoundaryIP,
			RuleName:    bruteForceTypedBoundaryRule,
			Protocol:    bruteForceTypedBoundaryProtocol,
			OIDCCID:     bruteForceTypedBoundaryOIDCCID,
			RemovedKeys: removedKeys,
			Status:      bruteForceTypedBoundaryStatus,
		},
	}
	generated := management.BruteForceFlushResult{}

	requesttest.RoundTripJSON(t, current, &generated)

	assertBruteForceTypedBoundaryEnvelope(t, generated.Object, generated.Operation, generated.Session)
	assertBruteForceFlushPayloadBridge(t, generated.Result, removedKeys)
}

func TestBruteForceListResponseBridgesGeneratedEnvelope(t *testing.T) {
	current := restdto.Result{
		GUID:      bruteForceTypedBoundarySession,
		Object:    definitions.CatBruteForce,
		Operation: definitions.ServList,
		Result: []any{
			model.BlockedIPAddresses{Entries: []model.BanEntry{}},
			model.BlockedAccounts{Accounts: map[string][]string{}},
		},
	}
	generated := management.BruteForceListResult{}

	requesttest.RoundTripJSON(t, current, &generated)

	assertBruteForceTypedBoundaryEnvelope(t, generated.Object, generated.Operation, generated.Session)

	if len(generated.Result) != 2 {
		t.Fatalf("result has %d entries, want 2", len(generated.Result))
	}
}

func assertBruteForceFilterRequestBridge(t testing.TB, current model.FilterCmd) {
	t.Helper()

	if len(current.Accounts) != 1 || current.Accounts[0] != bruteForceTypedBoundaryAccount {
		t.Fatalf("current accounts = %v, want [%s]", current.Accounts, bruteForceTypedBoundaryAccount)
	}

	if len(current.IPAddress) != 1 || current.IPAddress[0] != bruteForceTypedBoundaryIP {
		t.Fatalf("current ip_addresses = %v, want [%s]", current.IPAddress, bruteForceTypedBoundaryIP)
	}
}

func assertBruteForceFlushRequestBridge(t testing.TB, current model.FlushRuleCmd, generated management.BruteForceFlushRequest) {
	t.Helper()

	if current.IPAddress != generated.IpAddress {
		t.Fatalf("current ip_address = %q, want %q", current.IPAddress, generated.IpAddress)
	}

	if current.RuleName != generated.RuleName {
		t.Fatalf("current rule_name = %q, want %q", current.RuleName, generated.RuleName)
	}

	requesttest.RequireStringPointer(t, "generated.protocol", generated.Protocol, current.Protocol)
	requesttest.RequireStringPointer(t, "generated.oidc_cid", generated.OidcCid, current.OIDCCID)
}

func assertBruteForceFlushPayloadBridge(t testing.TB, generated management.BruteForceFlushPayload, removedKeys []string) {
	t.Helper()

	requesttest.RequireStringPointer(t, "result.ip_address", generated.IpAddress, bruteForceTypedBoundaryIP)
	requesttest.RequireStringPointer(t, "result.rule_name", generated.RuleName, bruteForceTypedBoundaryRule)
	requesttest.RequireStringPointer(t, "result.protocol", generated.Protocol, bruteForceTypedBoundaryProtocol)
	requesttest.RequireStringPointer(t, "result.oidc_cid", generated.OidcCid, bruteForceTypedBoundaryOIDCCID)
	requesttest.RequireStringPointer(t, "result.status", generated.Status, bruteForceTypedBoundaryStatus)
	requesttest.RequireStringSlicePointer(t, "result.removed_keys", generated.RemovedKeys, removedKeys)
}

func assertBruteForceTypedBoundaryEnvelope(t testing.TB, object string, operation string, session string) {
	t.Helper()

	if session != bruteForceTypedBoundarySession {
		t.Fatalf("session = %q, want %q", session, bruteForceTypedBoundarySession)
	}

	if object != definitions.CatBruteForce {
		t.Fatalf("object = %q, want %q", object, definitions.CatBruteForce)
	}

	if operation != definitions.ServFlush && operation != definitions.ServList {
		t.Fatalf("operation = %q, want %q or %q", operation, definitions.ServFlush, definitions.ServList)
	}
}
