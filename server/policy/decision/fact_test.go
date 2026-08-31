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

package decision_test

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

func TestFactRejectsCallerOwnershipOfReservedPrefixes(t *testing.T) {
	value := mustStringValue(t, "admin")
	provenance := mustProvenance(t, decision.FactSourceCaller, "client-a", "request")

	for _, id := range []string{
		"caller.principal",
		"token.subject",
		"transport.source_ip",
		"nauthilus.reputation",
		"backend.account",
		"lua.geoip.country",
		"plugin.rns.role",
	} {
		_, err := decision.NewFact(id, decision.FactCategoryEnvironment, value, provenance)
		if !errors.Is(err, decision.ErrReservedFact) {
			t.Fatalf("NewFact(%q) error = %v, want ErrReservedFact", id, err)
		}
	}
}

func TestFactEnforcesSourceOwnership(t *testing.T) {
	value := mustStringValue(t, "service-a")

	tests := []struct {
		name      string
		id        string
		source    decision.FactSource
		authority string
		component string
		ok        bool
		want      error
	}{
		{name: "caller input", id: "input.message_size", source: decision.FactSourceCaller, authority: "client-a", component: "request", ok: true},
		{name: "token claim", id: "token.subject", source: decision.FactSourceToken, authority: "issuer-a", component: "access_token", ok: true},
		{name: "transport fact", id: "transport.listener", source: decision.FactSourceTransport, authority: "nauthilus", component: "http", ok: true},
		{name: "host fact", id: "nauthilus.instance", source: decision.FactSourceNauthilus, authority: "nauthilus", component: "host", ok: true},
		{name: "backend fact", id: "backend.account", source: decision.FactSourceBackend, authority: "ldap", component: "primary", ok: true},
		{name: "lua fact", id: "lua.geoip.country", source: decision.FactSourceLua, authority: "geoip", component: "country", ok: true},
		{name: "plugin fact", id: "plugin.rns.role", source: decision.FactSourcePlugin, authority: "rns", component: "role", ok: true},
		{name: "token source on caller prefix", id: "subject.id", source: decision.FactSourceToken, authority: "issuer-a", component: "access_token", want: decision.ErrFactSource},
		{name: "caller source on host prefix", id: "nauthilus.instance", source: decision.FactSourceCaller, authority: "client-a", component: "request", want: decision.ErrReservedFact},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provenance := mustProvenance(t, test.source, test.authority, test.component)

			_, err := decision.NewFact(test.id, decision.FactCategoryEnvironment, value, provenance)
			if test.ok && err != nil {
				t.Fatalf("NewFact() error = %v", err)
			}

			if !test.ok && !errors.Is(err, test.want) {
				t.Fatalf("NewFact() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestProviderFactAuthorityMatchesCanonicalOwner(t *testing.T) {
	value := mustStringValue(t, "DE")

	tests := []struct {
		name      string
		id        string
		source    decision.FactSource
		authority string
	}{
		{name: "lua provider mismatch", id: "lua.geoip.country", source: decision.FactSourceLua, authority: "reputation"},
		{name: "plugin module mismatch", id: "plugin.rns.role", source: decision.FactSourcePlugin, authority: "director"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provenance := mustProvenance(t, test.source, test.authority, "result")

			_, err := decision.NewFact(test.id, decision.FactCategoryEnvironment, value, provenance)
			if !errors.Is(err, decision.ErrFactSource) {
				t.Fatalf("NewFact() error = %v, want ErrFactSource", err)
			}
		})
	}
}

func TestFactSetRejectsCanonicalCollisions(t *testing.T) {
	value := mustStringValue(t, "value")
	provenance := mustProvenance(t, decision.FactSourceCaller, "client-a", "request")

	fact, err := decision.NewFact("input.message_id", decision.FactCategoryResource, value, provenance)
	if err != nil {
		t.Fatalf("NewFact() error = %v", err)
	}

	_, err = decision.NewFactSet([]decision.Fact{fact, fact})
	if !errors.Is(err, decision.ErrFactCollision) {
		t.Fatalf("NewFactSet() error = %v, want ErrFactCollision", err)
	}
}

// mustStringValue creates a strict string value for fact tests.
func mustStringValue(t *testing.T, input string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}

// mustProvenance creates constructor-validated provenance for fact tests.
func mustProvenance(
	t *testing.T,
	source decision.FactSource,
	authority string,
	component string,
) decision.Provenance {
	t.Helper()

	provenance, err := decision.NewProvenance(source, authority, component)
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	return provenance
}
