// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package policyfx

import (
	"errors"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/policy/catalogcompile"
)

// TestCheckCatalogCompilesTheStartupCatalog proves that a valid configuration passes the dry catalog compilation.
func TestCheckCatalogCompilesTheStartupCatalog(t *testing.T) {
	if err := CheckCatalog(t.Context(), productionNonAuthDecisionCandidate(t), &pluginloader.State{}, nil); err != nil {
		t.Fatalf("CheckCatalog() error = %v", err)
	}
}

// TestCheckCatalogRejectsRuleFactMismatch reproduces a configuration check that passed although the startup catalog
// compilation rejects a rule whose fact is outside the target schema, which left the server crash-looping.
func TestCheckCatalogRejectsRuleFactMismatch(t *testing.T) {
	document, err := policyconfig.Decode("yaml", strings.NewReader(strings.Replace(
		productionNonAuthDecisionFixture,
		"if: {always: true}",
		"if: {attribute: mail.unknown_flag, is: true}",
		1,
	)))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	configured := &config.FileSettings{Policy: document.Policy}

	err = CheckCatalog(t.Context(), configured, &pluginloader.State{}, nil)
	if !errors.Is(err, catalogcompile.ErrPolicyRuleFactMismatch) {
		t.Fatalf("CheckCatalog() error = %v, want %v", err, catalogcompile.ErrPolicyRuleFactMismatch)
	}

	if !strings.Contains(err.Error(), "mail.unknown_flag") {
		t.Fatalf("CheckCatalog() error = %v, want the rejected fact named", err)
	}
}
