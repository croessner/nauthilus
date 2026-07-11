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

package core

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/report"
)

func TestBruteForceUpdateObligationLearningGate(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	cfg.BruteForce.Learning = []*config.RuntimeModule{mustCurrentBehaviorModule(t, definitions.ControlRBL)}
	auth, _, _ := newCurrentBehaviorAuthState(t, cfg)

	tests := []struct {
		name    string
		request bruteForceUpdateObligation
		want    bool
	}{
		{name: "unconditional", request: bruteForceUpdateObligation{}, want: true},
		{name: "configured feature", request: bruteForceUpdateObligation{featureName: definitions.ControlRBL, environmentName: definitions.ControlRBL}, want: true},
		{name: "configured environment alias", request: bruteForceUpdateObligation{featureName: "environment", environmentName: definitions.ControlRBL}, want: true},
		{name: "unconfigured feature", request: bruteForceUpdateObligation{featureName: definitions.ControlLua, environmentName: "blocklist"}, want: false},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := auth.shouldRunBruteForceUpdate(testCase.request); got != testCase.want {
				t.Fatalf("shouldRunBruteForceUpdate() = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestBruteForceUpdateObligationFromEffect(t *testing.T) {
	request, ok := bruteForceUpdateObligationFromEffect(policyEffectRequest(
		policy.ObligationBruteForceUpdate,
		map[string]any{
			policy.ObligationArgFeature:     definitions.ControlLua,
			policy.ObligationArgEnvironment: "blocklist",
		},
	))
	if !ok {
		t.Fatal("bruteForceUpdateObligationFromEffect() rejected valid args")
	}

	if request.featureName != definitions.ControlLua || request.environmentName != "blocklist" {
		t.Fatalf("request = %#v, want lua/blocklist", request)
	}
}

func TestLuaActionObligationDoesNotUpdateBruteForceState(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	cfg.BruteForce.Learning = []*config.RuntimeModule{mustCurrentBehaviorModule(t, definitions.ControlLua)}
	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Runtime.AccountName = auth.Request.Username

	ctx.Set(definitions.CtxRWPResultKey, false)

	ok := auth.executeLuaActionObligation(ctx, luaActionObligation{
		environmentName: "blocklist",
		actionName:      definitions.ControlLua,
		luaAction:       definitions.LuaActionLua,
	})
	if !ok {
		t.Fatal("executeLuaActionObligation() rejected valid Lua action")
	}

	if auth.Runtime.BFRWP {
		t.Fatal("Lua action dispatch updated brute-force RWP state")
	}
}

// policyEffectRequest builds one report effect for obligation parser tests.
func policyEffectRequest(id string, args map[string]any) report.EffectRequest {
	return report.EffectRequest{ID: id, Args: args}
}
