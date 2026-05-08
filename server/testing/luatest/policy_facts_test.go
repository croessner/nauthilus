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

package luatest

import (
	"path/filepath"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestPolicyFactsHelperStoresContextAndPublicLogs(t *testing.T) {
	env := newPolicyFactsTestEnv()
	defer env.L.Close()

	if err := env.L.DoString(`
local facts = require("nauthilus_policy_facts")
facts.set("blocklist", "internal_reason", "not logged")
facts.set_public("blocklist", "matched", true)
facts.set_public("geoip", "country_codes", { "DE", "AT" })
facts.status_message("blocklist", "IP address blocked")
`); err != nil {
		t.Fatalf("policy facts script failed: %v", err)
	}

	assertPolicyFactsContext(t, env.state)
	assertPolicyFactLogs(t, env.logs)
	assertPolicyFactEmissions(t, env.emitted)

	if len(env.statusMessages) != 1 || env.statusMessages[0] != "IP address blocked" {
		t.Fatalf("status messages = %#v, want IP address blocked", env.statusMessages)
	}
}

type policyFactsTestEnv struct {
	L              *lua.LState
	state          map[string]lua.LValue
	logs           []string
	emitted        []string
	statusMessages []string
}

func newPolicyFactsTestEnv() *policyFactsTestEnv {
	env := &policyFactsTestEnv{
		L:     lua.NewState(),
		state: map[string]lua.LValue{},
	}

	env.L.PreloadModule("nauthilus_context", env.loaderModContext())
	env.L.PreloadModule("nauthilus_policy", env.loaderModPolicy())
	env.L.SetGlobal("nauthilus_builtin", env.builtinTable())
	addPackagePath(env.L, filepath.Join("..", "..", "lua-plugins.d", "share", "?.lua"))

	return env
}

func (e *policyFactsTestEnv) loaderModContext() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()
		L.SetFuncs(mod, map[string]lua.LGFunction{
			"context_get": e.contextGet,
			"context_set": e.contextSet,
		})
		L.Push(mod)

		return 1
	}
}

func (e *policyFactsTestEnv) loaderModPolicy() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()
		L.SetFuncs(mod, map[string]lua.LGFunction{
			"emit_attribute": func(L *lua.LState) int {
				table := L.CheckTable(1)
				e.emitted = append(e.emitted, table.RawGetString("id").String())

				return 0
			},
		})
		L.Push(mod)

		return 1
	}
}

func (e *policyFactsTestEnv) contextGet(L *lua.LState) int {
	key := L.CheckString(1)
	if value, ok := e.state[key]; ok {
		L.Push(value)
	} else {
		L.Push(lua.LNil)
	}

	return 1
}

func (e *policyFactsTestEnv) contextSet(L *lua.LState) int {
	key := L.CheckString(1)
	e.state[key] = L.CheckAny(2)

	return 0
}

func (e *policyFactsTestEnv) builtinTable() *lua.LTable {
	builtin := e.L.NewTable()
	builtin.RawSetString("custom_log_add", e.L.NewFunction(func(L *lua.LState) int {
		e.logs = append(e.logs, L.CheckString(1)+"="+L.CheckAny(2).String())

		return 0
	}))
	builtin.RawSetString("status_message_set", e.L.NewFunction(func(L *lua.LState) int {
		e.statusMessages = append(e.statusMessages, L.CheckString(1))

		return 0
	}))

	return builtin
}

func assertPolicyFactsContext(t *testing.T, state map[string]lua.LValue) {
	t.Helper()

	facts, ok := state["policy_facts"].(*lua.LTable)
	if !ok {
		t.Fatalf("policy_facts context type = %T, want table", state["policy_facts"])
	}

	blocklist, ok := facts.RawGetString("blocklist").(*lua.LTable)
	if !ok {
		t.Fatalf("blocklist facts type = %T, want table", facts.RawGetString("blocklist"))
	}

	if got := blocklist.RawGetString("matched"); got != lua.LTrue {
		t.Fatalf("blocklist.matched = %v, want true", got)
	}

	if got := blocklist.RawGetString("internal_reason").String(); got != "not logged" {
		t.Fatalf("blocklist.internal_reason = %q, want not logged", got)
	}
}

func assertPolicyFactLogs(t *testing.T, logs []string) {
	t.Helper()

	wantLogs := []string{
		"policy_fact_blocklist_matched=true",
		"policy_fact_geoip_country_codes=DE,AT",
		"policy_fact_blocklist_status_message=IP address blocked",
	}
	if len(logs) != len(wantLogs) {
		t.Fatalf("logs = %#v, want %#v", logs, wantLogs)
	}

	for index, want := range wantLogs {
		if logs[index] != want {
			t.Fatalf("logs[%d] = %q, want %q", index, logs[index], want)
		}
	}
}

func assertPolicyFactEmissions(t *testing.T, emitted []string) {
	t.Helper()

	want := []string{
		"lua.plugin.blocklist.matched",
		"lua.plugin.geoip.country_codes",
		"lua.plugin.blocklist.status_message",
	}
	if len(emitted) != len(want) {
		t.Fatalf("emitted = %#v, want %#v", emitted, want)
	}

	for index, expected := range want {
		if emitted[index] != expected {
			t.Fatalf("emitted[%d] = %q, want %q", index, emitted[index], expected)
		}
	}
}

func addPackagePath(L *lua.LState, pattern string) {
	pkg := L.GetGlobal("package").(*lua.LTable)
	current := L.GetField(pkg, "path").String()
	L.SetField(pkg, "path", lua.LString(filepath.ToSlash(pattern)+";"+current))
}
