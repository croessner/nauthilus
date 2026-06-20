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

package lualib

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"

	lua "github.com/yuin/gopher-lua"
	"golang.org/x/text/language"
)

const (
	luaI18NKey             = "auth.policy.company.account_blocked"
	luaI18NFallback        = "Login failed because the account is locked."
	luaI18NEnglish         = "Login denied."
	luaI18NGerman          = "Anmeldung abgelehnt."
	luaI18NDeploymentFinal = "Deployment override."
	luaI18NGetArgError     = "get_localized expects exactly one table argument"
)

type luaI18NErrorCase struct {
	script      string
	name        string
	wantErrPart string
}

func TestI18NGetLocalizedReturnsExplicitTable(t *testing.T) {
	L := newI18NTestState(t, newI18NTestRuntime(t, localization.CatalogOverlay{}), I18NModeRequest)

	err := L.DoString(`
		local i18n = require("nauthilus_i18n")
		result = i18n.get_localized({
			i18n_key = "auth.policy.company.account_blocked",
			fallback = "Login failed because the account is locked.",
			language = "de",
		})
	`)
	if err != nil {
		t.Fatalf("run Lua: %v", err)
	}

	result := requireLuaTable(t, L.GetGlobal("result"))
	assertLuaStringField(t, result, "message", luaI18NGerman)
	assertLuaStringField(t, result, "language", "de")
	assertLuaStringField(t, result, "i18n_key", luaI18NKey)
	assertLuaBoolField(t, result, "localized", true)
	assertLuaBoolField(t, result, "fallback_used", false)
}

func TestI18NGetLocalizedValidatesSingleTableArgument(t *testing.T) {
	runI18NLuaErrorCases(t, I18NModeRequest, getLocalizedValidationCases())
}

func TestI18NGetLocalizedFallbackAndInvalidLanguageHandling(t *testing.T) {
	L := newI18NTestState(t, newI18NTestRuntime(t, localization.CatalogOverlay{}), I18NModeRequest)

	err := L.DoString(`
		local i18n = require("nauthilus_i18n")
		invalid_language = i18n.get_localized({
			i18n_key = "auth.policy.company.account_blocked",
			fallback = "Login failed because the account is locked.",
			language = "not a language",
		})
		missing_key = i18n.get_localized({
			i18n_key = "auth.policy.company.missing",
			fallback = "Login failed because the account is locked.",
			language = "de",
		})
	`)
	if err != nil {
		t.Fatalf("run Lua: %v", err)
	}

	invalidLanguage := requireLuaTable(t, L.GetGlobal("invalid_language"))
	assertLuaStringField(t, invalidLanguage, "message", luaI18NEnglish)
	assertLuaStringField(t, invalidLanguage, "language", "en")
	assertLuaBoolField(t, invalidLanguage, "localized", true)
	assertLuaBoolField(t, invalidLanguage, "fallback_used", false)

	missingKey := requireLuaTable(t, L.GetGlobal("missing_key"))
	assertLuaStringField(t, missingKey, "message", luaI18NFallback)
	assertLuaStringField(t, missingKey, "language", "de")
	assertLuaBoolField(t, missingKey, "localized", false)
	assertLuaBoolField(t, missingKey, "fallback_used", true)
}

func TestI18NRegisterCatalogStartupMergesDeploymentOverlays(t *testing.T) {
	runtime := newI18NTestRuntime(t, localization.CatalogOverlay{})
	session := runtime.NewCatalogSession()
	L := newI18NTestState(t, session, I18NModeStartup)

	err := L.DoString(`
		local i18n = require("nauthilus_i18n")
		i18n.register_catalog({
			language = "en",
			namespace = "company-base",
			entries = {
				["auth.policy.company.account_blocked"] = "Deployment English.",
			},
		})
		i18n.register_catalog({
			language = "de",
			namespace = "company-base",
			entries = {
				["auth.policy.company.account_blocked"] = "Deployment German.",
			},
		})
		i18n.register_catalog({
			language = "de",
			namespace = "company-final",
			entries = {
				["auth.policy.company.account_blocked"] = "Deployment override.",
			},
		})
	`)
	if err != nil {
		t.Fatalf("run Lua: %v", err)
	}

	if err := session.CommitCatalogSession(); err != nil {
		t.Fatalf("commit catalog session: %v", err)
	}

	assertCatalogText(t, runtime.Registry.Active(), "en", luaI18NKey, "Deployment English.")
	assertCatalogText(t, runtime.Registry.Active(), "de", luaI18NKey, luaI18NDeploymentFinal)
}

func TestI18NRegisterCatalogRejectsRequestTimeMutation(t *testing.T) {
	runtime := newI18NTestRuntime(t, localization.CatalogOverlay{
		Namespace: "company",
		Entries: map[string]map[string]string{
			"de": {
				luaI18NKey: luaI18NGerman,
			},
		},
	})
	L := newI18NTestState(t, runtime, I18NModeRequest)

	err := L.DoString(`
		local i18n = require("nauthilus_i18n")
		i18n.register_catalog({
			language = "de",
			namespace = "company-request",
			entries = {
				["auth.policy.company.account_blocked"] = "Request-time mutation.",
			},
		})
	`)
	if err == nil {
		t.Fatal("request-time catalog registration succeeded")
	}

	if !strings.Contains(err.Error(), "register_catalog is only available during startup Lua execution") {
		t.Fatalf("error = %q, want startup-only rejection", err.Error())
	}

	assertCatalogText(t, runtime.Registry.Active(), "de", luaI18NKey, luaI18NGerman)
}

func TestI18NRegisterCatalogFailedReloadKeepsPreviousCatalog(t *testing.T) {
	runtime := newI18NTestRuntime(t, localization.CatalogOverlay{
		Namespace: "company",
		Entries: map[string]map[string]string{
			"de": {
				luaI18NKey: luaI18NGerman,
			},
		},
	})
	session := runtime.NewCatalogSession()
	L := newI18NTestState(t, session, I18NModeStartup)

	err := L.DoString(`
		local i18n = require("nauthilus_i18n")
		i18n.register_catalog({
			language = "de",
			namespace = "company-pending",
			entries = {
				["auth.policy.company.account_blocked"] = "Pending mutation.",
			},
		})
		i18n.register_catalog({
			language = "not a language",
			namespace = "company-broken",
			entries = {
				["auth.policy.company.account_blocked"] = "Broken.",
			},
		})
	`)
	if err == nil {
		t.Fatal("invalid catalog registration succeeded")
	}

	assertCatalogText(t, runtime.Registry.Active(), "de", luaI18NKey, luaI18NGerman)
}

func TestI18NRegisterCatalogValidatesSingleTableArgument(t *testing.T) {
	runI18NLuaErrorCases(t, I18NModeStartup, registerCatalogValidationCases())
}

func getLocalizedValidationCases() []luaI18NErrorCase {
	return []luaI18NErrorCase{
		{name: "missing argument", script: `local i18n = require("nauthilus_i18n"); i18n.get_localized()`, wantErrPart: luaI18NGetArgError},
		{name: "extra argument", script: `local i18n = require("nauthilus_i18n"); i18n.get_localized({}, {})`, wantErrPart: luaI18NGetArgError},
		{name: "non table argument", script: `local i18n = require("nauthilus_i18n"); i18n.get_localized("invalid")`, wantErrPart: luaI18NGetArgError},
		{name: "missing key", script: `local i18n = require("nauthilus_i18n"); i18n.get_localized({ fallback = "fallback" })`, wantErrPart: "i18n_key must be a non-empty string"},
		{name: "missing fallback", script: `local i18n = require("nauthilus_i18n"); i18n.get_localized({ i18n_key = "auth.policy.company.account_blocked" })`, wantErrPart: "fallback must be a non-empty string"},
		{name: "non string language", script: `local i18n = require("nauthilus_i18n"); i18n.get_localized({ i18n_key = "auth.policy.company.account_blocked", fallback = "fallback", language = true })`, wantErrPart: "language must be a string when provided"},
	}
}

func registerCatalogValidationCases() []luaI18NErrorCase {
	return []luaI18NErrorCase{
		{name: "missing argument", script: `local i18n = require("nauthilus_i18n"); i18n.register_catalog()`, wantErrPart: "register_catalog expects exactly one table argument"},
		{name: "missing language", script: `local i18n = require("nauthilus_i18n"); i18n.register_catalog({ entries = {} })`, wantErrPart: "language must be a non-empty string"},
		{name: "missing entries", script: `local i18n = require("nauthilus_i18n"); i18n.register_catalog({ language = "de" })`, wantErrPart: "entries must be a table"},
		{name: "non string entry key", script: `local i18n = require("nauthilus_i18n"); i18n.register_catalog({ language = "de", entries = { [1] = "invalid" } })`, wantErrPart: "entries keys must be strings"},
		{name: "non string entry value", script: `local i18n = require("nauthilus_i18n"); i18n.register_catalog({ language = "de", entries = { ["auth.policy.company.account_blocked"] = true } })`, wantErrPart: "entries values must be strings"},
	}
}

func runI18NLuaErrorCases(t *testing.T, mode I18NMode, tests []luaI18NErrorCase) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L := newI18NTestState(t, newI18NTestRuntime(t, localization.CatalogOverlay{}), mode)

			err := L.DoString(tt.script)
			if err == nil {
				t.Fatal("Lua call succeeded")
			}

			if !strings.Contains(err.Error(), tt.wantErrPart) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErrPart)
			}
		})
	}
}

func newI18NTestRuntime(t *testing.T, overlays ...localization.CatalogOverlay) *I18NRuntime {
	t.Helper()

	system := localization.NewMapCatalog(map[string]map[string]string{
		"en": {
			luaI18NKey: luaI18NEnglish,
		},
		"de": {
			luaI18NKey: luaI18NGerman,
		},
	})

	registry, err := localization.NewCatalogRegistry(system, overlays...)
	if err != nil {
		t.Fatalf("create catalog registry: %v", err)
	}

	return NewI18NRuntime(I18NRuntimeOptions{
		Registry:        registry,
		DefaultLanguage: "en",
		DefaultPreference: localization.LanguagePreference{
			Default: "en",
		},
	})
}

func newI18NTestState(t *testing.T, runtime *I18NRuntime, mode I18NMode) *lua.LState {
	t.Helper()

	L := lua.NewState()
	t.Cleanup(L.Close)
	L.SetContext(t.Context())
	L.PreloadModule(definitions.LuaModI18N, LoaderModI18N(runtime, mode))

	return L
}

func requireLuaTable(t *testing.T, value lua.LValue) *lua.LTable {
	t.Helper()

	table, ok := value.(*lua.LTable)
	if !ok {
		t.Fatalf("value = %s, want table", value.Type().String())
	}

	return table
}

func assertLuaStringField(t *testing.T, table *lua.LTable, key string, want string) {
	t.Helper()

	assertLuaTypedField(t, table, key, lua.LString(want), "string")
}

func assertLuaBoolField(t *testing.T, table *lua.LTable, key string, want bool) {
	t.Helper()

	assertLuaTypedField(t, table, key, lua.LBool(want), "bool")
}

// assertLuaTypedField verifies a typed scalar field in a Lua table.
func assertLuaTypedField[T comparable](t *testing.T, table *lua.LTable, key string, want T, typeName string) {
	t.Helper()

	got, ok := table.RawGetString(key).(T)
	if !ok {
		t.Fatalf("%s = %s, want %s", key, table.RawGetString(key).Type().String(), typeName)
	}

	if got != want {
		t.Fatalf("%s = %v, want %v", key, got, want)
	}
}

func assertCatalogText(t *testing.T, catalog *localization.EffectiveCatalog, languageName string, key string, want string) {
	t.Helper()

	tag, err := language.Parse(languageName)
	if err != nil {
		t.Fatalf("parse language: %v", err)
	}

	got, ok := catalog.Lookup(tag, key)
	if !ok {
		t.Fatalf("catalog lookup for %q/%q failed", languageName, key)
	}

	if got != want {
		t.Fatalf("catalog text = %q, want %q", got, want)
	}
}
