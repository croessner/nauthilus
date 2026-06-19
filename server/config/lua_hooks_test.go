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

package config

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestValidateLuaHooks_AllowsUniqueAbsoluteAliasLocations(t *testing.T) {
	cfg := &FileSettings{
		Lua: &LuaSection{
			Hooks: []LuaHooks{
				{
					Location:      "one",
					AliasLocation: "/external/one",
					Method:        http.MethodGet,
				},
				{
					Location:      "two",
					AliasLocation: "/external/two",
					Method:        http.MethodGet,
				},
				{
					Location:      "three",
					AliasLocation: "/external/one",
					Method:        http.MethodPost,
				},
			},
		},
	}

	if err := cfg.validateLuaHooks(); err != nil {
		t.Fatalf("validateLuaHooks() error = %v", err)
	}
}

func TestValidateLuaHooks_RejectsDuplicateAliasLocationsForSameMethod(t *testing.T) {
	cfg := &FileSettings{
		Lua: &LuaSection{
			Hooks: []LuaHooks{
				{
					Location:      "one",
					AliasLocation: "/external/hook",
					Method:        http.MethodGet,
				},
				{
					Location:      "two",
					AliasLocation: "/external/hook",
					Method:        http.MethodGet,
				},
			},
		},
	}

	if err := cfg.validateLuaHooks(); err == nil {
		t.Fatal("validateLuaHooks() error = nil, want duplicate alias error")
	}
}

func TestValidateLuaHooks_RejectsCanonicalAliasLocation(t *testing.T) {
	cfg := &FileSettings{
		Lua: &LuaSection{
			Hooks: []LuaHooks{
				{
					Location:      "canonical",
					AliasLocation: "/api/v1/custom/canonical",
					Method:        http.MethodGet,
				},
			},
		},
	}

	if err := cfg.validateLuaHooks(); err == nil {
		t.Fatal("validateLuaHooks() error = nil, want canonical alias error")
	}
}

func TestValidateLuaHooks_RejectsReservedCustomHookAliasPrefix(t *testing.T) {
	cfg := &FileSettings{
		Lua: &LuaSection{
			Hooks: []LuaHooks{
				{
					Location:      "canonical",
					AliasLocation: "/api/v1/custom/other",
					Method:        http.MethodGet,
				},
			},
		},
	}

	if err := cfg.validateLuaHooks(); err == nil {
		t.Fatal("validateLuaHooks() error = nil, want reserved prefix alias error")
	}
}

func TestLuaHooksValidation_RequiresAbsoluteAliasLocation(t *testing.T) {
	validate := validator.New(validator.WithRequiredStructEnabled())

	scriptPath := filepath.Join(t.TempDir(), "hook.lua")
	if err := os.WriteFile(scriptPath, []byte("return true\n"), 0o600); err != nil {
		t.Fatalf("write hook script: %v", err)
	}

	luaHook := LuaHooks{
		Location:      "canonical",
		AliasLocation: "relative/hook",
		Method:        http.MethodGet,
		ScriptPath:    scriptPath,
	}

	if err := validate.Struct(luaHook); err == nil {
		t.Fatal("validate.Struct() error = nil, want absolute alias validation error")
	}
}
