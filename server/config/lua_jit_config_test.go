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
	"testing"

	"github.com/spf13/viper"
)

// luaJITFromViper decodes a default Lua backend section and returns the resolved JIT switch.
func luaJITFromViper(t *testing.T, section map[string]any) bool {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	setDefaultEnvVars()

	viper.Set("auth", map[string]any{
		"backends": map[string]any{
			"lua": map[string]any{
				"backend": map[string]any{
					"default": section,
				},
			},
		},
	})

	cfg := &FileSettings{}
	if err := viper.UnmarshalExact(cfg, createDecoderOption()); err != nil {
		t.Fatalf("unmarshal config failed: %v", err)
	}

	cfg.materializeLegacySections()

	conf, ok := cfg.GetLua().GetConfig().(*LuaConf)
	if !ok {
		t.Fatalf("unexpected Lua configuration type %T", cfg.GetLua().GetConfig())
	}

	return conf.GetJIT()
}

func TestLuaJITSwitch(t *testing.T) {
	cases := []struct {
		name    string
		section map[string]any
		want    bool
	}{
		{name: "default is enabled", section: map[string]any{"queue_length": 1}, want: true},
		{name: "explicitly enabled", section: map[string]any{"jit": true}, want: true},
		{name: "explicitly disabled", section: map[string]any{"jit": false}, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := luaJITFromViper(t, tc.section); got != tc.want {
				t.Fatalf("jit = %v, want %v", got, tc.want)
			}
		})
	}

	if !(*LuaConf)(nil).GetJIT() {
		t.Fatal("a missing Lua configuration must keep the JIT enabled")
	}
}
