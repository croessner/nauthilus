// Copyright (C) 2024 Christian Rößner
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

package rediscli

import (
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/server/config"
)

func TestBuildClientTrackingArgs(t *testing.T) {
	tests := []struct {
		name string
		ct   *config.RedisClientTracking
		want []any
	}{
		{
			name: "nil config",
			ct:   nil,
			want: []any{"client", "tracking", "on"},
		},
		{
			name: "enabled defaults",
			ct:   &config.RedisClientTracking{Enabled: true},
			want: []any{"client", "tracking", "on"},
		},
		{
			name: "bcast noloop",
			ct:   &config.RedisClientTracking{Enabled: true, BCast: true, NoLoop: true},
			want: []any{"client", "tracking", "on", "bcast", "noloop"},
		},
		{
			name: "optin optout (both set)",
			ct:   &config.RedisClientTracking{Enabled: true, OptIn: true, OptOut: true},
			want: []any{"client", "tracking", "on", "optin", "optout"},
		},
		{
			name: "prefixes",
			ct:   &config.RedisClientTracking{Enabled: true, Prefixes: []string{"nt:", "bf:"}},
			want: []any{"client", "tracking", "on", "prefix", "nt:", "prefix", "bf:"},
		},
		{
			name: "full flags",
			ct:   &config.RedisClientTracking{Enabled: true, BCast: true, NoLoop: true, OptOut: true, Prefixes: []string{"nt:"}},
			want: []any{"client", "tracking", "on", "bcast", "noloop", "optout", "prefix", "nt:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildClientTrackingArgs(tt.ct)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("unexpected args. got=%v want=%v", got, tt.want)
			}
		})
	}
}
