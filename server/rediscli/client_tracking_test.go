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
		want []interface{}
	}{
		{
			name: "nil config",
			ct:   nil,
			want: []interface{}{"client", "tracking", "on"},
		},
		{
			name: "enabled defaults",
			ct:   &config.RedisClientTracking{Enabled: true},
			want: []interface{}{"client", "tracking", "on"},
		},
		{
			name: "bcast noloop",
			ct:   &config.RedisClientTracking{Enabled: true, BCast: true, NoLoop: true},
			want: []interface{}{"client", "tracking", "on", "bcast", "noloop"},
		},
		{
			name: "optin optout (both set)",
			ct:   &config.RedisClientTracking{Enabled: true, OptIn: true, OptOut: true},
			want: []interface{}{"client", "tracking", "on", "optin", "optout"},
		},
		{
			name: "prefixes",
			ct:   &config.RedisClientTracking{Enabled: true, Prefixes: []string{"nt:", "bf:"}},
			want: []interface{}{"client", "tracking", "on", "prefix", "nt:", "prefix", "bf:"},
		},
		{
			name: "full flags",
			ct:   &config.RedisClientTracking{Enabled: true, BCast: true, NoLoop: true, OptOut: true, Prefixes: []string{"nt:"}},
			want: []interface{}{"client", "tracking", "on", "bcast", "noloop", "optout", "prefix", "nt:"},
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
