package rediscli

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/stretchr/testify/assert"
)

func TestGetProtocol(t *testing.T) {
	tests := []struct {
		name     string
		redisCfg *config.Redis
		want     int
	}{
		{
			name:     "nil config",
			redisCfg: nil,
			want:     2,
		},
		{
			name:     "default config (no features)",
			redisCfg: &config.Redis{},
			want:     2,
		},
		{
			name: "explicit protocol 2",
			redisCfg: &config.Redis{
				Protocol: 2,
			},
			want: 2,
		},
		{
			name: "explicit protocol 3",
			redisCfg: &config.Redis{
				Protocol: 3,
			},
			want: 3,
		},
		{
			name: "tracking enabled triggers protocol 3",
			redisCfg: &config.Redis{
				ClientTracking: config.RedisClientTracking{
					Enabled: true,
				},
			},
			want: 3,
		},
		{
			name: "maint notifications enabled triggers protocol 3",
			redisCfg: &config.Redis{
				MaintNotificationsEnabled: true,
			},
			want: 3,
		},
		{
			name: "explicit protocol 2 overrides tracking",
			redisCfg: &config.Redis{
				Protocol: 2,
				ClientTracking: config.RedisClientTracking{
					Enabled: true,
				},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getProtocol(tt.redisCfg)
			assert.Equal(t, tt.want, got)
		})
	}
}
