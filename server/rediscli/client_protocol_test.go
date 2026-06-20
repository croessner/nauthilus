package rediscli

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/stretchr/testify/assert"
)

type redisProtocolCase struct {
	name     string
	redisCfg *config.Redis
	want     int
}

func TestGetProtocol(t *testing.T) {
	for _, tt := range redisProtocolCases() {
		t.Run(tt.name, func(t *testing.T) {
			got := getProtocol(tt.redisCfg)
			assert.Equal(t, tt.want, got)
		})
	}
}

// redisProtocolCases returns RESP protocol selection scenarios.
func redisProtocolCases() []redisProtocolCase {
	return []redisProtocolCase{
		{name: "nil config", want: 2},
		{name: "default config (no RESP3-only capabilities)", redisCfg: &config.Redis{}, want: 2},
		{name: "explicit protocol 2", redisCfg: redisProtocolConfig(2), want: 2},
		{name: "explicit protocol 3", redisCfg: redisProtocolConfig(3), want: 3},
		{name: "tracking enabled triggers protocol 3", redisCfg: redisProtocolTrackingConfig(0), want: 3},
		{name: "maint notifications enabled triggers protocol 3", redisCfg: redisProtocolMaintConfig(), want: 3},
		{name: "explicit protocol 2 overrides tracking", redisCfg: redisProtocolTrackingConfig(2), want: 2},
	}
}

// redisProtocolConfig returns a Redis config with an explicit protocol.
func redisProtocolConfig(protocol int) *config.Redis {
	return &config.Redis{Protocol: protocol}
}

// redisProtocolTrackingConfig returns a Redis config with client tracking enabled.
func redisProtocolTrackingConfig(protocol int) *config.Redis {
	return &config.Redis{
		Protocol: protocol,
		ClientTracking: config.RedisClientTracking{
			Enabled: true,
		},
	}
}

// redisProtocolMaintConfig returns a Redis config with maintenance notifications enabled.
func redisProtocolMaintConfig() *config.Redis {
	return &config.Redis{MaintNotificationsEnabled: true}
}
