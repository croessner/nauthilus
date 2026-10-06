package config

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// TestIdentityCacheDefaults verifies explicit opt-in and a bounded default lifetime.
func TestIdentityCacheDefaults(t *testing.T) {
	t.Parallel()

	for _, redis := range []*Redis{nil, {}, {IdentityCache: &IdentityCache{}}} {
		assert.False(t, redis.GetIdentityCacheEnabled())
		assert.Equal(t, time.Minute, redis.GetIdentityCacheTTL())
	}
}

// TestIdentityCacheConfiguration verifies canonical configuration decoding and explicit overrides.
func TestIdentityCacheConfiguration(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigType("yaml")
	assert.NoError(t, viper.ReadConfig(strings.NewReader(`storage:
  redis:
    identity_cache:
      enabled: true
      ttl: 30s
`)))

	cfg := &FileSettings{}
	assert.NoError(t, viper.UnmarshalExact(cfg, createDecoderOption()))
	cfg.materializeLegacySections()

	redis := cfg.GetServer().GetRedis()
	assert.True(t, redis.GetIdentityCacheEnabled())
	assert.Equal(t, 30*time.Second, redis.GetIdentityCacheTTL())
}

// TestIdentityCacheDefaultDump verifies the operator-visible default configuration.
func TestIdentityCacheDefaultDump(t *testing.T) {
	t.Parallel()

	dump, err := RenderDefaultConfigDumpWithFormat(DumpFormatYAML)
	assert.NoError(t, err)

	var document struct {
		Storage struct {
			Redis struct {
				IdentityCache struct {
					Enabled bool   `yaml:"enabled"`
					TTL     string `yaml:"ttl"`
				} `yaml:"identity_cache"`
			} `yaml:"redis"`
		} `yaml:"storage"`
	}

	assert.NoError(t, yaml.Unmarshal([]byte(dump), &document))
	assert.False(t, document.Storage.Redis.IdentityCache.Enabled)
	assert.Equal(t, "1m0s", document.Storage.Redis.IdentityCache.TTL)
}

// TestIdentityCacheTTLValidation rejects unbounded or subsecond positive identity lifetimes.
func TestIdentityCacheTTLValidation(t *testing.T) {
	for _, ttl := range []string{"-1s", "500ms", "8761h"} {
		t.Run(ttl, func(t *testing.T) {
			content := `storage:
  redis:
    primary:
      address: localhost:6379
    password_nonce: nonce-secret-1234
    encryption_secret: redis-secret-1234
    identity_cache:
      enabled: true
      ttl: ` + ttl + "\n"

			_, err := handleFileFromContent(t, content)
			assert.Error(t, err)
		})
	}
}
