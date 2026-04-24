package backchannel

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/stretchr/testify/assert"
)

func TestEnsureBackchannelAuthConfigured(t *testing.T) {
	t.Run("returns error when no auth is configured", func(t *testing.T) {
		cfg := &config.FileSettings{
			Server: &config.ServerSection{
				BasicAuth: config.BasicAuth{Enabled: false},
				OIDCAuth:  config.OIDCAuth{Enabled: false},
			},
		}

		err := ensureBackchannelAuthConfigured(cfg, false)
		assert.ErrorIs(t, err, errBackchannelAuthNotConfigured)
	})

	t.Run("allows hook-only setup without auth", func(t *testing.T) {
		cfg := &config.FileSettings{
			Server: &config.ServerSection{
				BasicAuth: config.BasicAuth{Enabled: false},
				OIDCAuth:  config.OIDCAuth{Enabled: false},
			},
			Lua: &config.LuaSection{
				Hooks: []config.LuaHooks{
					{
						Location:   "/hooks/demo",
						Method:     "POST",
						ScriptPath: "/tmp/demo.lua",
					},
				},
			},
		}

		assert.NoError(t, ValidateAuthConfiguration(cfg, false))
	})

	t.Run("allows basic auth only", func(t *testing.T) {
		cfg := &config.FileSettings{
			Server: &config.ServerSection{
				BasicAuth: config.BasicAuth{Enabled: true},
				OIDCAuth:  config.OIDCAuth{Enabled: false},
			},
		}

		assert.NoError(t, ensureBackchannelAuthConfigured(cfg, false))
	})

	t.Run("allows oidc auth only", func(t *testing.T) {
		cfg := &config.FileSettings{
			Server: &config.ServerSection{
				BasicAuth: config.BasicAuth{Enabled: false},
				OIDCAuth:  config.OIDCAuth{Enabled: true},
			},
		}

		assert.NoError(t, ensureBackchannelAuthConfigured(cfg, false))
	})

	t.Run("developer mode bypasses auth configuration check", func(t *testing.T) {
		cfg := &config.FileSettings{
			Server: &config.ServerSection{
				BasicAuth: config.BasicAuth{Enabled: false},
				OIDCAuth:  config.OIDCAuth{Enabled: false},
			},
		}

		assert.NoError(t, ensureBackchannelAuthConfigured(cfg, true))
	})
}
