package accountcache

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/stretchr/testify/assert"
)

func TestGetAccountMappingField(t *testing.T) {
	tests := []struct {
		username     string
		protocol     string
		oidcClientID string
		expected     string
	}{
		{"user1", "imap", "", "user1|imap|"},
		{"user1", "keycloak", "clientA", "user1|keycloak|clientA"},
		{"user2", "", "", "user2||"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, GetAccountMappingField(tt.username, tt.protocol, tt.oidcClientID))
		})
	}
}

func TestManager_GetSet(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				AccountLocalCache: config.AccountLocalCache{
					Enabled:  true,
					Shards:   1,
					TTL:      5 * time.Minute,
					CleanUp:  1 * time.Minute,
					MaxItems: 100,
				},
			},
		},
	}

	mgr := NewManager(cfg)

	username := "testuser"

	// Set for IMAP
	mgr.Set(cfg, username, "imap", "", "account_imap")

	// Set for Keycloak
	mgr.Set(cfg, username, "keycloak", "cid123", "account_kc")

	// Get IMAP
	val, ok := mgr.Get(username, "imap", "")
	assert.True(t, ok)
	assert.Equal(t, "account_imap", val)

	// Get Keycloak
	val, ok = mgr.Get(username, "keycloak", "cid123")
	assert.True(t, ok)
	assert.Equal(t, "account_kc", val)

	// Get Non-existent
	val, ok = mgr.Get(username, "pop3", "")
	assert.False(t, ok)
	assert.Empty(t, val)
}

func TestManager_Disabled(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				AccountLocalCache: config.AccountLocalCache{
					Enabled:  false,
					Shards:   1,
					TTL:      5 * time.Minute,
					CleanUp:  1 * time.Minute,
					MaxItems: 100,
				},
			},
		},
	}

	mgr := NewManager(cfg)

	username := "testuser"
	mgr.Set(cfg, username, "imap", "", "account_imap")

	// Should not be in cache because it was disabled during Set
	val, ok := mgr.Get(username, "imap", "")
	assert.False(t, ok)
	assert.Empty(t, val)
}
