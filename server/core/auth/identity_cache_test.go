package auth

import (
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

// TestIdentityCachePurgeInvalidatesAliasAndCanonicalAccount invalidates both submitted and mapped identities.
func TestIdentityCachePurgeInvalidatesAliasAndCanonicalAccount(t *testing.T) {
	cfg := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:", IdentityCache: &config.IdentityCache{Enabled: true}}},
		LDAP: &config.LDAPSection{Search: []config.LDAPSearchProtocol{{Protocols: []string{"jmap"}, CacheName: "mail"}}}}
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)
	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{Cfg: cfg, Logger: slog.Default(), Redis: client}).(*core.AuthState)
	auth.Request.HTTPClientRequest = nil

	mock.MatchExpectationsInOrder(false)
	mock.Regexp().ExpectSet("test:UCI:epoch", ".+", 0).SetVal("OK")
	mock.ExpectHGet(rediscli.GetUserHashKey("test:", "alias"), accountcache.GetAccountMappingField("alias", "jmap", "")).SetVal("account")

	for _, name := range []string{"alias", "account"} {
		mock.ExpectDel("test:UCI:mail:" + name).SetVal(1)
		mock.ExpectDel("test:UCP:__default__:" + name).SetVal(1)
	}

	DefaultCacheService{}.Purge(auth, "alias")
	assert.NoError(t, mock.ExpectationsWereMet())
}
