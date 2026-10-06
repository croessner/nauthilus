package core

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/security"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

// identityLookupQueue returns detached backend data without network LDAP dependencies.
type identityLookupQueue struct{ calls int }

// Push serves the minimal identity result expected by the LDAP lookup pipeline.
func (q *identityLookupQueue) Push(request *bktype.LDAPRequest, _ int) {
	q.calls++

	if request.Filter == "(member=%{user_dn})" {
		request.LDAPReplyChan <- &bktype.LDAPReply{Result: bktype.AttributeMapping{
			definitions.DistinguishedName: {"cn=mail,dc=example,dc=test"}, "cn": {"mail"},
		}}

		return
	}

	request.LDAPReplyChan <- &bktype.LDAPReply{Result: bktype.AttributeMapping{
		definitions.DistinguishedName: {"uid=alice,dc=example,dc=test"}, "uid": {"alice"}, "groups": {"mail"},
	}}
}

// newIdentityLookupTest wires a real LDAP manager to hermetic Redis and LDAP doubles.
func newIdentityLookupTest(t *testing.T) (*ldapManagerImpl, *AuthState, redismock.ClientMock, *identityLookupQueue) {
	t.Helper()
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.IdentityCache = &config.IdentityCache{Enabled: true, TTL: time.Minute}
	cfg.LDAP = &config.LDAPSection{Config: &config.LDAPConf{}, Search: []config.LDAPSearchProtocol{{
		Protocols: []string{definitions.ProtoIMAP}, CacheName: "mail", BaseDN: "dc=example,dc=test", Scope: "sub",
		LDAPFilter: config.LDAPFilter{User: "(uid=%s)"}, LDAPAttributeMapping: config.LDAPAttributeMapping{AccountField: "uid"}, Attributes: []string{"uid", "groups"},
	}}}
	auth, _, _ := newCurrentBehaviorAuthState(t, cfg)
	db, mock := redismock.NewClientMock()
	auth.deps.Redis = rediscli.NewTestClientWithSecurity(db, security.NewManager(secret.New("1234567890123456")))
	auth.Request.NoAuth = true
	auth.Request.Password = secret.Value{}
	queue := &identityLookupQueue{}
	auth.deps.LDAPQueue = queue

	return &ldapManagerImpl{poolName: definitions.DefaultBackendName, deps: auth.deps}, auth, mock, queue
}

// TestIdentityCacheLDAPMissThenHitPreservesRawSnapshot reuses LDAP results without retaining downstream mutations.
func TestIdentityCacheLDAPMissThenHitPreservesRawSnapshot(t *testing.T) {
	lm, auth, mock, queue := newIdentityLookupTest(t)
	seedIdentityMembershipCache(t, lm, auth)

	key := "parity:UCI:mail:" + auth.Request.Username

	mock.ExpectGet("parity:UCI:epoch").SetVal("epoch")
	mock.ExpectGet(key).RedisNil()

	var stored string

	mock.CustomMatch(func(expected, actual []any) error {
		if len(actual) != len(expected) || actual[0] != "set" || actual[1] != key {
			return fmt.Errorf("unexpected SET arguments")
		}

		stored = actual[2].(string)
		if !reflect.DeepEqual(actual[3:], expected[3:]) {
			return fmt.Errorf("missing fixed TTL")
		}

		return nil
	}).ExpectSet(key, "snapshot", time.Minute).SetVal("OK")

	first, err := lm.PassDB(auth)
	if !assert.NoError(t, err) || !assert.NotNil(t, first) {
		return
	}

	assert.Equal(t, 2, queue.calls)
	assert.False(t, first.IdentityCacheHit)
	// Simulate request-specific subject/policy mutation after the raw backend has returned.
	first.Attributes["uid"] = []any{"mutated"}

	mock.ExpectGet("parity:UCI:epoch").SetVal("epoch")
	mock.ExpectGet(key).SetVal(stored)
	mock.ExpectGet("parity:UCI:epoch").SetVal("epoch")

	second, err := lm.PassDB(auth)
	if !assert.NoError(t, err) || !assert.NotNil(t, second) {
		return
	}

	assert.Equal(t, 2, queue.calls)
	assert.True(t, second.IdentityCacheHit)
	assert.Equal(t, []any{"alice"}, second.Attributes["uid"])
	assert.Equal(t, []string{"mail"}, second.Groups)
	auth.applyFoundPassDBRuntime(second, &PassDBMap{backend: definitions.BackendLDAP})
	assert.Equal(t, definitions.BackendCache, auth.Runtime.UsedPassDBBackend)
	assert.Equal(t, definitions.BackendLDAP, auth.Runtime.SourcePassDBBackend)
	assert.Contains(t, auth.Runtime.AdditionalLogs, "identity")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestIdentityCacheEligibilityNeverAcceptsPasswordOrBrowserEvidence keeps credential and mutable IdP flows outside UCI.
func TestIdentityCacheEligibilityNeverAcceptsPasswordOrBrowserEvidence(t *testing.T) {
	for _, name := range []string{"password", "browser", "disabled", "master"} {
		t.Run(name, func(t *testing.T) {
			lm, auth, mock, _ := newIdentityLookupTest(t)

			switch name {
			case "password":
				auth.Request.NoAuth = false
			case "browser":
				auth.Request.Service = definitions.ServIDP
			case "disabled":
				auth.Cfg().GetServer().GetRedis().IdentityCache.Enabled = false
			case "master":
				auth.Runtime.MasterUserMode = true
			}

			assert.Nil(t, lm.newIdentityCacheLookup(auth))
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestIdentityCacheRedisFailureFallsBackToLDAP preserves lookup availability when Redis fails.
func TestIdentityCacheRedisFailureFallsBackToLDAP(t *testing.T) {
	lm, auth, mock, queue := newIdentityLookupTest(t)
	mock.ExpectGet("parity:UCI:epoch").SetErr(errors.New("redis unavailable"))

	result, err := lm.PassDB(auth)
	assert.NoError(t, err)
	assert.True(t, result.UserFound)
	assert.Equal(t, 1, queue.calls)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestIdentityCacheScopeUsesEffectiveLDAPContext binds snapshots to inputs that affect LDAP results.
func TestIdentityCacheScopeUsesEffectiveLDAPContext(t *testing.T) {
	lm, auth, _, _ := newIdentityLookupTest(t)
	protocol, _ := auth.Cfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName)
	original, err := lm.identityCacheScope(auth, protocol)
	assert.NoError(t, err)

	auth.Request.XClientPort = "45678"
	same, err := lm.identityCacheScope(auth, protocol)
	assert.NoError(t, err)
	assert.Equal(t, original, same, "unused ephemeral port must not prevent hits")

	auth.Request.OIDCCID = "another-client"
	other, err := lm.identityCacheScope(auth, protocol)
	assert.NoError(t, err)
	assert.NotEqual(t, original, other)

	protocol.User = "(&(uid=%s)(port=%{remote_port}))"
	portScope, _ := lm.identityCacheScope(auth, protocol)
	auth.Request.XClientPort = "12345"
	changedPortScope, _ := lm.identityCacheScope(auth, protocol)
	assert.NotEqual(t, portScope, changedPortScope)
}

// TestIdentityCacheLDAPGroupsBypassMembershipCache prevents stale local memberships from extending UCI freshness.
func TestIdentityCacheLDAPGroupsBypassMembershipCache(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		t.Run(fmt.Sprintf("seeded=%t", seeded), func(t *testing.T) {
			lm, auth, _, _ := newIdentityLookupTest(t)
			auth.Request.Username = t.Name()
			protocol, err := auth.Cfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName)
			assert.NoError(t, err)

			protocol.Groups = config.LDAPGroups{Strategy: "member_of", Attribute: "groups"}
			attributes := bktype.AttributeMapping{definitions.DistinguishedName: {"uid=alice,dc=example,dc=test"}, "uid": {"alice"}, "groups": {"fresh"}}
			_, _, key, ttl := lm.groupResolutionCacheSettings(auth, protocol, protocol.GetGroups(), attributes, "uid")

			t.Cleanup(func() { ldapMembershipCache.Delete(key) })

			if seeded {
				storeLDAPGroupResolution(key, time.Minute, []string{"stale"}, nil)
			}

			groups, _ := lm.resolveGroups(auth, protocol, attributes, "uid", auth.Logger())
			assert.Equal(t, []string{"fresh"}, groups)
			assert.Zero(t, ttl, "UCI must be the only membership cache for eligible identity lookups")

			cached, _, found := cachedLDAPGroupResolution(key, time.Minute)
			assert.Equal(t, seeded, found, "identity lookups must not populate the local membership cache")

			if seeded {
				assert.Equal(t, []string{"stale"}, cached, "identity lookups must not overwrite the local membership cache")
			}
		})
	}
}

// seedIdentityMembershipCache primes stale local group data while enabling real group-search dispatch.
func seedIdentityMembershipCache(t *testing.T, lm *ldapManagerImpl, auth *AuthState) {
	t.Helper()

	protocol, err := auth.Cfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName)
	if err != nil {
		t.Fatal(err)
	}

	protocol.Groups = config.LDAPGroups{Strategy: "search", Filter: "(member=%{user_dn})"}
	attributes := bktype.AttributeMapping{definitions.DistinguishedName: {"uid=alice,dc=example,dc=test"}, "uid": {"alice"}}
	_, _, key, _ := lm.groupResolutionCacheSettings(auth, protocol, protocol.GetGroups(), attributes, "uid")
	storeLDAPGroupResolution(key, time.Minute, []string{"stale"}, nil)
	t.Cleanup(func() { ldapMembershipCache.Delete(key) })
}

// TestIdentityCacheExclusionsPreserveMembershipCache retains existing group caching for password and IdP requests.
func TestIdentityCacheExclusionsPreserveMembershipCache(t *testing.T) {
	for _, mode := range []string{"password", "browser"} {
		t.Run(mode, func(t *testing.T) {
			lm, auth, _, queue := newIdentityLookupTest(t)
			seedIdentityMembershipCache(t, lm, auth)

			if mode == "password" {
				auth.Request.NoAuth = false
			} else {
				auth.Request.Service = definitions.ServIDP
			}

			protocol, err := auth.Cfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName)
			assert.NoError(t, err)

			attributes := bktype.AttributeMapping{definitions.DistinguishedName: {"uid=alice,dc=example,dc=test"}, "uid": {"alice"}}
			groups, _ := lm.resolveGroups(auth, protocol, attributes, "uid", auth.Logger())
			assert.Equal(t, []string{"stale"}, groups)
			assert.Zero(t, queue.calls, "excluded requests retain the existing local membership cache")
		})
	}
}
