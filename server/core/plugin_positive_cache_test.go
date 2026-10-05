package core

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

// cacheablePluginManager models an explicitly opted-in plugin backend.
type cacheablePluginManager struct{ testBackendManagerImpl }

// PositivePasswordCacheEnabled reports the jointly approved cache contract.
func (*cacheablePluginManager) PositivePasswordCacheEnabled() bool { return true }

func TestPluginPositiveCacheExecutionPlan(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Backends = []*config.Backend{
		mustBackendPlanConfig(t, "cache"),
		mustBackendPlanConfig(t, "plugin(example.identity)"),
	}
	auth, _, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.deps.PluginBackendFactory = func(string, AuthDeps) BackendManager { return &cacheablePluginManager{} }

	plan := auth.buildBackendExecutionPlan()
	if !plan.positivePasswordCacheEnabled(definitions.BackendPlugin) {
		t.Fatal("explicitly opted-in plugin backend is excluded from positive password caching")
	}
}

// pluginCachePipelineVerifier executes the production Redis/backend verification chain.
type pluginCachePipelineVerifier struct{}

// Verify delegates to the real password pipeline so cache hits become host credential evidence.
func (pluginCachePipelineVerifier) Verify(ctx *gin.Context, auth *AuthState, plan []*PassDBMap) (*PassDBResult, error) {
	return VerifyPasswordPipeline(ctx, auth, plan)
}

// guardedPluginCacheManager restores a deterministic backend snapshot and rejects uncached credentials.
type guardedPluginCacheManager struct {
	cacheablePluginManager
	calls    int
	verified bool
}

// RestorePositivePasswordCache returns the fixture's original backend evidence.
func (*guardedPluginCacheManager) RestorePositivePasswordCache(auth *AuthState, _ string) (*PassDBResult, error) {
	result := GetPassDBResultFromPool()
	result.Authenticated, result.UserFound = true, true
	result.Backend, result.BackendName = definitions.BackendPlugin, "example.identity"
	result.AccountField, result.Account = "uid", auth.Request.Username
	result.Attributes = map[string][]any{"uid": {auth.Request.Username}}
	result.PluginCachePayload = "cached-original"

	return result, nil
}

// PassDB records a miss and returns a failed credential that subject providers must not raise.
func (m *guardedPluginCacheManager) PassDB(auth *AuthState) (*PassDBResult, error) {
	m.calls++
	result, err := m.RestorePositivePasswordCache(auth, "")

	result.Authenticated = m.verified
	if !m.verified {
		result.PluginCachePayload = ""
	}

	return result, err
}

func TestPluginPositiveCacheFSMHostEvidence(t *testing.T) {
	for _, hit := range []bool{true, false} {
		t.Run(fmt.Sprint(hit), func(t *testing.T) {
			h := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate, pluginCachePipelineVerifier{}, testLuaSubject{})
			auth := h.execution.auth
			h.cfg.Server.Backends = []*config.Backend{mustBackendPlanConfig(t, "cache"), mustBackendPlanConfig(t, "plugin(example.identity)")}
			auth.Runtime.MonitoringFlags = []definitions.Monitoring{definitions.MonInMemory}
			manager := &guardedPluginCacheManager{}
			auth.deps.PluginBackendFactory = func(string, AuthDeps) BackendManager { return manager }
			db, mock := redismock.NewClientMock()
			auth.deps.Redis = rediscli.NewTestClient(db)

			mock.MatchExpectationsInOrder(false)

			for range 3 {
				mock.Regexp().ExpectHGet(".*", ".*").SetVal(auth.Request.Username)
			}

			hash := preparedCredentialDigest(auth)
			if !hit {
				hash = strings.Repeat("0", 64)
			}

			key := auth.positivePasswordCacheKey(backend.PluginPasswordCacheName("example.identity"), auth.Request.Username)
			mock.ExpectHGetAll(key).SetVal(map[string]string{"backend": fmt.Sprint(int(definitions.BackendPlugin)), "backend_name": "example.identity", "password": hash, "plugin_result": "cached-original"})
			h.runBackendPlan(t, auth.buildBackendExecutionPlan())
			h.patchNativeSubjectAuthenticated(t)
			h.completeSubject()
			result := h.finalize(t, policy.StageAuthDecision, policy.DecisionPermit, policy.FSMEventMarkerAuthPermit)
			assertPluginCacheFSMResult(t, hit, result, manager.calls)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPluginPositiveCacheAdminFlushIncludesPluginOnlyConfig(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Backends = []*config.Backend{mustBackendPlanConfig(t, "cache"), mustBackendPlanConfig(t, "plugin(example.identity)")}
	keys := config.NewStringSet()
	addProtocolPositiveCacheKeys(keys, cfg, restAdminDeps{}, "test:", "alice")

	want := "test:" + definitions.RedisUserPositiveCachePrefix + backend.PluginPasswordCacheName("example.identity") + ":alice"
	if !slices.Contains(keys.GetStringSlice(), want) {
		t.Fatalf("flush keys %v lack plugin key", keys)
	}
}

// assertPluginCacheFSMResult checks both frozen host authority and backend invocation counts.
func assertPluginCacheFSMResult(t *testing.T, hit bool, result authnApplicationResult, calls int) {
	t.Helper()

	if hit {
		if result.auth.Decision != AuthDecisionOK || calls != 0 {
			t.Fatal("cache evidence failed or plugin was called")
		}

		return
	}

	if result.auth.Decision == AuthDecisionOK || calls != 1 {
		t.Fatal("subject raised a failed credential or plugin was skipped")
	}
}

func TestPluginPositiveCacheTypedProviderPlan(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Backends = []*config.Backend{
		mustBackendPlanConfig(t, "cache"), mustBackendPlanConfig(t, "ldap"), mustBackendPlanConfig(t, "plugin(example.identity)"),
	}
	auth, _, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.deps.PluginBackendFactory = func(string, AuthDeps) BackendManager { return &guardedPluginCacheManager{} }

	plan, err := auth.buildAuthnTypedBackendExecutionPlan(policy.AuthnProviderPluginBackendOrder)
	if err != nil {
		t.Fatal(err)
	}

	if len(plan.passDBs) != 2 || plan.passDBs[0].backend != definitions.BackendCache || plan.passDBs[1].backend != definitions.BackendPlugin {
		t.Fatal("typed plugin provider omitted its explicitly opted-in cache or included another backend")
	}

	if !plan.positivePasswordCacheEnabled(definitions.BackendPlugin) {
		t.Fatal("typed plugin provider cannot write positive cache")
	}
}

func TestPluginPositiveCachePreservesLegacyPluginPrefix(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	auth, _, mock := newCurrentBehaviorAuthState(t, cfg)
	legacyName := "plugin.example.identity"

	mock.Regexp().ExpectHGet(".*", ".*").SetVal(auth.Request.Username)
	mock.ExpectHGetAll(auth.positivePasswordCacheKey(legacyName, auth.Request.Username)).SetVal(map[string]string{
		"backend": fmt.Sprint(int(definitions.BackendLDAP)), "password": preparedCredentialDigest(auth),
		"account_field": "uid", "attributes": `{"uid":["legacy-user"]}`,
	})

	result, err := cachePassDB(auth, []string{legacyName})
	if err != nil {
		t.Fatal(err)
	}
	defer PutPassDBResultToPool(result)

	if !result.Authenticated || result.Backend != definitions.BackendLDAP {
		t.Fatal("printable LDAP/Lua cache name was misclassified as a plugin namespace")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// pluginSnapshotCache records the exact finalization payload while retaining failure accounting.
type pluginSnapshotCache struct {
	authnFSMGuardRecordingCache
	saved *bktype.PositivePasswordCache
}

// OnSuccess captures the production snapshot selected by processFinalAuthCache.
func (c *pluginSnapshotCache) OnSuccess(auth *AuthState, _ string) error {
	c.saved = auth.CreatePositivePasswordCache()
	return nil
}

// newTypedPluginCacheHarness supplies account mappings and only a plugin cache response to the typed provider.
func newTypedPluginCacheHarness(t *testing.T, manager *guardedPluginCacheManager, stored *bktype.PositivePasswordCache) (*authnFSMGuardHarness, redismock.ClientMock) {
	t.Helper()
	h := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate, pluginCachePipelineVerifier{}, testLuaSubject{})
	auth := h.execution.auth
	h.cfg.Server.Backends = []*config.Backend{mustBackendPlanConfig(t, "cache"), mustBackendPlanConfig(t, "ldap"), mustBackendPlanConfig(t, "plugin(example.identity)")}
	auth.Runtime.MonitoringFlags = []definitions.Monitoring{definitions.MonInMemory}
	auth.deps.PluginBackendFactory = func(string, AuthDeps) BackendManager { return manager }
	db, mock := redismock.NewClientMock()
	auth.deps.Redis = rediscli.NewTestClient(db)

	mock.MatchExpectationsInOrder(false)

	for range 3 {
		mock.Regexp().ExpectHGet(".*", ".*").SetVal(auth.Request.Username)
	}

	values := map[string]string{}
	if stored != nil {
		values = map[string]string{"backend": fmt.Sprint(int(stored.Backend)), "backend_name": stored.BackendName, "password": stored.Password, "plugin_result": stored.PluginResult}
	}

	key := auth.positivePasswordCacheKey(backend.PluginPasswordCacheName("example.identity"), auth.Request.Username)
	mock.ExpectHGetAll(key).SetVal(values)

	return h, mock
}

func TestPluginPositiveCacheTypedProviderColdAndWarm(t *testing.T) {
	manager := &guardedPluginCacheManager{verified: true}

	cache := &pluginSnapshotCache{}
	for range 2 {
		h, mock := newTypedPluginCacheHarness(t, manager, cache.saved)

		h.execution.auth.deps.HostServices.cache = cache
		if _, err := h.execution.prepareTypedBackendProvider(policy.AuthnProviderPluginBackendOrder); err != nil {
			t.Fatal(err)
		}

		h.patchNativeSubjectAuthenticated(t)
		h.completeSubject()

		result := h.finalize(t, policy.StageAuthDecision, policy.DecisionPermit, policy.FSMEventMarkerAuthPermit)
		if result.auth.Decision != AuthDecisionOK {
			t.Fatal("typed plugin provider did not permit verified credential")
		}

		if cache.saved == nil || cache.saved.PluginResult == "" {
			t.Fatal("typed provider omitted final positive cache write")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}

	if manager.calls != 1 {
		t.Fatalf("two typed-provider logins called plugin %d times, want 1", manager.calls)
	}
}
