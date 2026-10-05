package pluginruntime

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	authservice "github.com/croessner/nauthilus/v4/server/core/auth"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/go-redis/redismock/v9"
)

// optedInPasswordBackend adds the cache-safety declaration to the counted backend fixture.
type optedInPasswordBackend struct{ *fakePluginBackend }

// PositivePasswordCacheable explicitly permits skipping password verification within the host TTL.
func (optedInPasswordBackend) PositivePasswordCacheable() bool { return true }

// pluginCacheFixture owns a real registry, runner, adapter and mocked Redis transport.
type pluginCacheFixture struct {
	runner *Runner
	cfg    *config.FileSettings
	redis  rediscli.Client
	mock   redismock.ClientMock
	calls  int
}

// newPluginCacheFixture constructs an opted-in module without loading a native binary.
func newPluginCacheFixture(t *testing.T, enabled bool) *pluginCacheFixture {
	t.Helper()

	f := &pluginCacheFixture{}
	module := config.PluginModule{Name: backendTestModuleName, PositivePasswordCache: enabled}
	registry := pluginregistry.NewRegistry()
	registrar := registry.NewRegistrar(module)

	impl := optedInPasswordBackend{&fakePluginBackend{verify: func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
		f.calls++
		return cacheTestPluginResult(), nil
	}}}
	if err := registrar.RegisterBackend(impl); err != nil {
		t.Fatal(err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatal(err)
	}

	f.runner = NewRunnerFromInstances(registry, []pluginloader.ModuleInstance{{Module: module, ModuleName: module.Name, Status: pluginloader.ModuleStatusRegistered}})
	if err := f.runner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = f.runner.Stop(context.Background()) })

	db, mock := redismock.NewClientMock()
	f.redis, f.mock = rediscli.NewTestClient(db), mock
	f.cfg = &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "plugin-cache:", PosCacheTTL: time.Minute}, Backends: []*config.Backend{
		mustBackendSelector(t, "cache"), mustBackendSelector(t, "plugin("+backendTestQualified+")"),
	}}, Plugins: &config.PluginsSection{Modules: []config.PluginModule{module}}}

	return f
}

// cacheTestPluginResult exercises the complete value-only backend result contract.
func cacheTestPluginResult() pluginapi.BackendResult {
	return pluginapi.BackendResult{
		Account: backendTestAccount, AccountField: backendTestAccountAttr, Authenticated: true, UserFound: true,
		Attributes:    map[string][]string{backendTestAccountAttr: {backendTestAccount}, "uid": {"stable-id"}, "display": {"Alice"}, "totp": {"test-only"}, "recovery": {"test-only"}},
		Identity:      pluginapi.BackendIdentityResult{UniqueUserIDField: "uid", DisplayNameField: "display", TOTPSecretField: "totp", TOTPRecoveryField: "recovery", Groups: []string{"mail"}, GroupDistinguishedNames: []string{"cn=mail"}},
		BackendServer: &pluginapi.BackendServerRef{Name: "mail", Address: "192.0.2.1", Port: "143", Protocol: "imap", Authority: "tenant"},
		Status:        &pluginapi.StatusMessage{Code: "ok", MessageKey: backendTestStatusKey, DefaultText: backendTestStatusText},
		Facts:         []pluginapi.PolicyFact{{Attribute: backendTestRiskAttr, Value: float64(2)}, {Attribute: "plugin.customer.passdb.enabled", Value: true}},
	}
}

// auth creates a fresh request with the same registry and Redis transport.
func (f *pluginCacheFixture) auth(t *testing.T, password string) *core.AuthState {
	t.Helper()
	auth := newBackendTestAuth(t)
	auth = core.NewAuthStateFromContextWithDeps(auth.Request.HTTPClientContext, core.AuthDeps{
		Cfg: f.cfg, Redis: f.redis, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		PluginBackendFactory: NewBackendManagerFactory(f.runner),
	}).(*core.AuthState)
	auth.Request.Username = backendTestAccount
	auth.Request.Password = secret.New(password)
	auth.Request.Protocol = config.NewProtocol(backendTestProtocolIMAP)

	return auth
}

// cacheKey returns the single module/backend/account key shared by write and purge paths.
func (f *pluginCacheFixture) cacheKey() string {
	return f.cfg.Server.Redis.Prefix + definitions.RedisUserPositiveCachePrefix + backend.PluginPasswordCacheName(backendTestQualified) + ":" + backendTestAccount
}

// cacheHash is the exact Redis wire representation, with a prepared digest rather than a raw password.
func (f *pluginCacheFixture) cacheHash(auth *core.AuthState, result *core.PassDBResult) map[string]string {
	return map[string]string{"backend": fmt.Sprint(int(definitions.BackendPlugin)), "backend_name": backendTestQualified,
		"password": util.PreparedPasswordHashWithConfig(auth.Request.Password, f.cfg), "plugin_result": result.PluginCachePayload}
}

// lookup exercises the real cache backend including scoped account mapping and runtime admission.
func (f *pluginCacheFixture) lookup(t *testing.T, auth *core.AuthState, hash map[string]string) *core.PassDBResult {
	t.Helper()
	f.mock.Regexp().ExpectHGet(".*", ".*").SetVal(backendTestAccount)

	if config.PluginPasswordCacheEnabled(f.cfg, backendTestQualified) {
		f.mock.ExpectHGetAll(f.cacheKey()).SetVal(hash)
	}

	result, err := core.CachePassDB(auth)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { core.PutPassDBResultToPool(result) })

	return result
}

func TestPluginPositiveCacheSecondLoginPreservesResult(t *testing.T) {
	f := newPluginCacheFixture(t, true)
	first := f.auth(t, backendTestPassword)
	manager := &BackendManager{runner: f.runner, qualifiedName: backendTestQualified}

	result, err := manager.PassDB(first)
	if err != nil {
		t.Fatal(err)
	}
	defer core.PutPassDBResultToPool(result)

	if result.PluginCachePayload == "" {
		t.Fatal("successful result was not admitted to positive cache")
	}

	f.mock.Regexp().ExpectHGet(".*", ".*").SetVal(backendTestAccount)

	if err := core.ProcessPassDBResult(first.Request.HTTPClientContext, result, first, &core.PassDBMap{}); err != nil {
		t.Fatal(err)
	}

	first.Runtime.UsedPassDBBackend = definitions.BackendPlugin
	hash := f.cacheHash(first, result)
	fields := map[string]any{"backend": int(definitions.BackendPlugin), "backend_name": backendTestQualified, "password": hash["password"], "plugin_result": hash["plugin_result"]}
	f.mock.ExpectHSet(f.cacheKey(), fields).SetVal(4)
	f.mock.ExpectExpire(f.cacheKey(), time.Minute).SetVal(true)

	if err := (authservice.DefaultCacheService{}).OnSuccess(first, backendTestAccount); err != nil {
		t.Fatal(err)
	}

	second := f.auth(t, backendTestPassword)

	hit := f.lookup(t, second, hash)
	if !reflect.DeepEqual(result, hit) {
		t.Fatalf("cache changed plugin result: live=%#v cached=%#v", result, hit)
	}

	if f.calls != 1 {
		t.Fatalf("plugin calls=%d, want 1", f.calls)
	}

	if second.Runtime.StatusMessage != first.Runtime.StatusMessage || second.Runtime.RemoteBackendRef != first.Runtime.RemoteBackendRef {
		t.Fatal("status or backend server changed on cache hit")
	}

	wrong := f.lookup(t, f.auth(t, "wrong-password"), hash)
	if wrong.Authenticated || wrong.UserFound {
		t.Fatal("wrong password used positive cache")
	}
}

func TestPluginPositiveCacheOptOutAndScope(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			f := newPluginCacheFixture(t, enabled)
			auth := f.auth(t, backendTestPassword)
			manager := &BackendManager{runner: f.runner, qualifiedName: backendTestQualified}

			result, err := manager.PassDB(auth)
			if err != nil {
				t.Fatal(err)
			}
			defer core.PutPassDBResultToPool(result)

			if (result.PluginCachePayload != "") != enabled {
				t.Fatal("operator opt-in not respected")
			}

			if !enabled {
				second, err := manager.PassDB(f.auth(t, backendTestPassword))
				if err != nil {
					t.Fatal(err)
				}

				core.PutPassDBResultToPool(second)

				if f.calls != 2 {
					t.Fatal("opt-out skipped plugin verification")
				}
			}

			assertPluginCacheRejectsOtherScopes(t, f, auth, result)
		})
	}
}

// assertPluginCacheRejectsOtherScopes checks request isolation even when aliases resolve to the same account.
func assertPluginCacheRejectsOtherScopes(t *testing.T, f *pluginCacheFixture, auth *core.AuthState, result *core.PassDBResult) {
	t.Helper()

	cases := []struct {
		name   string
		change func(*core.AuthState)
	}{
		{"username", func(other *core.AuthState) { other.Request.Username = "alias" }},
		{"protocol", func(other *core.AuthState) { other.Request.Protocol = config.NewProtocol("smtp") }},
		{"oidc_client", func(other *core.AuthState) { other.Request.OIDCCID = "other-client" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			other := f.auth(t, backendTestPassword)
			tc.change(other)

			if hit := f.lookup(t, other, f.cacheHash(auth, result)); hit.Authenticated || hit.UserFound {
				t.Fatal("cache crossed request scope")
			}
		})
	}
}

func TestPluginPositiveCacheExcludesLossyFacts(t *testing.T) {
	f := newPluginCacheFixture(t, true)
	manager := &BackendManager{runner: f.runner, qualifiedName: backendTestQualified}
	result := cacheTestPluginResult()

	result.Facts[0].Value = int64(9007199254740993)
	if manager.encodePositivePasswordCache(f.auth(t, backendTestPassword), result) != "" {
		t.Fatal("lossy numeric fact was cached")
	}
}

func TestPluginPositiveCacheOptInRequiresRestart(t *testing.T) {
	classifier := ReloadClassifier{}
	current := config.PluginModule{Name: backendTestModuleName}
	next := current
	next.PositivePasswordCache = true

	change, err := classifier.classifyModule(current, next)
	if err == nil {
		t.Fatal("cache admission changed without restart error")
	}

	if change.result != ReloadResultRestartRequired {
		t.Fatalf("cache opt-in reload result=%s", change.result)
	}
}

func TestPluginPositiveCachePurge(t *testing.T) {
	f := newPluginCacheFixture(t, true)
	auth := f.auth(t, backendTestPassword)
	// Pure plugin configuration has no LDAP/Lua protocol list; purge must still find its namespace.
	f.mock.MatchExpectationsInOrder(false)
	f.mock.Regexp().ExpectHGet(".*", ".*").SetVal(backendTestAccount)
	f.mock.Regexp().ExpectHGet(".*", ".*").SetVal(backendTestAccount)
	f.mock.ExpectDel(f.cacheKey()).SetVal(1)
	(authservice.DefaultCacheService{}).Purge(auth, backendTestAccount)

	if err := f.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	// An evicted/expired hash is a miss, and password verification runs again.
	hit := f.lookup(t, auth, map[string]string{})
	if hit.Authenticated {
		t.Fatal("purged cache authenticated request")
	}

	manager := &BackendManager{runner: f.runner, qualifiedName: backendTestQualified}

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatal(err)
	}

	core.PutPassDBResultToPool(result)

	if f.calls != 1 {
		t.Fatalf("calls after purge=%d", f.calls)
	}
}
