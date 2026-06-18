// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package pluginruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/pluginapi/v1/helpers"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/go-redis/redismock/v9"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const (
	facadeLDAPDN       = "uid=demo,dc=example,dc=test"
	facadeLDAPMail     = "demo@example.test"
	facadeLDAPPoolName = "default"
	facadeMetricResult = "result"
	facadeMetricOK     = "ok"
	facadeIMAPProtocol = "imap"
	facadeIMAPHost     = "192.0.2.10"
	facadeSMTPProtocol = "smtp"
	facadeSMTPHost     = "192.0.2.25"
	facadeRedisKey     = "key"
)

type facadeRedisMockError string

// Error returns the Redis mock error text.
func (err facadeRedisMockError) Error() string {
	return string(err)
}

func TestBackendServerFacadeReturnsSafeImmutableCandidates(t *testing.T) {
	facade := NewBackendServerFacade(func() []*config.BackendServer {
		return []*config.BackendServer{
			{
				Protocol:  facadeIMAPProtocol,
				Host:      facadeIMAPHost,
				Port:      993,
				HAProxyV2: true,
			},
			nil,
		}
	})

	candidates := facade.List(context.Background())
	if len(candidates) != 1 {
		t.Fatalf("List() length = %d, want 1", len(candidates))
	}

	candidate := candidates[0]
	if candidate.Protocol != facadeIMAPProtocol ||
		candidate.Address != facadeIMAPHost ||
		candidate.Port != 993 ||
		!candidate.HAProxyV2 ||
		!candidate.Alive {
		t.Fatalf("candidate = %#v, want safe backend server fields", candidate)
	}

	candidates[0].Address = "198.51.100.99"
	again := facade.List(context.Background())

	if again[0].Address != facadeIMAPHost {
		t.Fatalf("candidate mutation changed host state: %#v", again[0])
	}
}

func TestHostBackendServersUsesCoreCandidateSource(t *testing.T) {
	previous := core.ListBackendServers()

	core.BackendServers.Update([]*config.BackendServer{
		{Protocol: facadeSMTPProtocol, Host: facadeSMTPHost, Port: 25},
	})
	t.Cleanup(func() {
		core.BackendServers.Update(previous)
	})

	host := NewHost()

	candidates := host.BackendServers().List(context.Background())
	if len(candidates) != 1 {
		t.Fatalf("BackendServers().List() length = %d, want 1", len(candidates))
	}

	if candidates[0].Protocol != facadeSMTPProtocol || candidates[0].Address != facadeSMTPHost || candidates[0].Port != 25 {
		t.Fatalf("candidate = %#v, want core backend server", candidates[0])
	}

	candidates[0].Address = "198.51.100.25"

	if got := core.ListBackendServers()[0].Host; got != facadeSMTPHost {
		t.Fatalf("core backend host = %q, want unchanged host", got)
	}
}

func TestRedisFacadeUsesInjectedHandles(t *testing.T) {
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	facade := NewRedisFacade(redisClient)

	mock.ExpectGet("key").SetVal("value")

	if got := facade.Read().Get(context.Background(), "key").Val(); got != "value" {
		t.Fatalf("Read().Get() = %q, want value", got)
	}

	if facade.Write() == nil {
		t.Fatal("Write() returned nil")
	}

	if facade.ReadPipeline() == nil || facade.WritePipeline() == nil {
		t.Fatal("Redis facade returned nil pipeline")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestRedisKeyFacadeBuildsPrefixedClusterSafeKeys(t *testing.T) {
	db, _ := redismock.NewClientMock()
	facade := NewRedisFacade(rediscli.NewTestClient(db), RedisFacadePrefix("ntc:"))

	key := facade.Keys().Key("acct:{acm-demo}alice:stepup")
	if key != "ntc:acct:{acm-demo}alice:stepup" {
		t.Fatalf("Key() = %q, want prefix with hash tag preserved", key)
	}

	keys := facade.Keys().Keys("acct:{left}alice:ips", "acct:{right}alice:fails")
	sameSlot := facade.Keys().SameSlot(keys, "{native}")

	want := []string{"ntc:acct:{native}alice:ips", "ntc:acct:{native}alice:fails"}
	if len(sameSlot) != len(want) || sameSlot[0] != want[0] || sameSlot[1] != want[1] {
		t.Fatalf("SameSlot() = %#v, want %#v", sameSlot, want)
	}
}

func TestRedisScriptFacadeUploadsAndRunsByName(t *testing.T) {
	db, mock := redismock.NewClientMock()
	facade := NewRedisFacade(rediscli.NewTestClient(db))
	ctx := context.Background()

	mock.ExpectScriptLoad("return ARGV[1]").SetVal("sha-demo")

	sha, err := facade.Scripts().Upload(ctx, "demo_script", "return ARGV[1]")
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}

	if sha != "sha-demo" {
		t.Fatalf("Upload() sha = %q, want sha-demo", sha)
	}

	mock.ExpectEvalSha("sha-demo", []string{facadeRedisKey}, "value").SetVal("value")

	result, err := facade.Scripts().Run(ctx, "demo_script", []string{facadeRedisKey}, "value")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result != "value" {
		t.Fatalf("Run() result = %#v, want value", result)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestRedisScriptFacadeRecoversNoScriptOnce(t *testing.T) {
	db, mock := redismock.NewClientMock()
	facade := NewRedisFacade(rediscli.NewTestClient(db))
	ctx := context.Background()

	mock.ExpectScriptLoad("return 1").SetVal("sha-old")

	if _, err := facade.Scripts().Upload(ctx, "recover_script", "return 1"); err != nil {
		t.Fatalf("Upload() error = %v", err)
	}

	mock.ExpectEvalSha("sha-old", []string{facadeRedisKey}).SetErr(facadeRedisMockError("NOSCRIPT No matching script. Please use EVAL."))
	mock.ExpectScriptLoad("return 1").SetVal("sha-new")
	mock.ExpectEvalSha("sha-new", []string{facadeRedisKey}).SetVal(int64(1))

	result, err := facade.Scripts().Run(ctx, "recover_script", []string{facadeRedisKey})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result != int64(1) {
		t.Fatalf("Run() result = %#v, want 1", result)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestRedisScriptFacadeValidatesNames(t *testing.T) {
	db, _ := redismock.NewClientMock()
	facade := NewRedisFacade(rediscli.NewTestClient(db))

	_, err := facade.Scripts().Upload(context.Background(), "bad script", "return 1")
	if !errors.Is(err, pluginapi.ErrInvalidRedisScriptName) {
		t.Fatalf("Upload() error = %v, want ErrInvalidRedisScriptName", err)
	}
}

func TestHostCacheFacadeTTLAndIsolation(t *testing.T) {
	host := NewHost()
	ctx := context.Background()

	cacheA, err := host.Cache("module_a")
	if err != nil {
		t.Fatalf("Cache(module_a) error = %v", err)
	}

	cacheB, err := host.Cache("module_b")
	if err != nil {
		t.Fatalf("Cache(module_b) error = %v", err)
	}

	cacheA.Set(ctx, "short", "value", 20*time.Millisecond)

	if value, ok := cacheA.Get(ctx, "short"); !ok || value != "value" {
		t.Fatalf("Get(short) = %#v, %v; want value", value, ok)
	}

	time.Sleep(30 * time.Millisecond)

	if cacheA.Exists(ctx, "short") {
		t.Fatal("Exists(short) = true after TTL expiry")
	}

	if cacheB.Exists(ctx, "short") {
		t.Fatal("module_b saw module_a cache value")
	}
}

func TestHostCacheFacadeListBatching(t *testing.T) {
	cache := mustHostCache(t, "module_a")
	ctx := context.Background()

	if got := cache.Push(ctx, "batch", "a"); got != 1 {
		t.Fatalf("Push(batch) = %d, want 1", got)
	}

	if got := cache.Push(ctx, "batch", "b"); got != 2 {
		t.Fatalf("Push(batch) = %d, want 2", got)
	}

	values := cache.PopAll(ctx, "batch")
	if len(values) != 2 || values[0] != "a" || values[1] != "b" {
		t.Fatalf("PopAll(batch) = %#v, want [a b]", values)
	}

	if values := cache.PopAll(ctx, "batch"); len(values) != 0 {
		t.Fatalf("PopAll(batch) after clear = %#v, want empty", values)
	}
}

func TestHostCacheFacadeDeleteAndClear(t *testing.T) {
	cache := mustHostCache(t, "module_a")
	ctx := context.Background()

	cache.Set(ctx, "persist", true, 0)

	if !cache.Delete(ctx, "persist") {
		t.Fatal("Delete(persist) = false, want true")
	}

	cache.Set(ctx, "clear", true, 0)
	cache.Clear(ctx)

	if cache.Exists(ctx, "clear") {
		t.Fatal("Exists(clear) = true after Clear")
	}
}

// mustHostCache returns a cache scope or fails the test.
func mustHostCache(t *testing.T, scope string) pluginapi.Cache {
	t.Helper()

	cache, err := NewHost().Cache(scope)
	if err != nil {
		t.Fatalf("Cache(%s) error = %v", scope, err)
	}

	return cache
}

func TestHostCacheFacadeRejectsInvalidScope(t *testing.T) {
	host := NewHost()

	if _, err := host.Cache("bad-scope"); !errors.Is(err, pluginapi.ErrInvalidName) {
		t.Fatalf("Cache(bad-scope) error = %v, want ErrInvalidName", err)
	}
}

func TestDeterministicHelperFacade(t *testing.T) {
	helper := NewDeterministicHelperFacade(HelperOptions{
		AccountTag: helpers.AccountTagOptions{
			UseHashTags:   true,
			HashTagPrefix: "acm-",
		},
		LuaIPv4CIDR: 24,
		LuaIPv6CIDR: 64,
	})

	if tag := helper.AccountTag("alice"); tag != "{acm-6384e2b2184bcbf58eccf10ca7a6563c}" {
		t.Fatalf("AccountTag() = %q, want Lua-compatible account tag", tag)
	}

	if scoped := helper.ScopedIP("lua_generic", "203.0.113.42"); scoped != "203.0.113.0/24" {
		t.Fatalf("ScopedIP() = %q, want /24 network", scoped)
	}

	if helper.IsRoutableIP("10.0.0.1") {
		t.Fatal("IsRoutableIP() returned true for private IPv4")
	}
}

func TestLDAPFacadeMapsSearchAndModifyRequests(t *testing.T) {
	fake := &recordingLDAPExecutor{
		searchResult: pluginapi.LDAPSearchResult{
			Attributes: map[string][]string{backendTestMailAttr: {facadeLDAPMail}},
			Entries: []pluginapi.LDAPEntry{
				{DN: facadeLDAPDN, Attributes: map[string][]string{"cn": {"Demo"}}},
			},
		},
	}
	facade := NewLDAPFacade(fake)

	searchRequest := pluginapi.LDAPSearchRequest{
		PoolName:   facadeLDAPPoolName,
		BaseDN:     "dc=example,dc=test",
		Filter:     "(uid=demo)",
		Scope:      pluginapi.LDAPScopeSub,
		Attributes: []string{backendTestMailAttr},
	}

	searchResult, err := facade.Search(context.Background(), searchRequest)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if got := searchResult.Attributes[backendTestMailAttr][0]; got != facadeLDAPMail {
		t.Fatalf("Search() mail = %q, want %s", got, facadeLDAPMail)
	}

	modifyRequest := pluginapi.LDAPModifyRequest{
		PoolName:   facadeLDAPPoolName,
		DN:         facadeLDAPDN,
		Operation:  pluginapi.LDAPModifyReplace,
		Attributes: map[string][]string{"description": {"updated"}},
	}
	if err := facade.Modify(context.Background(), modifyRequest); err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if len(fake.searchRequests) != 1 || fake.searchRequests[0].Filter != searchRequest.Filter {
		t.Fatalf("mapped search requests = %#v", fake.searchRequests)
	}

	if len(fake.modifyRequests) != 1 || fake.modifyRequests[0].Operation != modifyRequest.Operation {
		t.Fatalf("mapped modify requests = %#v", fake.modifyRequests)
	}
}

func TestMetricsFacadeRejectsUndeclaredLabels(t *testing.T) {
	metrics := NewMetricsFacade("geoip")

	counter, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   "lookups",
		Help:   "lookup count",
		Labels: []string{facadeMetricResult},
	})
	if err != nil {
		t.Fatalf("Counter() error = %v", err)
	}

	counter.Add(context.Background(), 1, pluginapi.LabelValue{Name: "unknown", Value: "bad"})

	if got := metrics.ObservationCount("lookups"); got != 0 {
		t.Fatalf("ObservationCount() = %d, want 0 for rejected labels", got)
	}

	counter.Add(context.Background(), 1, pluginapi.LabelValue{Name: facadeMetricResult, Value: facadeMetricOK})

	if got := metrics.ObservationCount("lookups"); got != 1 {
		t.Fatalf("ObservationCount() = %d, want 1 after declared label", got)
	}
}

func TestMetricsFacadeExportsPluginCounterToPrometheus(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetricsFacadeWithRegisterer("geoip", registry)

	counter, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   "lookup_total",
		Help:   "plugin lookup count",
		Labels: []string{facadeMetricResult},
	})
	if err != nil {
		t.Fatalf("Counter() error = %v", err)
	}

	counter.Add(context.Background(), 2, pluginapi.LabelValue{Name: facadeMetricResult, Value: facadeMetricOK})

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range families {
		if family.GetName() != "nauthilus_plugin_geoip_lookup_total" {
			continue
		}

		for _, metric := range family.GetMetric() {
			if metric.GetCounter().GetValue() != 2 {
				t.Fatalf("counter value = %f, want 2", metric.GetCounter().GetValue())
			}

			if !prometheusMetricHasLabel(metric, "plugin_scope", "geoip") {
				t.Fatalf("counter labels = %#v, want plugin_scope=geoip", metric.GetLabel())
			}

			if !prometheusMetricHasLabel(metric, facadeMetricResult, facadeMetricOK) {
				t.Fatalf("counter labels = %#v, want result=ok", metric.GetLabel())
			}

			return
		}
	}

	t.Fatal("exported plugin counter was not gathered")
}

// prometheusMetricHasLabel reports whether a gathered metric has the expected label pair.
func prometheusMetricHasLabel(metric *dto.Metric, name string, value string) bool {
	for _, label := range metric.GetLabel() {
		if label.GetName() == name && label.GetValue() == value {
			return true
		}
	}

	return false
}

type recordingLDAPExecutor struct {
	searchResult   pluginapi.LDAPSearchResult
	searchRequests []pluginapi.LDAPSearchRequest
	modifyRequests []pluginapi.LDAPModifyRequest
}

func (e *recordingLDAPExecutor) Search(_ context.Context, request pluginapi.LDAPSearchRequest) (pluginapi.LDAPSearchResult, error) {
	e.searchRequests = append(e.searchRequests, request)

	return e.searchResult, nil
}

func (e *recordingLDAPExecutor) Modify(_ context.Context, request pluginapi.LDAPModifyRequest) error {
	e.modifyRequests = append(e.modifyRequests, request)

	return nil
}
