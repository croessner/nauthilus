// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/bruteforce"
	"github.com/croessner/nauthilus/v4/server/bruteforce/l1"
	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	bf "github.com/croessner/nauthilus/v4/server/model/bruteforce"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const (
	natClientIP    = "198.51.100.17"
	natRuleName    = "nat-network"
	natRuleNetwork = "198.51.100.0/24"
)

// recordingBruteForceEvents captures emitted brute-force events in order.
type recordingBruteForceEvents struct {
	events []pluginapi.BruteForceEvent
	mu     sync.Mutex
}

// EmitBruteForceEvent records one event.
func (r *recordingBruteForceEvents) EmitBruteForceEvent(_ context.Context, event pluginapi.BruteForceEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// take returns and clears the recorded events.
func (r *recordingBruteForceEvents) take() []pluginapi.BruteForceEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	events := r.events
	r.events = nil

	return events
}

// bruteForceEventWorld shares one miniredis and emitter between synthetic requests.
type bruteForceEventWorld struct {
	cfg      *config.FileSettings
	storage  *miniredis.Miniredis
	redis    rediscli.Client
	events   *recordingBruteForceEvents
	sequence int
}

// newBruteForceEventWorld configures one IPv4 /24 rule that bans after three counted failures.
func newBruteForceEventWorld(t *testing.T, rules ...config.BruteForceRule) *bruteForceEventWorld {
	t.Helper()

	cfg := hardCutBruteForceConfig(t)
	cfg.BruteForce.AllowedUniqueWrongPWHashes = 1

	if len(rules) == 0 {
		rules = []config.BruteForceRule{{
			Name: natRuleName, Period: time.Hour, CIDR: 24, IPv4: true, FailedRequests: 3, BanTime: time.Hour,
		}}
	}

	cfg.BruteForce.Buckets = rules

	storage := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: storage.Addr()})

	t.Cleanup(func() { _ = db.Close() })

	redisClient := rediscli.NewTestClient(db)

	// The process-wide L1 decision cache would otherwise replay bans of earlier scenarios as orphan hits.
	l1.GetEngine().Clear()

	rediscli.ClearScriptCache()

	if err := rediscli.UploadAllScripts(t.Context(), nil, redisClient); err != nil {
		t.Fatalf("upload scripts: %v", err)
	}

	return &bruteForceEventWorld{cfg: cfg, storage: storage, redis: redisClient, events: &recordingBruteForceEvents{}}
}

// request builds one synthetic request; an empty account models a login name without account mapping.
func (w *bruteForceEventWorld) request(t *testing.T, username, account, password, clientIP string) (*AuthState, *gin.Context) {
	t.Helper()

	auth, ctx, _ := newCurrentBehaviorAuthState(t, w.cfg)
	w.sequence++

	auth.deps.Redis = w.redis
	auth.deps.Tolerate = tolerate.NewTolerateWithDeps(w.cfg, auth.Logger(), w.redis, 0)
	auth.deps.BruteForceEvents = w.events
	auth.Runtime.GUID = fmt.Sprintf("request-%02d", w.sequence)
	auth.Request.Username = username
	auth.Request.Password = secret.New(password)
	auth.Request.ClientIP = clientIP

	if account != "" {
		field := accountcache.GetAccountMappingField(username, auth.Request.Protocol.Get(), "")
		w.storage.HSet(rediscli.GetUserHashKey(w.cfg.Server.Redis.Prefix, username), field, account)
	}

	return auth, ctx
}

// failedLogin runs the pre-check and, like the request paths, counts a failure or a rejected request.
func (w *bruteForceEventWorld) failedLogin(t *testing.T, username, account, password, clientIP string) bool {
	t.Helper()

	auth, ctx := w.request(t, username, account, password, clientIP)

	if auth.CheckBruteForce(ctx) {
		auth.updateBruteForceBucketsCounter(ctx, "", bruteforce.CountSourcePreAuthReject)

		return true
	}

	auth.UpdateBruteForceBucketsCounter(ctx)

	return false
}

// TestBruteForceEventsSeparateCountedContributorsFromAffectedRequests reproduces the shared-IP diagnosis gap: behind
// one public IP, counted failures of several claimed names, the ban written by a later request, and requests that only
// hit the ban must stay distinguishable, with no invented identity for an unknown login name.
func TestBruteForceEventsSeparateCountedContributorsFromAffectedRequests(t *testing.T) {
	world := newBruteForceEventWorld(t)

	world.failedLogin(t, "alice@example.test", "alice@example.test", "alice-wrong-1", natClientIP)
	world.failedLogin(t, "ceo@foreign.test", "", "guess-2", natClientIP)
	world.failedLogin(t, "bob@example.test", "bob@example.test", "bob-wrong-3", natClientIP)

	counted := world.events.take()
	assertCountedSequence(t, counted, []string{"alice@example.test", "ceo@foreign.test", "bob@example.test"})

	if counted[1].AccountKnown != nil || counted[1].Account != "" {
		t.Fatalf("unknown login name got account %q known=%v, want none", counted[1].Account, counted[1].AccountKnown)
	}

	if crossed := crossedFlags(counted); !slices.Equal(crossed, []bool{false, false, true}) {
		t.Fatalf("crossed = %v, want only the third increment", crossed)
	}

	if !world.failedLogin(t, "carol@example.test", "carol@example.test", "carol-correct", natClientIP) {
		t.Fatal("over-limit request was not rejected")
	}

	activation := world.events.take()
	assertActivation(t, activation[0], 3)
	assertRequestEvent(t, activation[1], requestEventShape{
		kind: pluginapi.BruteForceCounted, countSource: bruteforce.CountSourcePreAuthReject, banActive: "false",
	})

	if !world.failedLogin(t, "dave@example.test", "dave@example.test", "dave-correct", natClientIP) {
		t.Fatal("request behind the banned network was not rejected")
	}

	affected := world.events.take()
	if len(affected) != 2 {
		t.Fatalf("affected request events = %+v, want a ban hit and a counted event", affected)
	}

	assertRequestEvent(t, affected[0], requestEventShape{
		kind: pluginapi.BruteForceBanHit, hitSource: pluginapi.BruteForceHitRedis, claimed: "dave@example.test",
		banActive: "true",
	})
	assertRequestEvent(t, affected[1], requestEventShape{
		kind: pluginapi.BruteForceCounted, claimed: "dave@example.test",
		countSource: bruteforce.CountSourcePreAuthReject, banActive: "true",
	})
}

// requestEventShape is the comparable projection of one request-scoped event that scenario tests assert on.
type requestEventShape struct {
	kind        pluginapi.BruteForceEventKind
	hitSource   string
	claimed     string
	countSource string
	banActive   string
}

// requestShapeOf projects one event; claimed is only kept when the expectation names it.
func requestShapeOf(event pluginapi.BruteForceEvent, want requestEventShape) requestEventShape {
	shape := requestEventShape{
		kind: event.Kind, hitSource: event.HitSource, countSource: event.CountSource, banActive: optionalBool(event.BanActive),
	}

	if want.claimed != "" {
		shape.claimed = event.ClaimedUsername
	}

	return shape
}

// assertRequestEvent compares one request-scoped event with its expected projection.
func assertRequestEvent(t *testing.T, event pluginapi.BruteForceEvent, want requestEventShape) {
	t.Helper()

	if got := requestShapeOf(event, want); got != want {
		t.Fatalf("request event = %+v, want %+v (event %+v)", got, want, event)
	}
}

// optionalBool renders an optional flag as "true", "false", or "unset".
func optionalBool(value *bool) string {
	if value == nil {
		return "unset"
	}

	return strconv.FormatBool(*value)
}

// crossedFlags lists the crossed marker of every event, treating an unset marker as false.
func crossedFlags(events []pluginapi.BruteForceEvent) []bool {
	flags := make([]bool, 0, len(events))
	for _, event := range events {
		flags = append(flags, event.Crossed != nil && *event.Crossed)
	}

	return flags
}

// TestBruteForceEventsSkipNonCountedFailures pins that repeated wrong passwords of a known account and allowlisted
// clients produce no counted event.
func TestBruteForceEventsSkipNonCountedFailures(t *testing.T) {
	world := newBruteForceEventWorld(t)

	world.failedLogin(t, "alice@example.test", "alice@example.test", "same-wrong", natClientIP)
	world.failedLogin(t, "alice@example.test", "alice@example.test", "same-wrong", natClientIP)

	if events := world.events.take(); len(events) != 1 || events[0].Kind != pluginapi.BruteForceCounted {
		t.Fatalf("repeated wrong password events = %+v, want only the first counted", events)
	}

	world.cfg.BruteForce.IPWhitelist = []string{"198.51.100.0/24"}
	world.failedLogin(t, "bob@example.test", "bob@example.test", "bob-wrong", natClientIP)

	if events := world.events.take(); len(events) != 0 {
		t.Fatalf("allowlisted failure events = %+v, want none", events)
	}
}

// TestBruteForceEventsReleaseAndReban pins that an administrative flush reports the release and the counter reset,
// and that a later ban is a distinct instance.
func TestBruteForceEventsReleaseAndReban(t *testing.T) {
	world := newBruteForceEventWorld(t)
	banNetwork(t, world, "first")
	world.events.take()

	if err := flushNATNetwork(world, world.redis); err != nil {
		t.Fatalf("flush error = %v", err)
	}

	released := world.events.take()
	if len(released) != 2 || released[0].Kind != pluginapi.BruteForceBanReleased || released[0].Network != natRuleNetwork ||
		released[0].OperatorClientID != "ops-client" || released[1].Kind != pluginapi.BruteForceCountersReset ||
		released[1].KeysRemoved == nil || *released[1].KeysRemoved < 1 {
		t.Fatalf("flush events = %+v, want release and counter reset with operator reference", released)
	}

	first := banNetwork(t, world, "second")
	if first.EventID == "" || first.EventID == released[0].EventID {
		t.Fatalf("re-ban activation = %+v, want a distinct instance", first)
	}
}

// TestBruteForceEventsReportPartialFlush reproduces a flush whose ban delete succeeded before the counter unlink
// failed: the removed ban must still be reported, otherwise the instance looks active until its planned end.
func TestBruteForceEventsReportPartialFlush(t *testing.T) {
	world := newBruteForceEventWorld(t)
	banNetwork(t, world, "partial")
	world.events.take()

	db := redis.NewClient(&redis.Options{Addr: world.storage.Addr()})
	db.AddHook(failingUnlinkHook{})

	t.Cleanup(func() { _ = db.Close() })

	if err := flushNATNetwork(world, rediscli.NewTestClient(db)); err == nil {
		t.Fatal("flush error = nil, want the injected unlink failure")
	}

	if world.storage.Exists("parity:bf:ban:" + natRuleNetwork) {
		t.Fatal("ban key survived the flush; the reproducer needs the delete to succeed")
	}

	released := world.events.take()
	if len(released) != 1 || released[0].Kind != pluginapi.BruteForceBanReleased || released[0].Network != natRuleNetwork {
		t.Fatalf("partial flush events = %+v, want the release of the removed ban only", released)
	}
}

// failingUnlinkHook fails every pipeline that unlinks keys, after the earlier ban delete pipeline went through.
type failingUnlinkHook struct{}

// DialHook keeps the default dialer.
func (failingUnlinkHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

// ProcessHook keeps single commands unchanged.
func (failingUnlinkHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return next
}

// ProcessPipelineHook rejects pipelines that contain UNLINK.
func (failingUnlinkHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			if cmd.Name() == "unlink" {
				injected := stderrors.New("injected unlink failure")
				for _, failed := range cmds {
					failed.SetErr(injected)
				}

				return injected
			}
		}

		return next(ctx, cmds)
	}
}

// flushNATNetwork runs an administrative wildcard flush of the shared NAT address through the given Redis client.
func flushNATNetwork(world *bruteForceEventWorld, redisClient rediscli.Client) error {
	deps := restAdminDeps{Cfg: world.cfg, Redis: redisClient, BruteForceEvents: world.events}
	deps.flushAudit = bruteForceFlushAudit{source: pluginapi.BruteForceReleaseAdminFlush, clientID: "ops-client"}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/bruteforce/flush", http.NoBody)

	_, _, err := processBruteForceRules(ctx, deps, &bf.FlushRuleCmd{IPAddress: natClientIP, RuleName: "*"}, "flush-guid")

	return err
}

// TestBruteForceEventsIPv6NetworkSharesBucket pins canonical IPv6 networks and one shared bucket for two clients.
func TestBruteForceEventsIPv6NetworkSharesBucket(t *testing.T) {
	world := newBruteForceEventWorld(t, config.BruteForceRule{
		Name: "v6-64", Period: time.Hour, CIDR: 64, IPv6: true, FailedRequests: 10,
	})
	world.cfg.Server.BruteForceProtocols = []*config.Protocol{config.NewProtocol(definitions.ProtoIMAP)}

	world.failedLogin(t, "alice@example.test", "", "pw-1", "2001:db8:0:1::10")
	world.failedLogin(t, "bob@example.test", "", "pw-2", "2001:db8:0:1::20")

	events := world.events.take()
	if len(events) != 2 || events[0].Network != "2001:db8:0:1::/64" || events[0].IPFamily != 6 ||
		events[0].BucketID == "" || events[0].BucketID != events[1].BucketID || *events[1].Current != 2 {
		t.Fatalf("IPv6 events = %+v, want one shared /64 bucket counted twice", events)
	}
}

// banNetwork counts three failures and lets a fourth request write the ban; it returns the activation event.
func banNetwork(t *testing.T, world *bruteForceEventWorld, label string) pluginapi.BruteForceEvent {
	t.Helper()

	for index := range 3 {
		world.failedLogin(t, fmt.Sprintf("%s-%d@example.test", label, index), "", fmt.Sprintf("%s-pw-%d", label, index), natClientIP)
	}

	world.events.take()

	if !world.failedLogin(t, label+"-trigger@example.test", "", label+"-pw", natClientIP) {
		t.Fatalf("%s: over-limit request was not rejected", label)
	}

	events := world.events.take()
	assertActivation(t, events[0], 3)

	return events[0]
}

// assertCountedSequence checks counted events of one bucket window in increment order.
func assertCountedSequence(t *testing.T, events []pluginapi.BruteForceEvent, names []string) {
	t.Helper()

	if len(events) != len(names) {
		t.Fatalf("counted events = %+v, want %d", events, len(names))
	}

	for index, event := range events {
		assertRequestEvent(t, event, requestEventShape{
			kind: pluginapi.BruteForceCounted, claimed: names[index],
			countSource: bruteforce.CountSourceBackendFailure, banActive: "false",
		})

		if got, want := countedBucketShapeOf(event, events[0].BucketID), (countedBucketShape{
			current: int64(index + 1), network: natRuleNetwork, rule: natRuleName, sameBucket: true, identified: true,
		}); got != want {
			t.Fatalf("counted event %d bucket = %+v, want %+v (event %+v)", index, got, want, event)
		}
	}
}

// countedBucketShape is the comparable bucket projection of one counted event.
type countedBucketShape struct {
	network    string
	rule       string
	current    int64
	sameBucket bool
	identified bool
}

// countedBucketShapeOf projects the bucket fields of one counted event against the expected bucket identity.
func countedBucketShapeOf(event pluginapi.BruteForceEvent, bucketID string) countedBucketShape {
	shape := countedBucketShape{
		network:    event.Network,
		rule:       event.Rule,
		current:    -1,
		sameBucket: bucketID != "" && event.BucketID == bucketID,
		identified: event.EventID != "" && event.RequestID != "",
	}

	if event.Current != nil {
		shape.current = *event.Current
	}

	return shape
}

// assertActivation checks one ban activation carrying the pre-check counter that fed the decision.
func assertActivation(t *testing.T, event pluginapi.BruteForceEvent, current int64) {
	t.Helper()

	if event.Kind != pluginapi.BruteForceBanActivated || event.Network != natRuleNetwork || event.StoredRule != natRuleName ||
		event.Current == nil || *event.Current != current || event.ExpiresAt == nil || event.ClaimedUsername != "" ||
		event.Account != "" || event.RuleFingerprint == "" || event.BanTimeSeconds != int64(time.Hour.Seconds()) {
		t.Fatalf("activation = %+v, want ban of %s with pre-check current %d and no claimed identity", event, natRuleNetwork, current)
	}
}

// TestBruteForceEventsToleratedThresholdIsNeverABan pins that an active toleration produces a tolerated event and no
// ban, while the same counter without toleration activates a ban.
func TestBruteForceEventsToleratedThresholdIsNeverABan(t *testing.T) {
	world := newBruteForceEventWorld(t)
	world.cfg.BruteForce.TolerateTTL = time.Hour
	world.cfg.BruteForce.ToleratePercent = 50

	// Successful logins of the shared IP make toleration active.
	toleration := tolerate.NewTolerateWithDeps(world.cfg, nil, world.redis, 50)
	for index := range 10 {
		toleration.SetIPAddress(t.Context(), natClientIP, fmt.Sprintf("user-%d@example.test", index), true)
	}

	// Positive reputation scales the limit from 2 to 3, so four counted failures exceed it.
	for index := range 4 {
		world.failedLogin(t, fmt.Sprintf("guess-%d@example.test", index), "", fmt.Sprintf("pw-%d", index), natClientIP)
	}

	if counted := world.events.take(); *counted[len(counted)-1].Limit != 3 {
		t.Fatalf("scaled limit = %v, want 3 from positive reputation", *counted[len(counted)-1].Limit)
	}

	if world.failedLogin(t, "next@example.test", "", "pw-next", natClientIP) {
		t.Fatal("tolerated network was rejected")
	}

	events := world.events.take()
	if len(events) == 0 || events[0].Kind != pluginapi.BruteForceThresholdTolerated || events[0].Network != natRuleNetwork {
		t.Fatalf("tolerated events = %+v, want threshold_tolerated first", events)
	}

	for _, event := range events {
		if event.Kind == pluginapi.BruteForceBanActivated || event.Kind == pluginapi.BruteForceBanHit {
			t.Fatalf("tolerated request produced %s", event.Kind)
		}
	}

	if world.storage.Exists(rediscli.GetBruteForceBanKey(world.cfg.Server.Redis.Prefix, natRuleNetwork)) {
		t.Fatal("tolerated threshold wrote a ban key")
	}
}

// bruteForceFixturePath is the shared brute-force contract fixture replayed into a real ClickHouse.
const bruteForceFixturePath = "../../contrib/plugins/clickhouse/testdata/diagnostic_contract/bruteforce_events.json"

// TestBruteForceEventsMatchContractFixture pins the complete event sequence of the shared-IP scenario: three counted
// contributors (one unknown claimed name), the ban written by a later request, one affected request, an
// administrative release, and a counter reset. Set NAUTHILUS_UPDATE_FIXTURES=1 to rewrite the fixture.
func TestBruteForceEventsMatchContractFixture(t *testing.T) {
	world := newBruteForceEventWorld(t)

	world.failedLogin(t, "alice@example.test", "alice@example.test", "alice-wrong-1", natClientIP)
	world.failedLogin(t, "ceo@foreign.test", "", "guess-2", natClientIP)
	world.failedLogin(t, "bob@example.test", "bob@example.test", "bob-wrong-3", natClientIP)
	world.failedLogin(t, "carol@example.test", "carol@example.test", "carol-correct", natClientIP)
	world.failedLogin(t, "dave@example.test", "dave@example.test", "dave-correct", natClientIP)

	deps := restAdminDeps{Cfg: world.cfg, Redis: world.redis, BruteForceEvents: world.events}
	deps.flushAudit = bruteForceFlushAudit{
		source: pluginapi.BruteForceReleaseAdminFlush, clientID: "ops-client", authMethod: "oidc_bearer",
		requestID: "flush-request",
	}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/bruteforce/flush", http.NoBody)

	if _, _, err := processBruteForceRules(ctx, deps, &bf.FlushRuleCmd{IPAddress: natClientIP, RuleName: "*"}, "flush-guid"); err != nil {
		t.Fatalf("flush error = %v", err)
	}

	got := normalizeBruteForceEvents(world.events.take())
	assertBruteForceFixture(t, got)
}

// normalizeBruteForceEvents replaces time-dependent values with stable ones while keeping their relations.
func normalizeBruteForceEvents(events []pluginapi.BruteForceEvent) []pluginapi.BruteForceEvent {
	base := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	windowIndex, weight := int64(493112), 1.0

	for index := range events {
		event := &events[index]
		event.EventID = fmt.Sprintf("%032x", index+1)
		event.ObservedAt = base.Add(time.Duration(index) * time.Second)

		if event.ExpiresAt != nil {
			expiresAt := event.ObservedAt.Add(time.Duration(event.BanTimeSeconds) * time.Second)
			event.ExpiresAt = &expiresAt
		}

		if event.WindowIndex != nil {
			event.WindowIndex = &windowIndex
		}

		if event.Weight != nil {
			event.Weight = &weight
		}

		if event.Total != nil && event.Current != nil {
			// With an empty previous window the weighted total equals the current window count.
			total := float64(*event.Current)
			event.Total = &total
		}
	}

	return events
}

// assertBruteForceFixture compares events with the shared fixture or rewrites it on request.
func assertBruteForceFixture(t *testing.T, got []pluginapi.BruteForceEvent) {
	t.Helper()

	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("encode events: %v", err)
	}

	if os.Getenv("NAUTHILUS_UPDATE_FIXTURES") == "1" {
		if err = os.WriteFile(bruteForceFixturePath, append(encoded, '\n'), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}

		return
	}

	want, err := os.ReadFile(bruteForceFixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	if strings.TrimSpace(string(want)) != strings.TrimSpace(string(encoded)) {
		t.Fatalf("brute-force events differ from %s:\n%s", bruteForceFixturePath, encoded)
	}
}

// TestBruteForceEventsMultipleRulesAndProtocolScope pins one counted event per incremented bucket, protocol-scoped
// bucket identity, and the first over-limit rule in config order writing the ban.
func TestBruteForceEventsMultipleRulesAndProtocolScope(t *testing.T) {
	world := newBruteForceEventWorld(t,
		config.BruteForceRule{
			Name: "imap-host", Period: time.Hour, CIDR: 32, IPv4: true, FailedRequests: 2, BanTime: time.Hour,
			FilterByProtocol: []string{definitions.ProtoIMAP},
		},
		config.BruteForceRule{Name: "any-net", Period: time.Hour, CIDR: 24, IPv4: true, FailedRequests: 10, BanTime: time.Hour},
	)

	world.failedLogin(t, "alice@example.test", "", "pw-1", natClientIP)

	counted := world.events.take()
	if len(counted) != 2 || counted[0].Rule != "imap-host" || counted[0].BucketProtocol != definitions.ProtoIMAP ||
		counted[0].Network != natClientIP+"/32" || counted[1].Rule != "any-net" || counted[1].BucketProtocol != "" ||
		counted[0].BucketID == counted[1].BucketID {
		t.Fatalf("counted events = %+v, want one scoped /32 bucket and one unscoped /24 bucket", counted)
	}

	world.failedLogin(t, "bob@example.test", "", "pw-2", natClientIP)
	world.events.take()

	if !world.failedLogin(t, "carol@example.test", "", "pw-3", natClientIP) {
		t.Fatal("over-limit request was not rejected")
	}

	events := world.events.take()
	if events[0].Kind != pluginapi.BruteForceBanActivated || events[0].Rule != "imap-host" ||
		events[0].Network != natClientIP+"/32" {
		t.Fatalf("activation = %+v, want the scoped /32 rule first in config order", events[0])
	}
}
