package core

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/rediscli"
)

// precheckTolerationProbe observes whether the request builder passes reputation authority.
type precheckTolerationProbe struct {
	tolerate.Tolerate
	reads int
}

// GetReputationKey records reputation reads without external state.
func (p *precheckTolerationProbe) GetReputationKey(_ string) string {
	p.reads++
	return "test:reputation"
}

// TestPrecheckUsesInjectedToleration exercises the actual precheck builder and counter collector.
func TestPrecheckUsesInjectedToleration(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	a, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	probe := &precheckTolerationProbe{}
	a.deps.Tolerate = probe

	mock.MatchExpectationsInOrder(false)
	rediscli.ClearScriptCache()
	mock.Regexp().ExpectExists(".*").SetVal(0)
	mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("review-sha")
	mock.Regexp().ExpectEvalSha("review-sha", []string{".*", ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").SetVal([]any{"0", int64(0), "4"})
	mock.ExpectHGet("test:reputation", "positive").SetVal("100")
	mock.Regexp().ExpectHGet(".*", ".*").RedisNil()

	bm := a.newBruteForceBucketManager(ctx)

	_, err := bm.CollectBucketPolicyFacts(cfg.BruteForce.Buckets)
	if err != nil {
		t.Fatal(err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}

	if probe.reads == 0 {
		t.Fatal("precheck did not consult injected reputation/toleration provider")
	}
}

// TestBruteForceStorageFailureStopsAuthentication distinguishes unavailable protection from a clean check.
func TestBruteForceStorageFailureStopsAuthentication(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	a, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	mock.MatchExpectationsInOrder(false)
	rediscli.ClearScriptCache()
	mock.Regexp().ExpectHGet(".*", ".*").RedisNil()
	mock.Regexp().ExpectExists(".*").SetVal(0)
	mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetErr(errors.New("storage unavailable"))

	if !a.CheckBruteForce(ctx) {
		t.Error("unavailable brute-force storage must stop authentication")
	}

	if a.GetBruteForceError() == nil {
		t.Error("storage failure was not retained for temporary failure and policy facts")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestPolicyBanStorageErrorIsNotAHealthyCheck rejects partial policy facts when ban storage is unavailable.
func TestPolicyBanStorageErrorIsNotAHealthyCheck(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	storageErr := errors.New("ban storage unavailable")

	mock.MatchExpectationsInOrder(false)
	mock.Regexp().ExpectHGet(".*", ".*").RedisNil()
	mock.Regexp().ExpectExists(".*").SetErr(storageErr)

	manager := auth.newBruteForceBucketManager(ctx)
	if _, err := manager.CollectBucketPolicyFacts(cfg.BruteForce.Buckets); !errors.Is(err, storageErr) {
		t.Fatalf("ban storage failure must invalidate policy facts, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
