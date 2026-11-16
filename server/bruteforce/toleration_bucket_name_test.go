// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package bruteforce_test

import (
	"context"
	"net"
	"testing"

	"github.com/croessner/nauthilus/v4/server/bruteforce"
	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/rediscli"
)

// activeToleration reports an active toleration for every client so the block of a triggered bucket is suppressed.
type activeToleration struct {
	tolerate.Tolerate
}

// PolicyFact returns one active toleration fact without touching Redis.
func (activeToleration) PolicyFact(context.Context, string) tolerate.PolicyFact {
	return tolerate.PolicyFact{Active: true, Mode: "static"}
}

// TestTolerationSuppressedTriggerKeepsBucketNameWithoutBlock pins the analytics path behind rows that carry a
// brute-force bucket without a brute_force decision source: the bucket went over its limit, toleration suppressed the
// block, ProcessBruteForce reports no trigger, and the setter still publishes the bucket name together with a
// suppressed-block toleration fact.
func TestTolerationSuppressedTriggerKeepsBucketNameWithoutBlock(t *testing.T) {
	cfg := initTestConfig()
	mock, tol := setupSubtest(cfg)

	bm := bruteforce.NewBucketManagerWithDeps(context.Background(), "test", bruteForceLogicIP, bruteforce.BucketManagerDeps{
		Cfg:      cfg,
		Logger:   log.GetLogger(),
		Redis:    rediscli.GetClient(),
		Tolerate: activeToleration{Tolerate: tol},
	})

	rules := cfg.GetBruteForceRules()
	rule := &rules[0]
	_, network, _ := net.ParseCIDR(bruteForceLogicIP + "/32")
	currentKey, prevKey, _ := bm.GetSlidingWindowKeys(rule, network)

	mock.MatchExpectationsInOrder(false)
	mock.Regexp().ExpectHGet(".*", "positive").RedisNil()
	mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha1")
	mock.Regexp().ExpectEvalSha("sha1", []string{currentKey, prevKey}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
		SetVal([]any{"15", int64(1), "4"})
	mockNoisy(mock)

	var message string

	if withError, ruleTriggered, _ := bm.CheckBucketOverLimit(rules, &message); withError || !ruleTriggered {
		t.Fatalf("CheckBucketOverLimit() error/triggered = %v/%v, want false/true", withError, ruleTriggered)
	}

	var published string

	triggered := bm.ProcessBruteForce(true, false, rule, network, "", func() {
		published = bm.GetBruteForceName()
	})

	if triggered {
		t.Fatal("ProcessBruteForce() = true, want toleration to suppress the block")
	}

	if !bm.GetTolerationPolicyFact().SuppressedBlock {
		t.Fatal("toleration fact SuppressedBlock = false, want true")
	}

	if published != rule.Name {
		t.Fatalf("published bucket name = %q, want %q from the suppressed over-limit bucket", published, rule.Name)
	}
}
