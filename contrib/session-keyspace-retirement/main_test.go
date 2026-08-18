// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRetirementDefaultsToSecretFreeDryRunAndRequiresApply(t *testing.T) {
	t.Parallel()

	fixture := seedRetirementFixture(t)
	dryRun := executeRetirement(t, fixture.client, false)
	assertRetirementReport(t, dryRun, "dry-run", "matched=1")

	if !fixture.mini.Exists(fixture.legacyKey) || !fixture.mini.Exists(fixture.currentKey) {
		t.Fatal("dry run deleted Redis state")
	}

	apply := executeRetirement(t, fixture.client, true)
	assertRetirementReport(t, apply, "apply", "deleted=1")

	if fixture.mini.Exists(fixture.legacyKey) || !fixture.mini.Exists(fixture.currentKey) {
		t.Fatal("apply did not stay within the legacy allowlist")
	}
}

type retirementFixture struct {
	mini       *miniredis.Miniredis
	client     *redis.Client
	legacyKey  string
	currentKey string
}

func seedRetirementFixture(t *testing.T) retirementFixture {
	t.Helper()

	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	ctx := context.Background()
	legacyKey := "nauthilus:idp:flow:legacy-flow-reference"
	currentKey := "nauthilus:browser-session:{current}:oidc:record"

	if err := client.Set(ctx, legacyKey, "secret legacy payload", 10*time.Minute).Err(); err != nil {
		t.Fatalf("seed legacy key: %v", err)
	}

	if err := client.Set(ctx, currentKey, "current payload", 10*time.Minute).Err(); err != nil {
		t.Fatalf("seed current key: %v", err)
	}

	return retirementFixture{mini: mini, client: client, legacyKey: legacyKey, currentKey: currentKey}
}

func executeRetirement(t *testing.T, client redis.UniversalClient, apply bool) string {
	t.Helper()

	var output bytes.Buffer
	if err := runRetirement(context.Background(), client, "nauthilus:", apply, &output); err != nil {
		t.Fatalf("run retirement apply=%v: %v", apply, err)
	}

	return output.String()
}

func assertRetirementReport(t *testing.T, output string, mode string, result string) {
	t.Helper()

	if strings.Contains(output, "legacy-flow-reference") || strings.Contains(output, "secret legacy payload") {
		t.Fatalf("report disclosed a key or value: %q", output)
	}

	if !strings.Contains(output, "mode="+mode) || !strings.Contains(output, result) {
		t.Fatalf("report = %q, want mode=%s and %s", output, mode, result)
	}
}
