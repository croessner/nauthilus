// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDecisionBindingReportsSnapshotFreshnessWithoutInventedASN(t *testing.T) {
	for _, test := range []struct {
		name      string
		age       time.Duration
		ip        string
		wantState string
		wantASN   bool
	}{
		{name: "miss", ip: "198.18.0.1", wantState: "not_found"},
		{name: "future snapshot", age: -30 * time.Second, wantState: "unavailable"},
		{name: "fresh", wantState: "fresh", wantASN: true},
		{name: "stale acceptable", age: 50 * 24 * time.Hour, wantState: "stale", wantASN: true},
		{name: "too stale", age: 100 * 24 * time.Hour, wantState: "unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := os.ReadFile(testDatabasePath(t, "geoip.json"))
			if err != nil {
				t.Fatal(err)
			}

			path := filepath.Join(t.TempDir(), "geoip.json")
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}

			observed := time.Now().Add(-test.age)
			if err = os.Chtimes(path, observed, observed); err != nil {
				t.Fatal(err)
			}

			runner, plugin, _, _ := startedTestRunnerWithPlugin(t, testModule(path))
			defer stopRunner(t, runner)

			ip := test.ip
			if ip == "" {
				ip = testClientIP
			}

			result, err := testDecisionProvider(t, plugin).Collect(t.Context(), newGeoIPDecisionFactRequest(t, "authenticate", ip))
			if err != nil {
				t.Fatal(err)
			}

			assertDecisionOutput(t, result, "lookup_state", test.wantState)

			hasASN := false

			for _, fact := range result.Facts {
				if fact.Name == "asn" {
					hasASN = true
				}
			}

			if hasASN != test.wantASN {
				t.Fatalf("ASN present = %v, want %v", hasASN, test.wantASN)
			}
		})
	}
}
