package main

import (
	"context"
	"errors"
	"testing"
)

// TestNetworkOverridePreservesLongestPrefixAndMissingFallback prevents static CIDR intent from collapsing into the learned network prefix.
func TestNetworkOverridePreservesLongestPrefixAndMissingFallback(t *testing.T) {
	cfg := testConfig(t)
	cfg.raw.IPOverrideNetworks = []string{"192.0.2.0/24", "192.0.2.16/28"}
	requireNoError(t, cfg.compileOverrideNetworks())

	for _, tc := range []struct {
		name, address, narrow string
		want                  string
		fail                  bool
	}{{"specific neutral", "192.0.2.20", "neutral", "neutral", false}, {"specific trusted", "192.0.2.20", "trusted", "trusted", false}, {"missing specific", "192.0.2.20", "none", "blocked", false}, {"broad match", "192.0.2.3", "trusted", "blocked", false}, {"absent", "198.51.100.2", "trusted", "none", false}, {"failure", "192.0.2.20", "trusted", "", true}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cfg.networkOverride(t.Context(), tc.address, func(_ context.Context, subject subjectInput) (string, error) {
				if tc.fail {
					return "", errors.New("primary unavailable")
				}

				if subject.value == "192.0.2.16/28" {
					return tc.narrow, nil
				}

				return "blocked", nil
			})
			if (err != nil) != tc.fail || (!tc.fail && got != tc.want) {
				t.Fatalf("got %q/%v want %q", got, err, tc.want)
			}
		})
	}
}
