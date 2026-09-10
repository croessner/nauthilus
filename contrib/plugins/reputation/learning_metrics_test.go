package main

import (
	"fmt"
	"testing"
)

// TestLearningIngestionResultSeparatesQuotaFromOutage retains partial progress and distinguishes resource admission.
func TestLearningIngestionResultSeparatesQuotaFromOutage(t *testing.T) {
	for _, test := range []struct {
		name   string
		result ingestionResult
		err    error
		want   string
	}{
		{name: "quota", err: errQuotaExceeded, want: storageQuotaExceeded},
		{name: "wrapped quota", err: fmt.Errorf("manifest: %w", errQuotaExceeded), want: storageQuotaExceeded},
		{name: "outage", err: errStateUnavailable, want: learningUnavailable},
		{name: "partial quota", result: ingestionResult{Applied: 1}, err: errQuotaExceeded, want: learningPartial},
		{name: "duplicate quota", result: ingestionResult{Duplicates: 1}, err: errQuotaExceeded, want: learningPartial},
		{name: "applied", result: ingestionResult{Applied: 1}, want: storageApplied},
		{name: "duplicate", result: ingestionResult{Duplicates: 1}, want: storageDuplicate},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := learningIngestionResult(test.result, test.err); got != test.want {
				t.Fatalf("result = %s, want %s", got, test.want)
			}
		})
	}
}
