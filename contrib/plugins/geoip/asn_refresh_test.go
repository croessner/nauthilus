package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type retryASNFetcher struct{ calls atomic.Int32 }

// Fetch fails the first attempt and then supplies a valid snapshot for either source family.
func (f *retryASNFetcher) Fetch(_ context.Context, url string) ([]byte, error) {
	if f.calls.Add(1) == 1 {
		return nil, errors.New("temporary download failure")
	}

	if url == testRegistrySourceURL {
		return []byte("arin|US|asn|64500|1|20240101|allocated\n"), nil
	}

	return []byte("203.0.113.0/24 64500 DE ripencc 20240101\n"), nil
}

// TestASNDownloadsRetryBeforeRegularRefresh reproduces the month-long gap after a startup failure.
func TestASNDownloadsRetryBeforeRegularRefresh(t *testing.T) {
	for _, registry := range []bool{false, true} {
		name := "routing"
		if registry {
			name = "registry"
		}

		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				plugin := NewPlugin()
				fetcher := &retryASNFetcher{}
				plugin.asnFetch, plugin.asnRouteFetch = fetcher, fetcher

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				go func() {
					if registry {
						_ = plugin.asnRegistryLoop(ctx, asnRegistryConfig{Enabled: true, RefreshInterval: 30 * 24 * time.Hour, Timeout: time.Second, SourceURLs: []string{testRegistrySourceURL}})
						return
					}

					_ = plugin.asnLookupLoop(ctx, asnLookupConfig{Enabled: true, RefreshInterval: 30 * 24 * time.Hour, Timeout: time.Second, SourceURLs: []string{testASNLookupSourceURL}})
				}()

				time.Sleep(time.Minute + time.Second)
				synctest.Wait()

				if got := fetcher.calls.Load(); got != 2 {
					t.Fatalf("download attempts = %d, want failed attempt followed by recovery", got)
				}

				time.Sleep(24 * time.Hour)

				if got := fetcher.calls.Load(); got != 2 {
					t.Fatalf("successful refresh did not restore regular interval: %d attempts", got)
				}

				cancel()
				synctest.Wait()
				time.Sleep(31 * 24 * time.Hour)

				if got := fetcher.calls.Load(); got != 2 {
					t.Fatalf("download continued after cancellation: %d attempts", got)
				}
			})
		})
	}
}

// TestASNRefreshScheduleBoundsFailuresAndResets prevents retry storms and permanent abandonment.
func TestASNRefreshScheduleBoundsFailuresAndResets(t *testing.T) {
	for _, interval := range []time.Duration{30 * 24 * time.Hour, 10 * time.Second} {
		schedule := asnRefreshSchedule{interval: interval}
		ceiling := min(asnRetryInitial, interval)

		for range 100 {
			delay := schedule.next(errors.New("offline"))
			if delay < ceiling/2 || delay > ceiling {
				t.Fatalf("retry delay = %s, outside [%s,%s]", delay, ceiling/2, ceiling)
			}

			ceiling = min(ceiling*2, asnRetryMaximum, interval)
		}

		if delay := schedule.next(nil); delay != interval {
			t.Fatalf("success delay = %s, want %s", delay, interval)
		}

		if delay := schedule.next(errors.New("offline again")); delay > min(asnRetryInitial, interval) {
			t.Fatalf("backoff was not reset: %s", delay)
		}
	}
}

// TestASNRefreshRetainsLastGoodSnapshots proves partial downloads and invalid data cannot replace live records.
func TestASNRefreshRetainsLastGoodSnapshots(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint("invalid_data=", invalid), func(t *testing.T) {
			plugin := NewPlugin()
			routing := asnLookupConfig{Enabled: true, Timeout: time.Second, SourceURLs: []string{testASNLookupSourceURL}}
			registry := asnRegistryConfig{Enabled: true, Timeout: time.Second, SourceURLs: []string{testRegistrySourceURL}}
			fetcher := &retryASNFetcher{}
			fetcher.calls.Store(1)

			plugin.asnFetch, plugin.asnRouteFetch = fetcher, fetcher
			if err := plugin.refreshASNLookupOnce(t.Context(), routing); err != nil {
				t.Fatal(err)
			}

			if err := plugin.refreshASNRegistryOnce(t.Context(), registry); err != nil {
				t.Fatal(err)
			}

			oldRouting, oldRegistry := plugin.asnLookup.currentSnapshot(), plugin.asnRegistry

			data := map[string][]byte{}
			if invalid {
				data[testASNLookupSourceURL] = []byte("invalid")
				data[testRegistrySourceURL] = []byte("invalid")
			}

			plugin.asnRouteFetch = fakeASNRouteFetcher{data: data}

			plugin.asnFetch = fakeASNRegistryFetcher{data: data}
			if err := plugin.refreshASNLookupOnce(t.Context(), routing); err == nil {
				t.Fatal("failed routing source accepted")
			}

			if err := plugin.refreshASNRegistryOnce(t.Context(), registry); err == nil {
				t.Fatal("failed registry source accepted")
			}

			if plugin.asnLookup.currentSnapshot() != oldRouting || plugin.asnRegistry != oldRegistry {
				t.Fatal("failed refresh replaced a live snapshot")
			}

			assertRetainedASNRecords(t, oldRouting, oldRegistry)
		})
	}
}

// assertRetainedASNRecords verifies lookups still resolve against the retained snapshots.
func assertRetainedASNRecords(t *testing.T, routing *asnLookupSnapshot, registry *asnRegistrySnapshot) {
	t.Helper()

	if record, ok := routing.Lookup(netip.MustParseAddr(testClientIP)); !ok || record.ASN != 64500 {
		t.Fatal("routing lookup lost its last good record")
	}

	if record, ok := registry.Lookup(64500); !ok || record.Registry != testRegistryARIN {
		t.Fatal("registry lookup lost its last good record")
	}
}
