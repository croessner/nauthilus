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

package rediscli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/testing/rediscluster"
	"github.com/croessner/nauthilus/v4/server/testing/redisroundtrip"
	"github.com/redis/go-redis/v9"
)

// errInjectedPipeline is returned by pipelineFaultHook for a failed pipeline execution.
var errInjectedPipeline = errors.New("injected pipeline failure")

// pipelineFaultHook fails or cancels selected pipeline executions to model network and context faults.
type pipelineFaultHook struct {
	cancel      context.CancelFunc
	failAt      int
	cancelAt    int
	cancelAfter int
	executions  int
}

// DialHook passes dials through unchanged.
func (h *pipelineFaultHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

// ProcessHook passes single commands through unchanged.
func (h *pipelineFaultHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return next
}

// ProcessPipelineHook injects the configured fault for the selected data pipeline execution (1-based).
// Connection handshake pipelines are passed through and not counted.
func (h *pipelineFaultHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if len(cmds) == 0 || cmds[0].Name() != "smembers" {
			return next(ctx, cmds)
		}

		h.executions++

		switch h.executions {
		case h.failAt:
			return errInjectedPipeline
		case h.cancelAt:
			h.cancel()
		}

		err := next(ctx, cmds)

		if h.executions == h.cancelAfter {
			h.cancel()
		}

		return err
	}
}

// pipelineBatchFixture is a miniredis-backed client with round-trip recording.
type pipelineBatchFixture struct {
	server   *miniredis.Miniredis
	handle   *redis.Client
	client   Client
	recorder *redisroundtrip.Recorder
}

// newPipelineBatchFixture starts miniredis and seeds count sets named set-<index> with index members.
func newPipelineBatchFixture(t *testing.T, count int) *pipelineBatchFixture {
	t.Helper()

	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr(), Protocol: 2})

	t.Cleanup(func() { _ = handle.Close() })

	for index := range count {
		for member := range index % 3 {
			if _, err := server.SetAdd(fmt.Sprintf("set-%d", index), fmt.Sprintf("m%d", member)); err != nil {
				t.Fatalf("seed set: %v", err)
			}
		}
	}

	return &pipelineBatchFixture{
		server:   server,
		handle:   handle,
		client:   NewTestClientForHandle(handle),
		recorder: redisroundtrip.Attach(handle),
	}
}

// keys returns the seeded key names in order.
func pipelineBatchKeys(count int) []string {
	keys := make([]string, count)
	for index := range keys {
		keys[index] = fmt.Sprintf("set-%d", index)
	}

	return keys
}

// collectSetCards runs the batches and returns each evaluated key with its member count.
func collectSetCards(ctx context.Context, client Client, keys []string, batchSize int) ([]string, error) {
	evaluated := make([]string, 0, len(keys))

	err := RunReadPipelineBatches(ctx, ReadPipelineBatches{Client: client, BatchSize: batchSize}, keys,
		func(ctx context.Context, pipe redis.Pipeliner, key string) *redis.StringSliceCmd {
			return pipe.SMembers(ctx, key)
		},
		func(key string, cmd *redis.StringSliceCmd) error {
			evaluated = append(evaluated, fmt.Sprintf("%s=%d", key, len(cmd.Val())))

			return nil
		},
	)

	return evaluated, err
}

// expectedSetCards returns the evaluation log for the first count seeded keys.
func expectedSetCards(count int) []string {
	want := make([]string, count)
	for index := range want {
		want[index] = fmt.Sprintf("set-%d=%d", index, index%3)
	}

	return want
}

func TestRunReadPipelineBatchesBoundsEveryPipeline(t *testing.T) {
	cases := []struct {
		count     int
		batchSize int
		wantTrips int
	}{
		{count: 0, batchSize: 4, wantTrips: 0},
		{count: 1, batchSize: 4, wantTrips: 1},
		{count: 4, batchSize: 4, wantTrips: 1},
		{count: 5, batchSize: 4, wantTrips: 2},
		{count: 9, batchSize: 1, wantTrips: 9},
		{count: 9, batchSize: 100, wantTrips: 1},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("count_%d_batch_%d", tc.count, tc.batchSize), func(t *testing.T) {
			fixture := newPipelineBatchFixture(t, tc.count)

			evaluated, err := collectSetCards(t.Context(), fixture.client, pipelineBatchKeys(tc.count), tc.batchSize)
			if err != nil {
				t.Fatalf("run batches: %v", err)
			}

			if !slices.Equal(evaluated, expectedSetCards(tc.count)) {
				t.Fatalf("evaluated = %v, want %v", evaluated, expectedSetCards(tc.count))
			}

			trips := fixture.recorder.RoundTrips()
			if len(trips) != tc.wantTrips {
				t.Fatalf("round trips = %d, want %d", len(trips), tc.wantTrips)
			}

			for _, trip := range trips {
				if len(trip) > tc.batchSize {
					t.Fatalf("pipeline carried %d commands, want at most %d", len(trip), tc.batchSize)
				}
			}
		})
	}
}

func TestRunReadPipelineBatchesRejectsUnboundedBatchSize(t *testing.T) {
	fixture := newPipelineBatchFixture(t, 1)

	if _, err := collectSetCards(t.Context(), fixture.client, pipelineBatchKeys(1), 0); !errors.Is(err, ErrInvalidPipelineBatchSize) {
		t.Fatalf("error = %v, want ErrInvalidPipelineBatchSize", err)
	}

	if fixture.recorder.Count() != 0 {
		t.Fatalf("round trips = %d, want none", fixture.recorder.Count())
	}
}

func TestRunReadPipelineBatchesStopsAtFirstFailedCommand(t *testing.T) {
	fixture := newPipelineBatchFixture(t, 9)

	// set-5 sits in the second batch of three; a string makes SMEMBERS fail with WRONGTYPE.
	fixture.server.Del("set-5")

	if err := fixture.server.Set("set-5", "not a set"); err != nil {
		t.Fatalf("seed wrong type: %v", err)
	}

	evaluated, err := collectSetCards(t.Context(), fixture.client, pipelineBatchKeys(9), 3)
	if err == nil {
		t.Fatal("expected WRONGTYPE error")
	}

	if want := expectedSetCards(5); !slices.Equal(evaluated, want) {
		t.Fatalf("evaluated = %v, want only the items before the failed command %v", evaluated, want)
	}

	if trips := fixture.recorder.Count(); trips != 2 {
		t.Fatalf("round trips = %d, want 2 (no batch after the failure)", trips)
	}
}

func TestRunReadPipelineBatchesRejectsPipelineFailureWithoutCommandError(t *testing.T) {
	fixture := newPipelineBatchFixture(t, 6)
	fixture.handle.AddHook(&pipelineFaultHook{failAt: 2})

	evaluated, err := collectSetCards(t.Context(), fixture.client, pipelineBatchKeys(6), 3)
	if !errors.Is(err, errInjectedPipeline) {
		t.Fatalf("error = %v, want injected pipeline failure", err)
	}

	// The failed batch has unset results; none of them may be reported as empty sets.
	if want := expectedSetCards(3); !slices.Equal(evaluated, want) {
		t.Fatalf("evaluated = %v, want %v", evaluated, want)
	}
}

func TestRunReadPipelineBatchesHonorsContextCancellation(t *testing.T) {
	cases := []struct {
		name          string
		hook          func(cancel context.CancelFunc) *pipelineFaultHook
		wantEvaluated int
		wantTrips     int
	}{
		{
			name: "between_batches",
			hook: func(cancel context.CancelFunc) *pipelineFaultHook {
				return &pipelineFaultHook{cancel: cancel, cancelAfter: 1}
			},
			wantEvaluated: 3,
			wantTrips:     1,
		},
		{
			name: "within_batch",
			hook: func(cancel context.CancelFunc) *pipelineFaultHook {
				return &pipelineFaultHook{cancel: cancel, cancelAt: 2}
			},
			wantEvaluated: 3,
			wantTrips:     2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newPipelineBatchFixture(t, 9)
			ctx, cancel := context.WithCancel(t.Context())

			defer cancel()

			fixture.handle.AddHook(tc.hook(cancel))

			evaluated, err := collectSetCards(ctx, fixture.client, pipelineBatchKeys(9), 3)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context.Canceled", err)
			}

			if want := expectedSetCards(tc.wantEvaluated); !slices.Equal(evaluated, want) {
				t.Fatalf("evaluated = %v, want %v", evaluated, want)
			}

			if trips := fixture.recorder.Count(); trips != tc.wantTrips {
				t.Fatalf("round trips = %d, want %d", trips, tc.wantTrips)
			}
		})
	}
}

func TestRunReadPipelineBatchesReadsKeysAcrossClusterSlots(t *testing.T) {
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	nodes := rediscluster.NewTwoNode(t)
	recorder := redisroundtrip.Attach(nodes.Cluster)
	keys := make([]string, 0, 8)
	want := make([]string, 0, 8)

	for index := range 8 {
		key := rediscluster.KeyOnNode(t, fmt.Sprintf("hist-%d", index), index%2 == 0)
		keys = append(keys, key)
		want = append(want, fmt.Sprintf("%s=%d", key, index+1))

		for member := range index + 1 {
			if _, err := nodes.Node(key).SetAdd(key, fmt.Sprintf("m%d", member)); err != nil {
				t.Fatalf("seed cluster set: %v", err)
			}
		}
	}

	evaluated, err := collectSetCards(t.Context(), NewTestClientForHandle(nodes.Cluster), keys, 5)
	if err != nil {
		t.Fatalf("run cluster batches: %v", err)
	}

	if !slices.Equal(evaluated, want) {
		t.Fatalf("evaluated = %v, want %v", evaluated, want)
	}

	// One pipeline execution per batch, each fanned out by the cluster client to both nodes.
	if trips := recorder.Count(); trips != 2 {
		t.Fatalf("pipeline executions = %d, want 2", trips)
	}
}
