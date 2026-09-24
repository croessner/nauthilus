// Copyright (C) 2026 Christian Rößner
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
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/testing/redisslot"
	"github.com/redis/go-redis/v9"
)

// Limitation: the fixture below is a two-node cluster made of two miniredis servers with a static slot map.
// It proves slot-local script keys, per-node splitting of cross-slot pipelines and a NOSCRIPT on one node.
// miniredis does not own slots, so MOVED and ASK redirections cannot be simulated; the repository has no
// cluster mock that answers them, and go-redis handles those redirections below the ScriptPipeline.

// clusterSlotSplit is the first slot of the second fixture node.
const clusterSlotSplit = 8192

// scriptPipelineCounterScript is the two-key script used to prove slot-local script keys.
const scriptPipelineCounterScript = "SlidingWindowCounter"

// scriptPipelineCluster is a two-node Redis Cluster fixture backed by two miniredis servers.
type scriptPipelineCluster struct {
	low     *miniredis.Miniredis
	high    *miniredis.Miniredis
	cluster *redis.ClusterClient
	guard   *redisslot.Guard
	client  Client
}

// clusterTestClient exposes a cluster handle through the Client interface.
type clusterTestClient struct {
	handle *redis.ClusterClient
}

// GetWriteHandle returns the cluster handle.
func (c *clusterTestClient) GetWriteHandle() redis.UniversalClient {
	return c.handle
}

// GetReadHandle returns the cluster handle.
func (c *clusterTestClient) GetReadHandle() redis.UniversalClient {
	return c.handle
}

// GetReadHandles returns no extra handles because the cluster handle serves reads and writes.
func (c *clusterTestClient) GetReadHandles() []redis.UniversalClient {
	return nil
}

// GetWritePipeline returns a pipeline on the cluster handle.
func (c *clusterTestClient) GetWritePipeline() redis.Pipeliner {
	return c.handle.Pipeline()
}

// GetReadPipeline returns a pipeline on the cluster handle.
func (c *clusterTestClient) GetReadPipeline() redis.Pipeliner {
	return c.handle.Pipeline()
}

// Close leaves the handle to the test cleanup.
func (c *clusterTestClient) Close() {}

// GetSecurityManager returns no security manager because the fixture never encrypts.
func (c *clusterTestClient) GetSecurityManager() *SecurityManager {
	return nil
}

// newScriptPipelineCluster starts two miniredis nodes that split the slot range and uploads the scripts.
func newScriptPipelineCluster(t *testing.T) *scriptPipelineCluster {
	t.Helper()

	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	low := miniredis.RunT(t)
	high := miniredis.RunT(t)

	cluster := redis.NewClusterClient(&redis.ClusterOptions{
		ClusterSlots: func(context.Context) ([]redis.ClusterSlot, error) {
			return []redis.ClusterSlot{
				{Start: 0, End: clusterSlotSplit - 1, Nodes: []redis.ClusterNode{{Addr: low.Addr()}}},
				{Start: clusterSlotSplit, End: 16383, Nodes: []redis.ClusterNode{{Addr: high.Addr()}}},
			}, nil
		},
	})

	t.Cleanup(func() { _ = cluster.Close() })

	fixture := &scriptPipelineCluster{
		low:     low,
		high:    high,
		cluster: cluster,
		guard:   redisslot.NewGuard(t, "").Attach(cluster),
		client:  &clusterTestClient{handle: cluster},
	}

	ClearScriptCache()
	t.Cleanup(ClearScriptCache)

	for _, name := range []string{scriptPipelineSetScript, scriptPipelineCounterScript} {
		if _, err := UploadScript(t.Context(), fixture.client, name, LuaScripts[name]); err != nil {
			t.Fatalf("upload %s: %v", name, err)
		}
	}

	return fixture
}

// keyOnNode returns a key named after base whose slot is served by the low or the high node.
func keyOnNode(t *testing.T, base string, high bool) string {
	t.Helper()

	for index := range 1000 {
		key := fmt.Sprintf("%s-%d", base, index)
		if (redisslot.Slot(key) >= clusterSlotSplit) == high {
			return key
		}
	}

	t.Fatalf("no key for %s on the requested node", base)

	return ""
}

// queueCounter queues one SlidingWindowCounter increment that writes currentKey.
func queueCounter(ctx context.Context, pipeline *ScriptPipeline, pipe redis.Pipeliner, currentKey, prevKey string) *ScriptCall {
	return pipeline.EvalSha(ctx, pipe, scriptPipelineCounterScript, []string{currentKey, prevKey},
		1, 0, 60, 10, 0, 0, 0, 1, 0, 0, 0)
}

func TestScriptPipelineKeepsScriptKeysInOneSlotAndSplitsPlainCommandsOnCluster(t *testing.T) {
	fixture := newScriptPipelineCluster(t)
	pipeline := NewScriptPipeline(fixture.client, fixture.cluster)
	lowKey := keyOnNode(t, "plain", false)
	highKey := keyOnNode(t, "plain", true)

	var (
		counter  *ScriptCall
		lowSet   *redis.StatusCmd
		highSet  *redis.StatusCmd
		setCalls []*ScriptCall
	)

	// The counter keys hash to different slots on purpose; the pipeline must move them into one slot.
	currentKey := keyOnNode(t, "counter-current", false)
	prevKey := keyOnNode(t, "counter-prev", true)

	err := pipeline.Exec(t.Context(), func(pctx context.Context, pipe redis.Pipeliner) {
		counter = queueCounter(pctx, pipeline, pipe, currentKey, prevKey)
		lowSet = pipe.Set(pctx, lowKey, "low", 0)
		highSet = pipe.Set(pctx, highKey, "high", 0)

		for _, high := range []bool{false, true} {
			setCalls = append(setCalls, pipeline.EvalSha(pctx, pipe, scriptPipelineSetScript,
				[]string{keyOnNode(t, "set", high)}, "member", 60, 10))
		}
	})
	if err != nil {
		t.Fatalf("cluster pipeline error = %v", err)
	}

	if len(counter.keys) != 2 || redisslot.Slot(counter.keys[0]) != redisslot.Slot(counter.keys[1]) {
		t.Fatalf("counter script keys = %v, want both keys in one slot", counter.keys)
	}

	if fixture.guard.Units() == 0 {
		t.Fatal("slot guard inspected no multi-key script call")
	}

	for _, call := range append([]*ScriptCall{counter}, setCalls...) {
		if call.Err() != nil {
			t.Fatalf("script %s failed on the cluster: %v", call.Name(), call.Err())
		}
	}

	if lowSet.Err() != nil || highSet.Err() != nil {
		t.Fatalf("plain commands failed: low=%v high=%v", lowSet.Err(), highSet.Err())
	}

	assertNodeValue(t, fixture.low, lowKey, "low")
	assertNodeValue(t, fixture.high, highKey, "high")

	if fixture.low.Exists(highKey) || fixture.high.Exists(lowKey) {
		t.Fatal("cross-slot plain commands were not split by node")
	}
}

func TestScriptPipelineRetriesNoScriptOnOneClusterNodeOnly(t *testing.T) {
	fixture := newScriptPipelineCluster(t)
	pipeline := NewScriptPipeline(fixture.client, fixture.cluster)
	lowKey := "{" + keyOnNode(t, "low", false) + "}"
	highSetKey := keyOnNode(t, "retry-set", true)

	// Only the high node loses its scripts, as after a restart of one cluster member.
	highNode := redis.NewClient(&redis.Options{Addr: fixture.high.Addr()})

	t.Cleanup(func() { _ = highNode.Close() })

	if err := highNode.ScriptFlush(t.Context()).Err(); err != nil {
		t.Fatalf("flush high node scripts: %v", err)
	}

	var counter, setCall *ScriptCall

	err := pipeline.Exec(t.Context(), func(pctx context.Context, pipe redis.Pipeliner) {
		counter = queueCounter(pctx, pipeline, pipe, lowKey+":current", lowKey+":prev")
		setCall = pipeline.EvalSha(pctx, pipe, scriptPipelineSetScript, []string{highSetKey}, "member", 60, 10)
	})
	if err != nil {
		t.Fatalf("pipeline error after NOSCRIPT retry = %v", err)
	}

	if counter.Err() != nil || setCall.Err() != nil {
		t.Fatalf("script calls after retry: counter=%v set=%v", counter.Err(), setCall.Err())
	}

	// The counter ran on the healthy node and must not run again; the set write was retried there.
	assertNodeValue(t, fixture.low, lowKey+":current", "1")

	if ok, _ := fixture.high.SIsMember(highSetKey, "member"); !ok {
		t.Fatal("retried script did not store its member on the flushed node")
	}

	// The retry re-uploaded the script to the flushed node.
	sha, err := UploadScript(t.Context(), fixture.client, scriptPipelineSetScript, LuaScripts[scriptPipelineSetScript])
	if err != nil {
		t.Fatalf("resolve script SHA: %v", err)
	}

	if exists, err := highNode.ScriptExists(t.Context(), sha).Result(); err != nil || len(exists) != 1 || !exists[0] {
		t.Fatalf("script on flushed node after retry = %v err:%v, want re-uploaded", exists, err)
	}
}

// assertNodeValue verifies that key holds want on exactly the given node.
func assertNodeValue(t *testing.T, node *miniredis.Miniredis, key string, want string) {
	t.Helper()

	got, err := node.Get(key)
	if err != nil || got != want {
		t.Fatalf("node value of %q = %q err:%v, want %q", key, got, err, want)
	}
}
