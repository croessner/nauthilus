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
	"errors"
	"reflect"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/testing/redisroundtrip"
	"github.com/redis/go-redis/v9"
)

const scriptPipelineSetScript = "AddToSetAndExpireLimit"

// newScriptPipelineTestClient returns a miniredis-backed client with the set script uploaded.
func newScriptPipelineTestClient(t *testing.T) (*redis.Client, Client) {
	t.Helper()

	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	server := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: server.Addr()})
	closeRedisTestClient(t, db)

	client := NewTestClient(db)

	ClearScriptCache()
	t.Cleanup(ClearScriptCache)

	if _, err := UploadScript(t.Context(), client, scriptPipelineSetScript, LuaScripts[scriptPipelineSetScript]); err != nil {
		t.Fatalf("upload script: %v", err)
	}

	return db, client
}

// execScriptPipelineWrites queues one plain INCR and one set script call into a script pipeline.
func execScriptPipelineWrites(t *testing.T, db *redis.Client, client Client) (*redis.IntCmd, *ScriptCall) {
	t.Helper()

	var (
		counter *redis.IntCmd
		call    *ScriptCall
	)

	ctx := t.Context()
	pipeline := NewScriptPipeline(client, db)

	err := pipeline.Exec(ctx, func(pipe redis.Pipeliner) {
		counter = pipe.Incr(ctx, "plain-counter")
		call = pipeline.EvalSha(ctx, pipe, scriptPipelineSetScript, []string{"script-set"}, "member", 60, 10)
	})
	if err != nil {
		t.Fatalf("pipeline error after NOSCRIPT retry = %v", err)
	}

	return counter, call
}

func TestScriptPipelineMixesPlainCommandsAndScriptsInOneRoundTrip(t *testing.T) {
	db, client := newScriptPipelineTestClient(t)
	recorder := redisroundtrip.Attach(db)

	counter, call := execScriptPipelineWrites(t, db, client)

	if trips := recorder.RoundTrips(); !reflect.DeepEqual(trips, [][]string{{"incr", "evalsha"}}) {
		t.Fatalf("round trips = %v, want one pipeline [incr evalsha]", trips)
	}

	if value, err := call.Result(); err != nil || value != int64(1) || counter.Val() != 1 {
		t.Fatalf("results = script:%v err:%v counter:%d, want 1, nil, 1", value, err, counter.Val())
	}
}

func TestScriptPipelineRetriesOnlyNoScriptCalls(t *testing.T) {
	db, client := newScriptPipelineTestClient(t)

	if err := db.ScriptFlush(t.Context()).Err(); err != nil {
		t.Fatalf("flush scripts: %v", err)
	}

	recorder := redisroundtrip.Attach(db)

	counter, call := execScriptPipelineWrites(t, db, client)

	trips := recorder.RoundTrips()
	if len(trips) < 3 || !reflect.DeepEqual(trips[0], []string{"incr", "evalsha"}) ||
		!reflect.DeepEqual(trips[len(trips)-1], []string{"evalsha"}) {
		t.Fatalf("round trips = %v, want pipeline, script upload, script-only retry", trips)
	}

	if value, err := call.Result(); err != nil || value != int64(1) {
		t.Fatalf("retried script result = %v err:%v, want 1", value, err)
	}

	if got := db.Get(t.Context(), "plain-counter").Val(); counter.Val() != 1 || got != "1" {
		t.Fatalf("plain counter = %d/%s, want a single increment", counter.Val(), got)
	}

	if isMember := db.SIsMember(t.Context(), "script-set", "member").Val(); !isMember {
		t.Fatal("retried script did not store its member")
	}
}

func TestScriptPipelineReportsUnknownScriptsWithoutQueueing(t *testing.T) {
	db, client := newScriptPipelineTestClient(t)
	recorder := redisroundtrip.Attach(db)
	ctx := t.Context()
	pipeline := NewScriptPipeline(client, db)

	var call *ScriptCall

	err := pipeline.Exec(ctx, func(pipe redis.Pipeliner) {
		call = pipeline.EvalSha(ctx, pipe, "UnknownScript", []string{"key"})
	})

	if !errors.Is(err, ErrScriptNotFound) || !errors.Is(call.Err(), ErrScriptNotFound) || call.Name() != "UnknownScript" {
		t.Fatalf("unknown script call = %s err:%v, want ErrScriptNotFound", call.Name(), call.Err())
	}

	if got := recorder.Count(); got != 0 {
		t.Fatalf("unknown script issued %d round trips, want none", got)
	}
}
