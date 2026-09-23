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

package redisslot

import (
	"context"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestSlotMatchesRedisClusterReferenceValues(t *testing.T) {
	tests := []struct {
		key  string
		want int
	}{
		{key: "123456789", want: 0x31C3},
		{key: "foo", want: 12182},
		{key: "bar", want: 5061},
		{key: "{foo}.bar", want: 12182},
		{key: "prefix:{foo}:suffix", want: 12182},
		{key: "{}foo", want: Slot("{}foo")},
	}

	for _, test := range tests {
		if got := Slot(test.key); got != test.want {
			t.Fatalf("Slot(%q) = %d, want %d", test.key, got, test.want)
		}
	}
}

func TestHashTagFollowsClusterSpecification(t *testing.T) {
	tests := map[string]string{
		"plain":          "plain",
		"a{tag}b":        "tag",
		"a{tag}b{other}": "tag",
		"a{}b{tag}":      "a{}b{tag}",
		"a{tag":          "a{tag",
		"a}tag{":         "a}tag{",
	}

	for key, want := range tests {
		if got := HashTag(key); got != want {
			t.Fatalf("HashTag(%q) = %q, want %q", key, got, want)
		}
	}
}

// guardRecorder captures guard reports without failing the surrounding test.
type guardRecorder struct {
	reports []string
}

// Helper satisfies Reporter.
func (r *guardRecorder) Helper() {}

// Errorf records one CROSSSLOT report.
func (r *guardRecorder) Errorf(format string, args ...any) {
	r.reports = append(r.reports, fmt.Sprintf(format, args...))
}

func TestGuardReportsCrossSlotScriptsTransactionsAndCommands(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	recorder := &guardRecorder{}
	guard := NewGuard(recorder, "p:").Attach(client)
	ctx := context.Background()

	_ = client.Eval(ctx, "return 1", []string{"p:{a}:x", "p:{a}:y"}, "p:{a}:z").Err()
	_ = client.MGet(ctx, "p:{a}:x", "p:{a}:y").Err()

	if len(recorder.reports) != 0 || guard.Units() != 2 {
		t.Fatalf("same-slot units reported %v, units = %d", recorder.reports, guard.Units())
	}

	_ = client.Eval(ctx, "return 1", []string{"p:{a}:x"}, "p:{b}:prefix:").Err()
	_ = client.MGet(ctx, "p:{a}:x", "p:{b}:y").Err()

	pipe := client.TxPipeline()
	pipe.Del(ctx, "p:{a}:x")
	pipe.Del(ctx, "p:{b}:y")
	_, _ = pipe.Exec(ctx)

	plain := client.Pipeline()
	plain.Del(ctx, "p:{a}:x")
	plain.Del(ctx, "p:{b}:y")
	_, _ = plain.Exec(ctx)

	if len(recorder.reports) != 3 {
		t.Fatalf("reports = %v, want script, MGET, and MULTI/EXEC violations only", recorder.reports)
	}
}

func TestCommandKeysCoverNativeMultiKeyCommands(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		cmd  redis.Cmder
		want []string
	}{
		{cmd: redis.NewStatusCmd(ctx, "mset", "k1", "v1", "k2", "v2"), want: []string{"k1", "k2"}},
		{cmd: redis.NewBoolCmd(ctx, "msetnx", "k1", "v1", "k2", "v2"), want: []string{"k1", "k2"}},
		{cmd: redis.NewStatusCmd(ctx, "rename", "src", "dst"), want: []string{"src", "dst"}},
		{cmd: redis.NewBoolCmd(ctx, "smove", "src", "dst", "member"), want: []string{"src", "dst"}},
		{cmd: redis.NewIntCmd(ctx, "copy", "src", "dst", "replace"), want: []string{"src", "dst"}},
		{cmd: redis.NewStringCmd(ctx, "lmove", "src", "dst", "left", "right"), want: []string{"src", "dst"}},
		{cmd: redis.NewStringCmd(ctx, "blmove", "src", "dst", "left", "right", 0), want: []string{"src", "dst"}},
		{cmd: redis.NewStringCmd(ctx, "rpoplpush", "src", "dst"), want: []string{"src", "dst"}},
		{cmd: redis.NewIntCmd(ctx, "sinterstore", "dst", "a", "b"), want: []string{"dst", "a", "b"}},
		{cmd: redis.NewIntCmd(ctx, "zunionstore", "dst", 2, "a", "b", "weights", 1, 2), want: []string{"dst", "a", "b"}},
		{cmd: redis.NewCmd(ctx, "eval", "return 1", 1, "k", "p:derived", "value"), want: []string{"k", "p:derived"}},
		{cmd: redis.NewCmd(ctx, "eval", "return 1"), want: nil},
	}

	for _, test := range tests {
		got := commandKeys(test.cmd, "p:")
		if fmt.Sprint(got) != fmt.Sprint(test.want) {
			t.Fatalf("commandKeys(%v) = %v, want %v", test.cmd.Args(), got, test.want)
		}
	}
}
