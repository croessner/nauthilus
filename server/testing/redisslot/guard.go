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
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"
)

const (
	// commandMulti opens a MULTI/EXEC block in a go-redis transaction pipeline.
	commandMulti = "multi"
	// commandExec closes a MULTI/EXEC block in a go-redis transaction pipeline.
	commandExec = "exec"
)

// Reporter is the subset of testing.TB that the guard needs to report violations.
type Reporter interface {
	Helper()
	Errorf(format string, args ...any)
}

// Guard is a go-redis hook that reports every atomic operation whose keys span several hash slots.
//
// It inspects Lua scripts (declared KEYS plus ARGV values that start with the key prefix, which is how
// scripts receive key prefixes they extend at runtime), MULTI/EXEC transactions, and native multi-key
// commands. Plain pipelines are split per command by Redis Cluster clients and are therefore checked
// command by command. Attach it to a client backed by miniredis to get CROSSSLOT coverage without a
// real cluster.
type Guard struct {
	reporter  Reporter
	keyPrefix string
	mu        sync.Mutex
	units     int
}

var _ redis.Hook = (*Guard)(nil)

// NewGuard creates a guard that treats ARGV values starting with keyPrefix as script-derived keys.
func NewGuard(reporter Reporter, keyPrefix string) *Guard {
	return &Guard{reporter: reporter, keyPrefix: keyPrefix}
}

// Attach registers the guard on a go-redis client and returns the guard for chaining.
func (g *Guard) Attach(client redis.UniversalClient) *Guard {
	client.AddHook(g)

	return g
}

// Units returns how many multi-key atomic operations were inspected, so tests can prove coverage.
func (g *Guard) Units() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.units
}

// DialHook leaves connection setup untouched.
func (g *Guard) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

// ProcessHook inspects one standalone command.
func (g *Guard) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		g.inspect(commandKeys(cmd, g.keyPrefix), cmd.Name())

		return next(ctx, cmd)
	}
}

// ProcessPipelineHook inspects a MULTI/EXEC block as one unit and plain pipelines per command.
func (g *Guard) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if len(cmds) > 0 && cmds[0].Name() == commandMulti {
			g.inspect(transactionKeys(cmds, g.keyPrefix), "multi/exec")
		} else {
			for _, cmd := range cmds {
				g.inspect(commandKeys(cmd, g.keyPrefix), cmd.Name())
			}
		}

		return next(ctx, cmds)
	}
}

// inspect records one atomic unit and reports it when its keys map to more than one slot.
func (g *Guard) inspect(keys []string, unit string) {
	if len(keys) < 2 {
		return
	}

	g.mu.Lock()
	g.units++
	g.mu.Unlock()

	slot := Slot(keys[0])

	for _, key := range keys[1:] {
		if Slot(key) != slot {
			g.reporter.Helper()
			g.reporter.Errorf("CROSSSLOT in %s: %q (slot %d) and %q (slot %d)", unit, keys[0], slot, key, Slot(key))

			return
		}
	}
}

// transactionKeys collects the keys of every command queued between MULTI and EXEC.
func transactionKeys(cmds []redis.Cmder, keyPrefix string) []string {
	var keys []string

	for _, cmd := range cmds {
		switch cmd.Name() {
		case commandMulti, commandExec:
			continue
		}

		keys = append(keys, commandKeys(cmd, keyPrefix)...)
	}

	return keys
}

// commandKeys extracts the keys that one command addresses.
//
// Scripts contribute their declared KEYS and every ARGV value with the key prefix. Native multi-key
// commands contribute all their keys (MSET every second argument, source/destination commands their two
// keys, Z*STORE the destination and the counted sources); every other command contributes its first
// argument.
func commandKeys(cmd redis.Cmder, keyPrefix string) []string {
	args := cmd.Args()
	if len(args) < 2 {
		return nil
	}

	switch strings.ToLower(cmd.Name()) {
	case "eval", "evalsha", "eval_ro", "evalsha_ro", "fcall", "fcall_ro":
		return scriptKeys(args, keyPrefix)
	case "mget", "del", "unlink", "exists", "touch", "watch", "sinter", "sunion", "sdiff", "sinterstore", "sunionstore", "sdiffstore":
		return stringArgs(args[1:])
	case "mset", "msetnx":
		return everySecondArg(args[1:])
	case "rename", "renamenx", "smove", "copy", "lmove", "blmove", "rpoplpush", "brpoplpush":
		return stringArgs(args[1:min(3, len(args))])
	case "zunionstore", "zinterstore", "zdiffstore":
		sources, _ := countedKeys(args, 2)

		return append(stringArgs(args[1:2]), sources...)
	default:
		return stringArgs(args[1:2])
	}
}

// everySecondArg returns the keys of key/value argument pairs.
func everySecondArg(args []any) []string {
	keys := make([]any, 0, (len(args)+1)/2)

	for index := 0; index < len(args); index += 2 {
		keys = append(keys, args[index])
	}

	return stringArgs(keys)
}

// countedKeys returns the keys that follow a numkeys argument at countIndex and the index after them.
func countedKeys(args []any, countIndex int) ([]string, int) {
	if countIndex >= len(args) {
		return nil, len(args)
	}

	count, err := strconv.Atoi(fmt.Sprint(args[countIndex]))
	if err != nil || count < 0 || countIndex+1+count > len(args) {
		return nil, len(args)
	}

	end := countIndex + 1 + count

	return stringArgs(args[countIndex+1 : end]), end
}

// scriptKeys returns declared script keys plus prefixed ARGV values used to derive further keys.
func scriptKeys(args []any, keyPrefix string) []string {
	keys, end := countedKeys(args, 2)

	for _, value := range stringArgs(args[end:]) {
		if keyPrefix != "" && strings.HasPrefix(value, keyPrefix) {
			keys = append(keys, value)
		}
	}

	return keys
}

// stringArgs keeps the string-typed arguments of a command.
func stringArgs(args []any) []string {
	values := make([]string, 0, len(args))

	for _, arg := range args {
		if value, ok := arg.(string); ok {
			values = append(values, value)
		}
	}

	return values
}
