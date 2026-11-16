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

package backend

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/redis/go-redis/v9"
)

// accountMappingScanCount is the HSCAN COUNT hint. One user-hash shard holds roughly 1/256 of all stored
// login mappings, so a single iteration usually covers a whole shard.
const accountMappingScanCount int64 = 512

// ErrAccountMappingReaderUnavailable reports that no Redis client is available for mapping reads.
var ErrAccountMappingReaderUnavailable = errors.New("account mapping reader has no redis client")

// AccountMappingLookup is the stored login-name to account mapping state owned by one login name.
//
// The mapping is the data brute-force protection uses to attribute requests to accounts. It is written
// by authentication whenever a backend found the user and is never verified against the backend again,
// so it can be stale after renames or removals.
type AccountMappingLookup struct {
	// Err is set when the mappings could not be read completely; Fields and Accounts are then partial.
	Err error

	// Username is the requested login name.
	Username string

	// Fields lists the owned user-hash fields (username|protocol|oidcClientID), sorted.
	Fields []string

	// Accounts lists the distinct non-empty mapped account names, sorted and treated as opaque values.
	Accounts []string
}

// AccountMappingReader reads stored login-name to account mappings without any side effect.
//
// It only issues HSCAN, and always on the primary that owns the user-hash shard: replicas could lag behind
// authentication writes, and a scan cursor must stay on one node. A cluster client may route read-only
// pipelines to replicas (route_reads_to_replicas, route_by_latency, route_randomly), so cluster scans use the
// slot master's node client directly. It neither reads nor fills the in-process account cache.
type AccountMappingReader struct {
	Cfg   config.File
	Redis rediscli.Client
}

// pipelineClient is the narrow client surface needed to send one scan round to one node.
type pipelineClient interface {
	Pipeline() redis.Pipeliner
}

// scanGroup collects the scans of one round that go to the same primary.
type scanGroup struct {
	client pipelineClient
	scans  []*accountMappingScan
}

// accountMappingScan tracks the incremental HSCAN state of one requested login name.
type accountMappingScan struct {
	err      error
	fields   map[string]struct{}
	accounts map[string]struct{}
	username string
	key      string
	pattern  string
	cursor   uint64
	done     bool
}

// Read resolves the stored mappings of one login name.
func (r AccountMappingReader) Read(ctx context.Context, username string) AccountMappingLookup {
	return r.ReadMany(ctx, []string{username})[0]
}

// ReadMany resolves the stored mappings of the given login names in request order.
//
// Every scan round sends one HSCAN step per unfinished name in a single pipeline, so the work grows with
// the requested names and their shards, never with a full account scan. The caller's context bounds the
// whole call; cancellation or a deadline marks every unfinished name as failed.
func (r AccountMappingReader) ReadMany(ctx context.Context, usernames []string) []AccountMappingLookup {
	scans := r.newScans(usernames)
	more := true

	for more {
		more = r.scanRound(ctx, scans)
	}

	results := make([]AccountMappingLookup, len(scans))
	for index, scan := range scans {
		results[index] = scan.lookup()
	}

	return results
}

// newScans prepares one scan state per requested login name.
func (r AccountMappingReader) newScans(usernames []string) []*accountMappingScan {
	scans := make([]*accountMappingScan, len(usernames))

	var prefix string
	if r.Cfg != nil {
		prefix = r.Cfg.GetServer().GetRedis().GetPrefix()
	}

	for index, username := range usernames {
		scans[index] = &accountMappingScan{
			fields:   make(map[string]struct{}),
			accounts: make(map[string]struct{}),
			username: username,
			key:      rediscli.GetUserHashKey(prefix, username),
			pattern:  escapeRedisGlob(username) + "|*",
		}

		if r.Redis == nil {
			scans[index].fail(ErrAccountMappingReaderUnavailable)
		}
	}

	return scans
}

// scanRound sends one HSCAN step for all unfinished names, pipelined per primary, and reports whether work
// remains.
func (r AccountMappingReader) scanRound(ctx context.Context, scans []*accountMappingScan) bool {
	pending := pendingScans(scans)
	if len(pending) == 0 {
		return false
	}

	if err := ctx.Err(); err != nil {
		failScans(pending, err)

		return false
	}

	for _, group := range r.groupByPrimary(ctx, pending) {
		scanGroupRound(ctx, group)
	}

	return len(pendingScans(scans)) > 0
}

// groupByPrimary assigns every pending scan to the client of the primary that owns its key; a scan whose
// primary cannot be determined fails closed.
func (r AccountMappingReader) groupByPrimary(ctx context.Context, pending []*accountMappingScan) []*scanGroup {
	handle := r.Redis.GetWriteHandle()
	cluster, isCluster := handle.(*redis.ClusterClient)
	groups := make([]*scanGroup, 0, 1)
	byClient := make(map[pipelineClient]*scanGroup)

	for _, scan := range pending {
		var client pipelineClient = handle

		if isCluster {
			master, err := cluster.MasterForKey(ctx, scan.key)
			if err != nil {
				scan.fail(err)

				continue
			}

			client = master
		}

		group, ok := byClient[client]
		if !ok {
			group = &scanGroup{client: client}
			byClient[client] = group
			groups = append(groups, group)
		}

		group.scans = append(group.scans, scan)
	}

	return groups
}

// scanGroupRound sends one pipelined HSCAN step for the scans of one primary.
func scanGroupRound(ctx context.Context, group *scanGroup) {
	pipe := group.client.Pipeline()
	cmds := make([]*redis.ScanCmd, len(group.scans))

	for index, scan := range group.scans {
		cmds[index] = pipe.HScan(ctx, scan.key, scan.cursor, scan.pattern, accountMappingScanCount)
	}

	stats.GetMetrics().GetRedisReadCounter().Inc()

	// A failed pipeline still carries one error per command; apply marks each of those scans as failed.
	_, _ = pipe.Exec(ctx)

	for index, scan := range group.scans {
		scan.apply(cmds[index])
	}
}

// pendingScans returns the scans that still need another HSCAN step.
func pendingScans(scans []*accountMappingScan) []*accountMappingScan {
	pending := make([]*accountMappingScan, 0, len(scans))

	for _, scan := range scans {
		if !scan.done {
			pending = append(pending, scan)
		}
	}

	return pending
}

// failScans marks every given scan as failed with err.
func failScans(scans []*accountMappingScan, err error) {
	for _, scan := range scans {
		scan.fail(err)
	}
}

// fail finishes the scan with an error and keeps what was read before.
func (s *accountMappingScan) fail(err error) {
	s.err = err
	s.done = true
}

// apply consumes one HSCAN reply and keeps only fields owned by this exact login name.
func (s *accountMappingScan) apply(cmd *redis.ScanCmd) {
	pairs, cursor, err := cmd.Result()
	if err != nil {
		s.fail(err)

		return
	}

	for index := 0; index+1 < len(pairs); index += 2 {
		s.add(pairs[index], pairs[index+1])
	}

	s.cursor = cursor
	s.done = cursor == 0
}

// add records one field and its account when the field belongs to this login name.
func (s *accountMappingScan) add(field string, account string) {
	owner, ok := accountcache.AccountMappingFieldUsername(field)
	if !ok || owner != s.username {
		return
	}

	s.fields[field] = struct{}{}

	if account != "" {
		s.accounts[account] = struct{}{}
	}
}

// lookup converts the scan state into a sorted, deduplicated result.
func (s *accountMappingScan) lookup() AccountMappingLookup {
	return AccountMappingLookup{
		Err:      s.err,
		Username: s.username,
		Fields:   sortedSetMembers(s.fields),
		Accounts: sortedSetMembers(s.accounts),
	}
}

// sortedSetMembers returns the members of a string set in ascending order.
func sortedSetMembers(set map[string]struct{}) []string {
	members := make([]string, 0, len(set))
	for member := range set {
		members = append(members, member)
	}

	sort.Strings(members)

	return members
}

// escapeRedisGlob escapes glob metacharacters so a login name only matches itself in a MATCH pattern.
func escapeRedisGlob(value string) string {
	var builder strings.Builder

	builder.Grow(len(value))

	// Iterate bytes, not runes: all metacharacters are ASCII and invalid UTF-8 must stay byte-exact.
	for index := range len(value) {
		switch value[index] {
		case '*', '?', '[', ']', '\\':
			builder.WriteByte('\\')
		}

		builder.WriteByte(value[index])
	}

	return builder.String()
}
