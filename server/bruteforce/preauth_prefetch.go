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

package bruteforce

import (
	"context"
	"slices"

	"github.com/croessner/nauthilus/v4/server/bruteforce/l1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/croessner/nauthilus/v4/server/util"

	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// preAuthPrefetch holds the pre-authentication brute-force reads of one request.
//
// The RWP result is consumed once by the precheck. The L1 decision, the rule candidates, the ban-key states
// and the reputation counter are request-scoped snapshots shared by every later check of the same request.
// A nil command means that the value was not prefetched and consumers read it themselves.
type preAuthPrefetch struct {
	rules      []config.BruteForceRule
	l1Decision l1.Decision
	l1Found    bool
	candidates *repeatingCandidateResult
	rwp        *rediscli.ScriptCall
	banFields  []string
	banCmds    []*redis.IntCmd
	reputation *redis.StringCmd
}

// PrefetchPreAuthState reads the data-independent pre-authentication state in one Redis round trip.
//
// It queues the RWP check script, the EXISTS reads of every candidate ban key and the reputation HGET into
// one pipeline. A cached L1 block decision does not skip the pipeline: the RWP precheck still runs, and the
// policy-fact collection that follows an L1 hit reads the same ban keys and the same reputation counter, so
// it consumes the prefetched values instead of issuing its own reads. All reads happen before any write of
// the same request, so the snapshot matches what the sequential reads would return.
func (bm *bucketManagerImpl) PrefetchPreAuthState(rules []config.BruteForceRule) {
	tr := monittrace.New("nauthilus/bruteforce")

	ctx, sp := tr.Start(bm.ctx, "auth.bruteforce.preauth_prefetch",
		attribute.String("protocol", bm.protocol),
		attribute.String("oidc_cid", bm.oidcCID),
		attribute.Int("rules.total", len(rules)),
	)
	defer sp.End()

	prevCtx := bm.ctx

	bm.ctx = ctx
	defer func() {
		bm.ctx = prevCtx
	}()

	if bm.parsedIP == nil || bm.netByCIDR == nil {
		bm.PrepareNetcalc(rules)
	}

	prefetch := &preAuthPrefetch{rules: rules}
	prefetch.l1Decision, prefetch.l1Found = bm.lookupRepeatingL1Decision(rules)
	bm.preAuth = prefetch

	sp.SetAttributes(attribute.Bool("micro_cache.hit", prefetch.l1Blocks()))

	candidates := bm.gatherRepeatingCandidates(ctx, rules)
	prefetch.candidates = &candidates

	bm.execPreAuthPrefetch(ctx, sp, prefetch)
}

// execPreAuthPrefetch queues the pre-authentication reads into one pipeline.
// The pipeline runs on the write handle when it carries the RWP script, because EVALSHA is routed to
// masters anyway; without the script it stays on the read handle.
func (bm *bucketManagerImpl) execPreAuthPrefetch(ctx context.Context, sp trace.Span, prefetch *preAuthPrefetch) {
	rwpArgs := bm.preAuthRWPArgs()
	banFields := prefetch.banCandidateFields()
	reputationKey := bm.preAuthReputationKey(banFields)

	sp.SetAttributes(
		attribute.Bool("rwp", rwpArgs != nil),
		attribute.Int("ban_keys", len(banFields)),
		attribute.Bool("reputation", reputationKey != ""),
	)

	if rwpArgs == nil && len(banFields) == 0 {
		return
	}

	handle := bm.redis().GetReadHandle()
	if rwpArgs != nil {
		handle = bm.redis().GetWriteHandle()
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, bm.cfg())
	defer cancel()

	stats.GetMetrics().GetRedisRoundtripsTotal().WithLabelValues("pipeline_preauth_check").Inc()

	if len(banFields) > 0 {
		stats.GetMetrics().GetRedisReadCounter().Inc()
	}

	prefix := bm.cfg().GetServer().GetRedis().GetPrefix()
	pipeline := rediscli.NewScriptPipeline(bm.redis(), handle)

	// Every command is evaluated on its own by its consumer; the first pipeline error is not authoritative.
	_ = pipeline.Exec(dCtx, func(pctx context.Context, pipe redis.Pipeliner) {
		if rwpArgs != nil {
			prefetch.rwp = pipeline.EvalSha(pctx, pipe, rwpCheckScriptName, []string{rwpArgs.allowKey},
				rwpArgs.passwordHash, rwpArgs.argNow, rwpArgs.argTTL, rwpArgs.argThreshold)
		}

		for _, field := range banFields {
			prefetch.banCmds = append(prefetch.banCmds, pipe.Exists(pctx, rediscli.GetBruteForceBanKey(prefix, field)))
		}

		if reputationKey != "" {
			prefetch.reputation = pipe.HGet(pctx, reputationKey, reputationPositiveField)
		}
	})

	prefetch.banFields = banFields
}

// preAuthRWPArgs returns the RWP check arguments when the precheck will need Redis, or nil.
// Unknown accounts and already decided requests never run the RWP script.
func (bm *bucketManagerImpl) preAuthRWPArgs() *rwpScriptArgs {
	if bm.rwpDecision != nil || bm.accountName == "" {
		return nil
	}

	return bm.buildRWPScriptArgs()
}

// preAuthReputationKey returns the reputation key to prefetch when bucket counters will be evaluated.
func (bm *bucketManagerImpl) preAuthReputationKey(banFields []string) string {
	if bm.tolerate() == nil || len(banFields) == 0 {
		return ""
	}

	return bm.tolerate().GetReputationKey(bm.clientIP)
}

// l1Blocks reports whether the cached L1 decision blocks the request for one of the prefetched rules.
func (p *preAuthPrefetch) l1Blocks() bool {
	if !p.l1Found || !p.l1Decision.Blocked {
		return false
	}

	return slices.ContainsFunc(p.rules, func(rule config.BruteForceRule) bool {
		return rule.Name == p.l1Decision.Rule
	})
}

// banCandidateFields returns the candidate networks whose ban keys are prefetched.
func (p *preAuthPrefetch) banCandidateFields() []string {
	if p.candidates == nil || p.candidates.withError {
		return nil
	}

	return repeatingCandidateFields(p.candidates.candidates)
}

// covers reports whether the prefetch was taken for the same rule list.
func (p *preAuthPrefetch) covers(rules []config.BruteForceRule) bool {
	return p != nil && slices.EqualFunc(p.rules, rules, func(a, b config.BruteForceRule) bool {
		return a.Name == b.Name
	})
}

// takeRWPCheck returns the prefetched RWP check call once, or nil when the precheck must read Redis itself.
func (p *preAuthPrefetch) takeRWPCheck() *rediscli.ScriptCall {
	if p == nil || p.rwp == nil {
		return nil
	}

	call := p.rwp
	p.rwp = nil

	return call
}

// banKeyStates returns the prefetched EXISTS commands for exactly these networks and the first command
// error, matching what a dedicated EXISTS pipeline would report.
func (p *preAuthPrefetch) banKeyStates(networks []string) ([]*redis.IntCmd, bool, error) {
	if p == nil || p.banCmds == nil || !slices.Equal(p.banFields, networks) {
		return nil, false, nil
	}

	for _, cmd := range p.banCmds {
		if err := cmd.Err(); err != nil {
			return p.banCmds, true, err
		}
	}

	return p.banCmds, true, nil
}

// reputationCmd returns the prefetched reputation HGET, or nil when it was not prefetched.
func (p *preAuthPrefetch) reputationCmd() *redis.StringCmd {
	if p == nil {
		return nil
	}

	return p.reputation
}

// repeatingL1Decision returns the request's L1 decision, reusing the prefetched lookup for the same rules.
func (bm *bucketManagerImpl) repeatingL1Decision(rules []config.BruteForceRule) (l1.Decision, bool) {
	if bm.preAuth.covers(rules) {
		return bm.preAuth.l1Decision, bm.preAuth.l1Found
	}

	return bm.lookupRepeatingL1Decision(rules)
}

// repeatingCandidates returns the prefetched rule candidates for the same rules or gathers them.
func (bm *bucketManagerImpl) repeatingCandidates(ctx context.Context, rules []config.BruteForceRule) repeatingCandidateResult {
	if bm.preAuth.covers(rules) && bm.preAuth.candidates != nil {
		return *bm.preAuth.candidates
	}

	return bm.gatherRepeatingCandidates(ctx, rules)
}

// existsBanKeys returns the prefetched ban-key states or reads them in a dedicated pipeline.
func (bm *bucketManagerImpl) existsBanKeys(ctx context.Context, networks []string, metricLabel string) ([]*redis.IntCmd, error) {
	if cmds, ok, err := bm.preAuth.banKeyStates(networks); ok {
		return cmds, err
	}

	return bm.pipelineExistsBanKeys(ctx, networks, metricLabel)
}

// reputationPositive returns the positive reputation counter, preferring the request's prefetched value.
func (bm *bucketManagerImpl) reputationPositive(reputationKey string) int64 {
	cmd := bm.preAuth.reputationCmd()
	if cmd == nil {
		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(bm.ctx, bm.cfg())
		defer cancel()

		cmd = bm.redis().GetReadHandle().HGet(dCtx, reputationKey, reputationPositiveField)
	}

	if val, err := cmd.Int64(); err == nil {
		return val
	}

	return 0
}

// rwpCheckResult maps an RWPSlidingWindowCheck reply to the repeating-password verdict.
func rwpCheckResult(result any, err error) (bool, error) {
	if err != nil {
		return false, err
	}

	if v, ok := result.(int64); ok && v == 1 {
		return true, nil
	}

	return false, nil
}
