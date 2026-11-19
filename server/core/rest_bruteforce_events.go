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

package core

import (
	"context"
	"sort"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/bruteforce"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	mdauth "github.com/croessner/nauthilus/v4/server/middleware/auth"

	"github.com/gin-gonic/gin"
)

// bruteForceFlushAudit carries the bounded operator reference of one administrative flush.
type bruteForceFlushAudit struct {
	source     string
	clientID   string
	authMethod string
	requestID  string
}

// bruteForceBucketFlushTarget remembers which rule and network a flushed counter key belongs to.
type bruteForceBucketFlushTarget struct {
	rule    *config.BruteForceRule
	network string
}

// withBruteForceFlushAudit returns deps that report the flush of this request with its operator reference.
func (r restAdminDeps) withBruteForceFlushAudit(ctx *gin.Context, source string) restAdminDeps {
	r.flushAudit = newBruteForceFlushAudit(ctx, source)

	return r
}

// newBruteForceFlushAudit reads the caller reference the authentication middleware left on the request.
func newBruteForceFlushAudit(ctx *gin.Context, source string) bruteForceFlushAudit {
	audit := bruteForceFlushAudit{source: source}
	if ctx == nil {
		return audit
	}

	audit.requestID = ctx.GetString(definitions.CtxGUIDKey)
	audit.authMethod = ctx.GetString(definitions.CtxAuthMethodKey)

	if caller := mdauth.CallerFromContext(ctx); caller != nil {
		audit.clientID = caller.Identity()

		if audit.authMethod == "" {
			audit.authMethod = string(caller.Method())
		}
	}

	return audit
}

// reportBruteForceFlush emits release and counter-reset events for the keys a flush really removed.
func reportBruteForceFlush(ctx context.Context, deps restAdminDeps, plan *bruteForceFlushPlan, removed []string) {
	if deps.BruteForceEvents == nil || plan == nil || len(removed) == 0 {
		return
	}

	resets := make(map[string]*pluginapi.BruteForceEvent)

	for _, key := range removed {
		if target, found := plan.banTargets[key]; found {
			event := bruteforce.RuleEventFields(pluginapi.BruteForceBanReleased, target.rule, target.network)
			event.StoredRule = target.storedRule()
			deps.flushAudit.apply(&event)
			bruteforce.EmitEvent(ctx, deps.BruteForceEvents, event)

			continue
		}

		bucket, found := plan.bucketTargets[key]
		if !found {
			continue
		}

		bucketID := bruteforce.BucketIdentityFromKey(key)

		reset := resets[bucketID]
		if reset == nil {
			event := bruteforce.RuleEventFields(pluginapi.BruteForceCountersReset, bucket.rule, bucket.network)
			event.BucketID = bucketID
			deps.flushAudit.apply(&event)
			resets[bucketID] = &event
			reset = &event
		}

		removedKeys := int64(1)
		if reset.KeysRemoved != nil {
			removedKeys += *reset.KeysRemoved
		}

		reset.KeysRemoved = &removedKeys
	}

	emitBruteForceResets(ctx, deps.BruteForceEvents, resets)
}

// emitBruteForceResets emits counter-reset events in stable bucket order.
func emitBruteForceResets(ctx context.Context, emitter bruteforce.EventEmitter, resets map[string]*pluginapi.BruteForceEvent) {
	bucketIDs := make([]string, 0, len(resets))
	for bucketID := range resets {
		bucketIDs = append(bucketIDs, bucketID)
	}

	sort.Strings(bucketIDs)

	for _, bucketID := range bucketIDs {
		bruteforce.EmitEvent(ctx, emitter, *resets[bucketID])
	}
}

// apply copies the operator reference into one lifecycle event.
func (a bruteForceFlushAudit) apply(event *pluginapi.BruteForceEvent) {
	event.ReleaseSource = a.source
	event.OperatorClientID = a.clientID
	event.OperatorAuthMethod = a.authMethod
	event.RequestID = a.requestID
}
