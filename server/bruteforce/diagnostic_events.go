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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
)

// Brute-force count sources name the host decision point that applied an increment.
const (
	// CountSourceBackendFailure is a failed credential check.
	CountSourceBackendFailure = "backend_failure"
	// CountSourcePreAuthReject is the legacy pre-auth brute-force reject.
	CountSourcePreAuthReject = "pre_auth_reject"
	// CountSourceProtectedEndpoint is a failed protected-endpoint authentication.
	CountSourceProtectedEndpoint = "protected_endpoint"
	// CountSourcePolicyUpdatePrefix prefixes the Policy brute_force_update obligation with its feature.
	CountSourcePolicyUpdatePrefix = "policy_update"
)

// EventEmitter receives brute-force events; implementations never block the caller.
type EventEmitter interface {
	EmitBruteForceEvent(context.Context, pluginapi.BruteForceEvent)
}

// DiagnosticContext carries request facts that the counting decision point cannot derive itself.
type DiagnosticContext struct {
	// BanActive reports whether the request itself hit an existing ban; nil when the check did not run.
	BanActive *bool
	// CountSource names the decision point that applies increments.
	CountSource string
}

// slidingWindow is one bucket's epoch-aligned window pair, resolved at a single instant.
type slidingWindow struct {
	baseKey    string
	currentKey string
	prevKey    string
	weight     float64
	index      int64
}

// slidingWindowResult is the decoded SlidingWindowCounter reply.
type slidingWindowResult struct {
	current  *int64
	previous *int64
	total    float64
	limit    float64
	exceeded bool
}

// parseSlidingWindowResult decodes the counter reply {total, exceeded, limit, current, previous}; replies of older
// scripts without the window counts leave current and previous nil.
func parseSlidingWindowResult(result any, fallbackLimit float64) (slidingWindowResult, bool) {
	parts, ok := result.([]any)
	if !ok || len(parts) < 2 {
		return slidingWindowResult{}, false
	}

	totalText, _ := parts[0].(string)

	total, err := strconv.ParseFloat(totalText, 64)
	if err != nil {
		return slidingWindowResult{}, false
	}

	exceeded, _ := parts[1].(int64)
	decoded := slidingWindowResult{total: total, limit: fallbackLimit, exceeded: exceeded == 1}

	if len(parts) >= 3 {
		if limitText, isText := parts[2].(string); isText {
			if parsed, parseErr := strconv.ParseFloat(limitText, 64); parseErr == nil {
				decoded.limit = parsed
			}
		}
	}

	if len(parts) >= 5 {
		decoded.current = int64Part(parts[3])
		decoded.previous = int64Part(parts[4])
	}

	return decoded, true
}

// int64Part returns a Redis integer reply as a pointer, or nil for other reply types.
func int64Part(value any) *int64 {
	number, ok := value.(int64)
	if !ok {
		return nil
	}

	return &number
}

// bucketIdentity hashes the window-less counter key, so shared buckets of several rules share one identity.
func bucketIdentity(baseKey string) string {
	if baseKey == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(baseKey))

	return hex.EncodeToString(sum[:16])
}

// ruleFingerprint hashes the rule definition that governs counting and banning.
func ruleFingerprint(rule *config.BruteForceRule) string {
	if rule == nil {
		return ""
	}

	protocols := slices.Sorted(slices.Values(rule.GetFilterByProtocol()))
	clients := slices.Sorted(slices.Values(rule.GetFilterByOIDCCID()))
	canonical := strings.Join([]string{
		rule.Name, strconv.FormatInt(bucketWindowSeconds(rule.Period), 10), strconv.FormatUint(uint64(rule.CIDR), 10),
		strconv.FormatUint(uint64(rule.FailedRequests), 10), strconv.FormatBool(rule.IPv4), strconv.FormatBool(rule.IPv6),
		strings.Join(protocols, ","), strings.Join(clients, ","), rule.GetBanTime().String(),
	}, "\x00")
	sum := sha256.Sum256([]byte(canonical))

	return hex.EncodeToString(sum[:16])
}

// newEventID returns a random 128-bit hex identifier, or empty when randomness is unavailable.
func newEventID() string {
	var buffer [16]byte

	if _, err := rand.Read(buffer[:]); err != nil {
		return ""
	}

	return hex.EncodeToString(buffer[:])
}

// diagnosticsEnabled reports whether events are wired for this bucket manager.
func (bm *bucketManagerImpl) diagnosticsEnabled() bool {
	return bm != nil && bm.deps.Events != nil
}

// emitDiagnosticEvent completes the request header of one event and hands it to the emitter.
func (bm *bucketManagerImpl) emitDiagnosticEvent(event pluginapi.BruteForceEvent) {
	if !bm.diagnosticsEnabled() {
		return
	}

	event = completeEvent(event)
	event.RequestID = bm.guid
	event.ClientIP = bm.clientIP
	event.Protocol = bm.protocol
	event.OIDCClientID = bm.oidcCID

	if !event.Kind.Lifecycle() {
		event.ClaimedUsername = bm.username
		event.CountSource = bm.deps.Diagnostic.CountSource

		if event.BanActive == nil {
			event.BanActive = bm.deps.Diagnostic.BanActive
		}

		if bm.accountName != "" {
			known := true
			event.Account = bm.accountName
			event.AccountKnown = &known
		}
	}

	bm.deps.Events.EmitBruteForceEvent(bm.ctx, event)
}

// ruleEvent builds the rule and bucket part of an event for one network.
func (bm *bucketManagerImpl) ruleEvent(
	kind pluginapi.BruteForceEventKind,
	rule *config.BruteForceRule,
	network *net.IPNet,
) pluginapi.BruteForceEvent {
	event := pluginapi.BruteForceEvent{Kind: kind}
	if rule == nil {
		return event
	}

	event.Rule = rule.Name
	event.RuleFingerprint = ruleFingerprint(rule)
	event.PeriodSeconds = bucketWindowSeconds(rule.Period)
	event.BanTimeSeconds = int64(rule.GetBanTime().Seconds())
	event.FailedRequests = int64(rule.FailedRequests)
	event.CIDR = uint8(min(rule.CIDR, 128))

	if network == nil {
		return event
	}

	event.Network = network.String()
	event.IPFamily = networkFamily(network)
	_, event.BucketProtocol, event.BucketOIDCClient = bm.bruteForceBucketContextParts(rule)
	event.BucketID = bucketIdentity(bm.getBruteForceBucketBaseKey(rule, network))

	return event
}

// networkFamily returns 4 or 6 for a parsed network.
func networkFamily(network *net.IPNet) uint8 {
	if network.IP.To4() != nil {
		return 4
	}

	return 6
}

// withWindow copies window and counter facts into an event.
func withWindow(event pluginapi.BruteForceEvent, window slidingWindow, result slidingWindowResult) pluginapi.BruteForceEvent {
	index, weight, total, limit := window.index, window.weight, result.total, result.limit
	event.WindowIndex = &index
	event.Weight = &weight
	event.Total = &total
	event.Limit = &limit
	event.Current = result.current
	event.Previous = result.previous

	return event
}

// emitCountedEvent records one increment the counter really applied.
func (bm *bucketManagerImpl) emitCountedEvent(write *bucketCounterWrite, result slidingWindowResult) {
	event := withWindow(bm.ruleEvent(pluginapi.BruteForceCounted, write.rule, write.network), write.window, result)

	// The script adds exactly the increment to the current window, so the total before is total minus increment.
	crossed := result.total-float64(write.increment) <= result.limit && result.total > result.limit
	event.Crossed = &crossed

	bm.emitDiagnosticEvent(event)
}

// emitFactEvent records a pre-check fact based event (tolerated threshold or ban activation).
func (bm *bucketManagerImpl) emitFactEvent(
	kind pluginapi.BruteForceEventKind,
	rule *config.BruteForceRule,
	network *net.IPNet,
	mutate func(*pluginapi.BruteForceEvent),
) {
	if !bm.diagnosticsEnabled() {
		return
	}

	// The over-limit path does not hand the network on; it is the rule's network of this client.
	if network == nil && rule != nil {
		network, _ = bm.getNetwork(rule)
	}

	event := bm.ruleEvent(kind, rule, network)

	if fact := bm.bucketFactFor(rule); fact != nil && fact.counted {
		event = withWindow(event, fact.window, fact.result)
	}

	if mutate != nil {
		mutate(&event)
	}

	bm.emitDiagnosticEvent(event)
}

// emitBanHitEvent records a request rejected by an existing ban.
func (bm *bucketManagerImpl) emitBanHitEvent(rule *config.BruteForceRule, network *net.IPNet, source string) {
	bm.emitFactEvent(pluginapi.BruteForceBanHit, rule, network, func(event *pluginapi.BruteForceEvent) {
		event.HitSource = source
		event.BanActive = boolPointer(true)
	})
}

// emitBanActivatedEvent records a ban instance written by this request.
func (bm *bucketManagerImpl) emitBanActivatedEvent(
	kind pluginapi.BruteForceEventKind,
	rule *config.BruteForceRule,
	network *net.IPNet,
	activatedAt time.Time,
) {
	bm.emitFactEvent(kind, rule, network, func(event *pluginapi.BruteForceEvent) {
		event.ObservedAt = activatedAt.UTC()
		event.StoredRule = bm.bruteForceName

		if kind == pluginapi.BruteForceBanActivated && rule != nil {
			expiresAt := activatedAt.Add(rule.GetBanTime()).UTC()
			event.ExpiresAt = &expiresAt
		}
	})
}

// boolPointer returns a pointer to value.
func boolPointer(value bool) *bool {
	return &value
}

// bucketFactFor returns the pre-check fact of one rule when the counters were read.
func (bm *bucketManagerImpl) bucketFactFor(rule *config.BruteForceRule) *BucketPolicyFact {
	if rule == nil {
		return nil
	}

	for index := range bm.bucketPolicyFacts {
		if bm.bucketPolicyFacts[index].Name == rule.Name {
			return &bm.bucketPolicyFacts[index]
		}
	}

	return nil
}

// windowSuffix separates a bucket base key from its window index.
const windowSuffix = ":win:"

// BucketIdentityFromKey returns the bucket identity of one window key, matching the identity of counted events.
func BucketIdentityFromKey(windowKey string) string {
	index := strings.LastIndex(windowKey, windowSuffix)
	if index <= 0 {
		return ""
	}

	return bucketIdentity(windowKey[:index])
}

// RuleEventFields returns the rule part of a brute-force event for host code outside the bucket manager.
func RuleEventFields(kind pluginapi.BruteForceEventKind, rule *config.BruteForceRule, network string) pluginapi.BruteForceEvent {
	event := (&bucketManagerImpl{}).ruleEvent(kind, rule, nil)
	event.Network = network

	if _, parsed, err := net.ParseCIDR(network); err == nil {
		event.IPFamily = networkFamily(parsed)
	}

	return event
}

// EmitEvent completes the event header and hands it to emitter; a nil emitter drops the event.
func EmitEvent(ctx context.Context, emitter EventEmitter, event pluginapi.BruteForceEvent) {
	if emitter == nil {
		return
	}

	emitter.EmitBruteForceEvent(ctx, completeEvent(event))
}

// completeEvent fills the event identity, version, and observation time.
func completeEvent(event pluginapi.BruteForceEvent) pluginapi.BruteForceEvent {
	event.EventID = newEventID()
	event.Version = pluginapi.BruteForceEventVersion

	if event.ObservedAt.IsZero() {
		event.ObservedAt = time.Now().UTC()
	}

	return event
}
