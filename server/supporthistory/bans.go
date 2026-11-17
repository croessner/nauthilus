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

package supporthistory

import (
	"cmp"
	"context"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Ban end reasons; only "released" and "superseded_by_new_activation" are recorded transitions.
const (
	endReleased       = "released"
	endSuperseded     = "superseded_by_new_activation"
	endPlannedPassed  = "planned_end_passed_unconfirmed"
	endPlannedLater   = "planned_end_after_window"
	endUnknown        = "unknown"
	activatingRequest = "NOT_A_CULPRIT"
	maxOrphanExcludes = 200

	// lifecycleRowsPerNetwork bounds the newest lifecycle rows read per candidate network.
	lifecycleRowsPerNetwork = 512
)

// Ban unknown codes.
const (
	unknownCreator           = "ACTIVATION_CREATOR_UNKNOWN"
	unknownEndUnrecorded     = "END_NOT_RECORDED_EVICTION_OR_SCRIPT_POSSIBLE"
	unknownLifecycleTrimmed  = "LIFECYCLE_ROWS_TRUNCATED"
	unknownHitsNotRead       = "HITS_NOT_READ"
	unknownContributions     = "CONTRIBUTIONS_NOT_READ"
	unknownUnconfirmedDuring = "UNCONFIRMED_ACTIVATION_DURING_BAN"
)

// banRefPattern matches a lifecycle event id.
var banRefPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// banKnownLimits are the coverage limits of brute-force evidence (contract §13.3, §13.7).
var banKnownLimits = []string{
	"RAW_ATTEMPTS_RETAINED_14_DAYS",
	"SUMMARY_COUNTS_ARE_UPPER_BOUNDS_UNDER_REPLAY",
	"BANS_WITHOUT_EVENTS_APPEAR_AS_ORPHAN_HITS",
	"ACTIVATING_REQUEST_IS_NOT_A_CULPRIT",
	"CROSSED_IS_A_HEURISTIC",
	"CLAIMED_NAMES_ARE_CLAIMS",
	"RULE_STATE_AS_RECORDED_NOT_CURRENT_CONFIG",
	limitNoGlobalOrder,
}

// banInstance is one ban instance assembled from lifecycle rows.
type banInstance struct {
	activation  LifecycleRecord
	resets      []LifecycleRecord
	unconfirmed []LifecycleRecord
	end         BanEnd
	until       time.Time
}

// validate normalizes and checks a ban search request.
func (r *BanSearchRequest) validate() *Error {
	if err := validateSchemaVersion(r.SchemaVersion); err != nil {
		return err
	}

	if (r.Target.IP == "") == (r.Target.Network == "") {
		return invalid(CodeInvalidRequest)
	}

	if r.Target.Network != "" {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(r.Target.Network))
		if err != nil {
			return invalid(CodeInvalidRequest)
		}

		r.Target.Network = banNetwork(prefix.Addr(), prefix.Bits())
	}

	ip, err := canonicalIP(r.Target.IP)
	if err != nil {
		return err
	}

	r.Target.IP = ip
	if r.Filter.BanRef != "" && !banRefPattern.MatchString(r.Filter.BanRef) {
		return invalid(CodeInvalidRequest)
	}

	if r.Subject != nil {
		subject := r.Subject.normalized()
		if err = subject.validate(); err != nil {
			return err
		}

		r.Subject = &subject
	}

	if err = validateWindow(r.Filter.From, r.Filter.Until); err != nil {
		return err
	}

	return validateAuditReference(r.AuditReference)
}

// banNetwork renders a network exactly like the host ban key (net.IPNet.String of the masked address).
func banNetwork(addr netip.Addr, bits int) string {
	addr = addr.Unmap()

	prefix, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}

	network := net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(bits, addr.BitLen())}

	return network.String()
}

// SearchBans explains the recorded bans of one IP or network inside a window of at most 31 days.
func (s *Service) SearchBans(ctx context.Context, caller Caller, request BanSearchRequest) (*BanSearchResult, error) {
	var subject []string

	need := permissionAttemptsRead
	if request.Subject != nil {
		subject, need = []string{request.Subject.Login, request.Subject.Account}, need|permissionDetailRead
	}

	ctx, call, err := s.begin(ctx, caller, operationBanSearch, need, subject, request.AuditReference, request.validate)
	if err != nil {
		return nil, err
	}

	result, searchErr := s.searchBans(ctx, caller, request)
	if searchErr != nil {
		call.finish(ctx, 0, searchErr)

		return nil, searchErr
	}

	call.finish(ctx, len(result.Bans), nil)

	return result, nil
}

// banScope is the validated state of one ban search page.
type banScope struct {
	window     Window
	queriedAt  time.Time
	cursor     *cursorState
	matcher    *subjectMatcher
	projection Projection
	digest     string
	trimmed    map[string]bool
	networks   []string
	limit      int
	partial    bool
}

// searchBans runs one authorized ban search page.
func (s *Service) searchBans(ctx context.Context, caller Caller, request BanSearchRequest) (*BanSearchResult, *Error) {
	if s.bans == nil {
		return nil, newError(CodeNotConfigured, nil)
	}

	scope, err := s.banScope(ctx, caller, request)
	if err != nil {
		return nil, err
	}

	lifecycle, readErr := s.bans.Lifecycle(ctx, LifecycleQuery{Networks: scope.networks,
		From: scope.queriedAt.Add(-lifecycleRetention), Until: scope.queriedAt, PerNetwork: lifecycleRowsPerNetwork})
	if readErr != nil {
		return nil, mapStoreError(ctx, readErr)
	}

	scope.trimmed = trimmedNetworks(lifecycle)
	instances := assembleInstances(lifecycle, scope.window, scope.queriedAt)
	result := s.newBanResult(scope, request.Target, lifecycle)
	page, next := pageInstances(instances, scope, request.Filter.BanRef)

	for _, instance := range page {
		result.Bans = append(result.Bans, s.explainBan(ctx, scope, instance))
	}

	result.Page.NextCursor = next
	result.OrphanHits = s.orphanHits(ctx, scope, instances)
	result.ThresholdTolerated = s.toleratedCount(ctx, scope)
	result.History = s.banCoverage(ctx, scope)
	result.ResultBasis = resultBasis(len(result.Bans) > 0, result.History, SourceBanLifecycle, false)

	return result, nil
}

// banScope validates paging and computes the candidate networks.
func (s *Service) banScope(ctx context.Context, caller Caller, request BanSearchRequest) (banScope, *Error) {
	scope := banScope{window: Window{From: request.Filter.From.UTC(), Until: request.Filter.Until.UTC()},
		queriedAt: s.now().UTC(), projection: caller.projection()}
	scope.digest = queryDigest(operationBanSearch, scope.projection, request.Target.IP, request.Target.Network,
		request.Filter.BanRef, scope.window.From.Format(time.RFC3339Nano), scope.window.Until.Format(time.RFC3339Nano))

	limit, err := pageLimit(request.Page.Limit, DefaultBanPageLimit, MaxBanPageLimit)
	if err != nil {
		return scope, err
	}

	scope.limit = limit
	if scope.cursor, err = decodeCursor(request.Page.Cursor, scope.digest); err != nil {
		return scope, err
	}

	if scope.cursor != nil {
		scope.queriedAt = scope.cursor.queriedAt()
	}

	if request.Subject != nil {
		_, accounts, resolveErr := subjectResolver{identity: s.identity, attempts: s.attempts}.resolve(ctx,
			*request.Subject, scope.window, false)
		if resolveErr != nil {
			return scope, mapStoreError(ctx, resolveErr)
		}

		matcher := newSubjectMatcher(request.Subject.Login, accounts, AttemptFilter{})
		scope.matcher = &matcher
	}

	if request.Target.Network != "" {
		scope.networks = []string{request.Target.Network}

		return scope, nil
	}

	scope.networks, scope.partial = s.candidateNetworks(ctx, netip.MustParseAddr(request.Target.IP))

	return scope, nil
}

// candidateNetworks derives the networks of an IP from the configured rule prefixes and the prefixes recorded in
// the lifecycle and summary tables; it never scans networks. partial reports a failed prefix lookup.
func (s *Service) candidateNetworks(ctx context.Context, addr netip.Addr) ([]string, bool) {
	var prefixes []Prefix
	if s.prefixes != nil {
		prefixes = append(prefixes, s.prefixes()...)
	}

	recorded, err := s.bans.Prefixes(ctx)
	prefixes = append(prefixes, recorded...)

	family := 6
	if addr.Unmap().Is4() {
		family = 4
	}

	var networks []string

	for _, prefix := range prefixes {
		if prefix.Family != family || prefix.Bits <= 0 || prefix.Bits > addr.Unmap().BitLen() {
			continue
		}

		if network := banNetwork(addr, prefix.Bits); network != "" {
			networks = append(networks, network)
		}
	}

	slices.Sort(networks)
	networks = slices.Compact(networks)

	partial := err != nil
	if len(networks) > maxCandidatePrefixes {
		networks, partial = networks[:maxCandidatePrefixes], true
	}

	return networks, partial
}

// trimmedNetworks reports the networks whose newest lifecycle rows filled the per-network bound, so older rows of
// those networks (earlier activations, resets) may be missing.
func trimmedNetworks(rows []LifecycleRecord) map[string]bool {
	counts := map[string]int{}
	trimmed := map[string]bool{}

	for _, row := range rows {
		if counts[row.Network]++; counts[row.Network] >= lifecycleRowsPerNetwork {
			trimmed[row.Network] = true
		}
	}

	return trimmed
}

// assembleInstances turns lifecycle rows into ban instances with their recorded or planned end.
func assembleInstances(rows []LifecycleRecord, window Window, queriedAt time.Time) []banInstance {
	byNetwork := map[string][]LifecycleRecord{}
	for _, row := range rows {
		byNetwork[row.Network] = append(byNetwork[row.Network], row)
	}

	var instances []banInstance

	for _, networkRows := range byNetwork {
		slices.SortStableFunc(networkRows, func(a, b LifecycleRecord) int {
			if order := a.At.Compare(b.At); order != 0 {
				return order
			}

			return cmp.Compare(a.EventID, b.EventID)
		})

		instances = append(instances, networkInstances(networkRows, window, queriedAt)...)
	}

	return instances
}

// networkInstances walks the ordered lifecycle rows of one network.
func networkInstances(rows []LifecycleRecord, window Window, queriedAt time.Time) []banInstance {
	var (
		instances []banInstance
		resets    []LifecycleRecord
		open      = -1
	)

	for _, row := range rows {
		switch row.Kind {
		case kindUnconfirmed:
			if open >= 0 && stillPlanned(instances[open], row.At) {
				// The key already existed: most likely the same ban, never a recorded end of it.
				instances[open].unconfirmed = append(instances[open].unconfirmed, row)

				continue
			}

			fallthrough
		case kindActivated:
			if open >= 0 {
				closeInstance(&instances[open], endSuperseded, row.At, nil)
			}

			instances = append(instances, banInstance{activation: row})
			open = len(instances) - 1
		case kindReleased:
			if open >= 0 {
				source := optional(row.ReleaseSource)
				closeInstance(&instances[open], endReleased, row.At, source)
				open = -1
			}
		case kindCountersReset:
			resets = append(resets, row)
		}
	}

	for index := range instances {
		instances[index].resets = resets
		if instances[index].end.Reason == "" {
			plannedEnd(&instances[index], window, queriedAt)
		}
	}

	return instances
}

// stillPlanned reports whether an instance without recorded end is still inside its planned ban time.
func stillPlanned(instance banInstance, at time.Time) bool {
	return instance.end.Reason == "" && (instance.activation.ExpiresAt == nil || instance.activation.ExpiresAt.After(at))
}

// closeInstance records a recorded end transition.
func closeInstance(instance *banInstance, reason string, at time.Time, source *string) {
	if instance.end.Reason != "" {
		return
	}

	if expires := instance.activation.ExpiresAt; expires != nil && expires.Before(at) {
		plannedEnd(instance, Window{Until: at}, at)

		return
	}

	instance.end = BanEnd{Reason: reason, At: timePointer(at), ReleaseSource: source}
	instance.until = at
}

// plannedEnd states the planned end of an instance without a recorded end transition.
func plannedEnd(instance *banInstance, window Window, queriedAt time.Time) {
	expires := instance.activation.ExpiresAt

	switch {
	case expires == nil:
		instance.end, instance.until = BanEnd{Reason: endUnknown}, queriedAt
	case expires.After(window.Until):
		instance.end, instance.until = BanEnd{Reason: endPlannedLater, At: timePointer(*expires)}, *expires
	default:
		instance.end, instance.until = BanEnd{Reason: endPlannedPassed, At: timePointer(*expires)}, *expires
	}
}

// pageInstances selects the instances overlapping the window, newest activation first.
func pageInstances(instances []banInstance, scope banScope, banRef string) ([]banInstance, *string) {
	var selected []banInstance

	for _, instance := range instances {
		if banRef != "" && instance.activation.EventID != banRef {
			continue
		}

		if instance.activation.At.Before(scope.window.Until) && instance.until.After(scope.window.From) {
			selected = append(selected, instance)
		}
	}

	slices.SortStableFunc(selected, func(a, b banInstance) int {
		if order := b.activation.At.Compare(a.activation.At); order != 0 {
			return order
		}

		return cmp.Compare(b.activation.EventID, a.activation.EventID)
	})

	if scope.cursor != nil {
		position := scope.cursor.position()
		selected = slices.DeleteFunc(selected, func(instance banInstance) bool {
			return !beforePosition(instance.activation.At, instance.activation.EventID, position)
		})
	}

	if len(selected) <= scope.limit {
		return selected, nil
	}

	last := selected[scope.limit-1].activation
	cursor := encodeCursor(AnchorPosition{At: last.At, Key: last.EventID}, scope.queriedAt, scope.digest)

	return selected[:scope.limit], &cursor
}

// beforePosition reports whether (at, key) sorts strictly after the newest-first position.
func beforePosition(at time.Time, key string, position AnchorPosition) bool {
	if order := at.Compare(position.At); order != 0 {
		return order < 0
	}

	return key < position.Key
}

// newBanResult creates the result with the lifecycle lists of the window.
func (s *Service) newBanResult(scope banScope, target BanTarget, rows []LifecycleRecord) *BanSearchResult {
	result := &BanSearchResult{SchemaVersion: SchemaVersion, QueriedAt: scope.queriedAt, Projection: string(scope.projection),
		Target: ResolvedTarget{IP: optional(target.IP), CandidateNetworks: append([]string{}, scope.networks...)},
		Bans:   []Ban{}, UnconfirmedActivations: []LifecycleEvent{}, Releases: []LifecycleEvent{},
		CounterResets: []LifecycleEvent{}, Page: BanPage{Limit: scope.limit}, ResultBasis: basisNoMatches}

	for _, row := range rows {
		if row.At.Before(scope.window.From) || !row.At.Before(scope.window.Until) {
			continue
		}

		event := lifecycleEvent(row, scope.projection)

		switch row.Kind {
		case kindUnconfirmed:
			result.UnconfirmedActivations = append(result.UnconfirmedActivations, event)
		case kindReleased:
			result.Releases = append(result.Releases, event)
		case kindCountersReset:
			result.CounterResets = append(result.CounterResets, event)
		}
	}

	return result
}

// lifecycleEvent projects one lifecycle row; operator identities are released to the detail role only.
func lifecycleEvent(row LifecycleRecord, projection Projection) LifecycleEvent {
	event := LifecycleEvent{At: row.At.UTC(), EventID: row.EventID, Kind: row.Kind, Network: row.Network, Rule: row.Rule,
		BucketID: optional(row.BucketID), ReleaseSource: optional(row.ReleaseSource), KeysRemoved: row.KeysRemoved}

	if projection == ProjectionDetail {
		event.OperatorClientID = optional(row.OperatorClientID)
	}

	return event
}
