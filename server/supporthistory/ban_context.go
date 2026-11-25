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
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Ban context statuses.
const (
	contextMatched      = "matched"
	contextOverlapOnly  = "overlap_only"
	contextNoBan        = "no_recorded_ban"
	contextNotEvaluated = "not_evaluated"
)

// Subject relations of a request to a ban instance, strongest first. None of them names a culprit.
const (
	relationActivating  = "ACTIVATING_REQUEST"
	relationUnconfirmed = "ACTIVATION_UNCONFIRMED"
	relationHit         = "HIT_EXISTING_BAN"
	relationRace        = "ACTIVATION_RACE"
	relationOverlap     = "INTERVAL_OVERLAP"

	activationThreshold   = "FAILURE_THRESHOLD_EXCEEDED"
	activationUnconfirmed = "ACTIVATION_UNCONFIRMED"
	scopeIP               = "ip"
	scopeNetwork          = "network"
	hitSourceRace         = "activation_race"
)

// Ban context limitation codes.
const (
	limitHitNotRecorded    = "BAN_HIT_NOT_RECORDED"
	limitHitsNotRead       = "BAN_HITS_NOT_READ"
	limitMultipleBans      = "MULTIPLE_BANS_MATCH"
	limitLifecycleMissing  = "BAN_LIFECYCLE_NOT_RECORDED"
	limitCandidatesPartial = "CANDIDATE_NETWORKS_PARTIAL"
	limitLifecycleNotRead  = "BAN_LIFECYCLE_NOT_READ"
	limitContextBound      = "BAN_CONTEXT_LIMIT_REACHED"
	limitContextBudget     = "BAN_CONTEXT_BUDGET_EXHAUSTED"
	limitNotConfigured     = "BAN_HISTORY_NOT_CONFIGURED"
	limitClientIP          = "CLIENT_IP_NOT_USABLE"
	limitNoRequestID       = "REQUEST_ID_NOT_RECORDED"
)

// Ban context bounds per search page; every bound that is reached is reported, never silent.
const (
	maxBanContextRequests  = 20
	maxBanContextAddresses = 8
	maxBanContextNetworks  = 32
	maxBanContextInstances = 10
	maxBanContextHits      = maxBanContextRequests * 8

	// banHitMargin covers the time between a hit and the login row of the same request.
	banHitMargin = 5 * time.Minute

	// banContextReserve is the share of the time budget that must remain before one more ban is explained.
	banContextReserve = 0.15
)

// relationRank orders relations so a request keeps its strongest link to one instance.
var relationRank = map[string]int{relationActivating: 5, relationUnconfirmed: 4, relationHit: 3, relationRace: 3,
	relationOverlap: 1}

// banCandidate is one subject request rejected by brute-force protection.
type banCandidate struct {
	at        time.Time
	attemptID string
	requestID string
	clientIP  string
	skipped   string
}

// banLink is one instance a candidate request is linked to.
type banLink struct {
	relation string
	instance int
}

// explainedBan is the shared explanation of one instance, computed once per page.
type explainedBan struct {
	ban         Ban
	attribution BanAttribution
	evidence    BanEvidence
}

// banContextRun links the rejected requests of one page to recorded ban instances with a fixed number of reads:
// one lifecycle read and one hit read for the page, then at most maxBanContextInstances explanations.
type banContextRun struct {
	service   *Service
	search    searchScope
	scope     banScope
	attempts  map[string]string
	networks  map[string][]string
	partialIP map[string]bool
	hits      map[string][]HitRecord
	explained map[int]*explainedBan
	failures  map[Source]error
	instances []banInstance
	compact   bool
	hitsRead  bool
	lifecycle bool
	attempted bool
}

// banContexts builds the ban context of every subject request of the page that brute-force protection rejected. A
// failed or bounded read never fails the search: the affected entries say not_evaluated and why.
func (s *Service) banContexts(ctx context.Context, search searchScope, attempts []Attempt, compact bool) ([]BanContext, *Coverage) {
	candidates := rejectedRequests(attempts)
	contexts := make([]BanContext, 0, len(candidates))

	if s.bans == nil {
		for _, candidate := range candidates {
			candidate.skipped = limitNotConfigured
			contexts = append(contexts, newBanContext(candidate))
		}

		return contexts, nil
	}

	run := &banContextRun{service: s, search: search, attempts: requestAttempts(attempts), networks: map[string][]string{},
		partialIP: map[string]bool{}, hits: map[string][]HitRecord{}, explained: map[int]*explainedBan{},
		failures: map[Source]error{}, compact: compact,
		scope: banScope{window: Window{From: search.window.From, Until: search.window.Until}, queriedAt: search.queriedAt,
			matcher: &search.matcher, trimmed: map[string]bool{}}}

	candidates = run.admit(ctx, candidates)
	run.read(ctx, candidates)

	for _, candidate := range candidates {
		contexts = append(contexts, run.context(ctx, candidate))
	}

	if !run.attempted {
		// Nothing was read, so no brute-force source can be reported as queried.
		return contexts, nil
	}

	coverage := s.banCoverage(ctx, run.scope, run.failures)

	return contexts, &coverage
}

// rejectedRequests returns the visible subject login rows rejected by brute-force protection, one per request; rows
// without a recorded request id stay separate, keyed by their event id.
func rejectedRequests(attempts []Attempt) []banCandidate {
	var candidates []banCandidate

	seen := map[string]struct{}{}

	for _, attempt := range attempts {
		for _, event := range attempt.Events {
			if event.Source != sourceNameLogins || !event.Identity.SubjectMatch || event.Code != CodeBruteForceRejected {
				continue
			}

			key := "request\x00" + event.RequestID
			if event.RequestID == "" {
				key = "event\x00" + stringValue(event.EventID)
			}

			if _, ok := seen[key]; ok && key != "event\x00" {
				continue
			}

			seen[key] = struct{}{}

			candidates = append(candidates, banCandidate{at: event.OccurredAt, attemptID: attempt.AttemptID,
				requestID: event.RequestID, clientIP: stringValue(event.Context.ClientIP)})
		}
	}

	return candidates
}

// requestAttempts maps the subject request ids of the page to their attempt ids.
func requestAttempts(attempts []Attempt) map[string]string {
	byRequest := map[string]string{}

	for _, attempt := range attempts {
		for _, event := range attempt.Events {
			if event.Source == sourceNameLogins && event.Identity.SubjectMatch && event.RequestID != "" {
				byRequest[event.RequestID] = attempt.AttemptID
			}
		}
	}

	return byRequest
}

// admit applies the request, address, and network bounds and derives the candidate networks of every address once;
// an address refused by a bound keeps its reason for later candidates.
func (r *banContextRun) admit(ctx context.Context, candidates []banCandidate) []banCandidate {
	admitted, refused := 0, map[string]string{}

	for index := range candidates {
		candidate := &candidates[index]
		if admitted >= maxBanContextRequests {
			candidate.skipped = limitContextBound

			continue
		}

		if reason, ok := refused[candidate.clientIP]; ok {
			candidate.skipped = reason

			continue
		}

		if _, known := r.networks[candidate.clientIP]; !known {
			candidate.skipped = r.addAddress(ctx, candidate.clientIP)
			if candidate.skipped != "" {
				refused[candidate.clientIP] = candidate.skipped
			}
		}

		if candidate.skipped == "" {
			admitted++
		}
	}

	return candidates
}

// addAddress derives the candidate networks of one client address within the bounds, or names the reason it was not.
func (r *banContextRun) addAddress(ctx context.Context, clientIP string) string {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return limitClientIP
	}

	if len(r.networks) >= maxBanContextAddresses {
		return limitContextBound
	}

	networks, partial := r.service.candidateNetworks(ctx, addr)
	if len(r.scope.networks)+len(networks) > maxBanContextNetworks {
		return limitContextBound
	}

	r.networks[clientIP], r.partialIP[clientIP] = networks, partial
	r.scope.networks = append(r.scope.networks, networks...)
	r.scope.partial = r.scope.partial || partial

	return ""
}

// read performs the page's lifecycle and hit reads for the admitted requests.
func (r *banContextRun) read(ctx context.Context, candidates []banCandidate) {
	slices.Sort(r.scope.networks)
	r.scope.networks = slices.Compact(r.scope.networks)

	var (
		requests    []string
		first, last time.Time
	)

	for _, candidate := range candidates {
		if candidate.skipped != "" {
			continue
		}

		if candidate.requestID != "" {
			requests = append(requests, candidate.requestID)
		}

		if first.IsZero() || candidate.at.Before(first) {
			first = candidate.at
		}

		last = maxTime(last, candidate.at)
	}

	if first.IsZero() {
		return
	}

	queriedAt := r.scope.queriedAt
	r.attempted = true

	rows, err := r.service.bans.Lifecycle(ctx, LifecycleQuery{Networks: r.scope.networks,
		From: queriedAt.Add(-lifecycleRetention), Until: queriedAt, PerNetwork: lifecycleRowsPerNetwork})
	if err != nil {
		r.failures[SourceBanLifecycle] = err

		return
	}

	r.lifecycle, r.scope.trimmed = true, trimmedNetworks(rows)
	r.instances = assembleInstances(rows, Window{Until: queriedAt}, queriedAt)

	hits, hitErr := r.service.bans.RequestHits(ctx, RequestHitQuery{Networks: r.scope.networks, RequestIDs: requests,
		From: first.Add(-banHitMargin), Until: minTime(last.Add(banHitMargin), queriedAt.Add(time.Second)),
		Limit: maxBanContextHits})
	hits, _ = dedupeByID(hits, func(hit HitRecord) string { return hit.EventID })
	r.hitsRead = hitErr == nil && len(hits) < maxBanContextHits

	if hitErr != nil {
		r.failures[SourceBanAttempts] = hitErr
	}

	for _, hit := range hits {
		if hit.RequestID != "" {
			r.hits[hit.RequestID] = append(r.hits[hit.RequestID], hit)
		}
	}
}

// newBanContext creates the entry of one candidate before linking.
func newBanContext(candidate banCandidate) BanContext {
	entry := BanContext{At: candidate.at, ClientIP: optional(candidate.clientIP), AttemptID: candidate.attemptID,
		RequestID: candidate.requestID, Reason: CodeBruteForceRejected, Status: contextNotEvaluated,
		Bans: []BanContextBan{}, Limitations: []string{}}

	if candidate.skipped != "" {
		entry.Limitations = append(entry.Limitations, candidate.skipped)
	}

	return entry
}

// context links one candidate to its instances and attaches their shared explanations.
func (r *banContextRun) context(ctx context.Context, candidate banCandidate) BanContext {
	entry := newBanContext(candidate)
	if candidate.skipped != "" {
		return entry
	}

	if !r.lifecycle {
		entry.Limitations = append(entry.Limitations, limitLifecycleNotRead)

		return entry
	}

	limit := func(condition bool, code string) {
		if condition && !slices.Contains(entry.Limitations, code) {
			entry.Limitations = append(entry.Limitations, code)
		}
	}

	limit(r.partialIP[candidate.clientIP] || len(r.networks[candidate.clientIP]) == 0, limitCandidatesPartial)
	limit(candidate.requestID == "", limitNoRequestID)
	limit(r.search.queriedAt.Sub(candidate.at) < lateEventHorizon, limitLateEvents)

	links, orphan := r.links(candidate)
	limit(orphan, limitLifecycleMissing)
	limit(len(links) > 1, limitMultipleBans)
	entry.Status = linkStatus(links)

	if entry.Status == contextOverlapOnly {
		limit(r.hitsRead && candidate.requestID != "", limitHitNotRecorded)
		limit(!r.hitsRead, limitHitsNotRead)
	}

	for _, link := range links {
		ban, code := r.contextBan(ctx, link)
		limit(code != "", code)

		entry.Bans = append(entry.Bans, ban)
	}

	return entry
}

// linkStatus states how the request was linked: by a recorded fact, by interval overlap only, or not at all.
func linkStatus(links []banLink) string {
	switch {
	case slices.ContainsFunc(links, func(link banLink) bool { return link.relation != relationOverlap }):
		return contextMatched
	case len(links) > 0:
		return contextOverlapOnly
	default:
		return contextNoBan
	}
}

// links finds the instances of one request: the activation it wrote or attempted, the bans its recorded hits name,
// and only without either the instances whose bounded interval contains the row. orphan reports a recorded hit that
// no lifecycle instance explains.
func (r *banContextRun) links(candidate banCandidate) ([]banLink, bool) {
	byInstance := map[int]string{}
	link := func(instance int, relation string) {
		if relationRank[relation] > relationRank[byInstance[instance]] {
			byInstance[instance] = relation
		}
	}

	for index, instance := range r.instances {
		if relation := activationRelation(instance, candidate.requestID); relation != "" {
			link(index, relation)
		}
	}

	orphan := false

	for _, hit := range r.hits[candidate.requestID] {
		indexes := r.instancesAt(hit.Network, hit.At, false)
		orphan = orphan || len(indexes) == 0

		relation := relationHit
		if hit.HitSource == hitSourceRace {
			relation = relationRace
		}

		for _, index := range indexes {
			link(index, relation)
		}
	}

	if len(byInstance) == 0 && len(r.hits[candidate.requestID]) == 0 {
		for _, network := range r.networks[candidate.clientIP] {
			for _, index := range r.instancesAt(network, candidate.at, true) {
				link(index, relationOverlap)
			}
		}
	}

	return r.orderedLinks(byInstance), orphan
}

// orderedLinks returns the links newest activation first with the ban reference as tie-break, so both transports and
// repeated calls render the same order.
func (r *banContextRun) orderedLinks(byInstance map[int]string) []banLink {
	links := make([]banLink, 0, len(byInstance))
	for index, relation := range byInstance {
		links = append(links, banLink{instance: index, relation: relation})
	}

	slices.SortFunc(links, func(a, b banLink) int {
		left, right := r.instances[a.instance].activation, r.instances[b.instance].activation
		if order := right.At.Compare(left.At); order != 0 {
			return order
		}

		return strings.Compare(right.EventID, left.EventID)
	})

	return links
}

// activationRelation reports whether the request wrote the activation or one recorded unconfirmed activation of an
// instance; an unconfirmed creator never becomes the activating request.
func activationRelation(instance banInstance, requestID string) string {
	if requestID == "" {
		return ""
	}

	if instance.activation.RequestID == requestID {
		if instance.activation.Kind == kindActivated {
			return relationActivating
		}

		return relationUnconfirmed
	}

	if slices.ContainsFunc(instance.unconfirmed, func(row LifecycleRecord) bool { return row.RequestID == requestID }) {
		return relationUnconfirmed
	}

	return ""
}

// instancesAt returns every instance of a network whose interval contains the instant; near a supersession both
// neighbours can match inside the grace and are both kept. bounded refuses instances whose end is neither recorded,
// planned, nor estimable from the ban time, so an inferred link never reaches forward without limit.
func (r *banContextRun) instancesAt(network string, at time.Time, bounded bool) []int {
	var indexes []int

	for index, instance := range r.instances {
		if instance.activation.Network != network {
			continue
		}

		until, known, _ := instanceEnd(instance)
		if bounded && !known {
			continue
		}

		if !at.Before(instance.activation.At.Add(-hitAttributionGrace)) && at.Before(until.Add(hitAttributionGrace)) {
			indexes = append(indexes, index)
		}
	}

	return indexes
}

// instanceEnd returns the end used for linking: the recorded or planned end, or for an instance without either the
// activation plus its recorded ban time (estimated). known is false when no end can be stated at all.
func instanceEnd(instance banInstance) (until time.Time, known bool, estimated bool) {
	if instance.end.Reason != endUnknown {
		return instance.until, true, false
	}

	if instance.activation.BanTimeSeconds > 0 {
		return instance.activation.At.Add(time.Duration(instance.activation.BanTimeSeconds) * time.Second), true, true
	}

	return instance.until, false, false
}

// contextBan renders one linked instance; an instance beyond the explanation bound or budget keeps its recorded
// activation facts but no attribution, and the returned code names that limitation.
func (r *banContextRun) contextBan(ctx context.Context, link banLink) (BanContextBan, string) {
	instance := r.instances[link.instance]
	row := instance.activation
	until, _, _ := instanceEnd(instance)
	item := BanContextBan{ActivatedAt: row.At.UTC(), PlannedEnd: row.ExpiresAt, End: instance.end, BanRef: row.EventID,
		Network: row.Network, Scope: networkScope(row.Network), Rule: recordedText(row.Rule),
		ActivationReason: activationThreshold, SubjectRelation: link.relation,
		History: historyReference(row, until, r.scope.queriedAt)}

	if row.Kind != kindActivated {
		item.ActivationReason = activationUnconfirmed
	}

	explained, code := r.explain(ctx, link.instance)
	if explained == nil {
		item.Attribution = BanAttribution{SubjectContributions: []SubjectContribution{}, Code: AttributionInsufficient,
			OtherContributors: othersUnknown, PersonAttribution: personNotEstablish}
		item.Evidence = BanEvidence{Completeness: evidenceNotRead, Limitations: []string{code}}

		return item, code
	}

	item.Attribution, item.Evidence = explained.attribution, explained.evidence
	if !r.compact {
		detail := explained.ban
		item.Detail = &detail
	}

	return item, ""
}

// explain computes the explanation and attribution of one instance once per page within the bounds.
func (r *banContextRun) explain(ctx context.Context, index int) (*explainedBan, string) {
	if explained, ok := r.explained[index]; ok {
		return explained, ""
	}

	if len(r.explained) >= maxBanContextInstances {
		return nil, limitContextBound
	}

	if r.service.budgetBelow(ctx, banContextReserve) {
		return nil, limitContextBudget
	}

	instance := r.instances[index]
	scope := r.scope
	scope.window = Window{From: instance.activation.At.Add(-hitAttributionGrace), Until: r.scope.queriedAt}

	ban, items := r.service.explainInstance(ctx, scope, instance, !r.compact)
	_, _, estimated := instanceEnd(instance)
	attribution, evidence := attribute(attributionInput{activatedAt: instance.activation.At, queriedAt: r.scope.queriedAt,
		attempts: r.attempts, matcher: r.search.matcher, items: items, ban: ban,
		estimated: estimated})

	explained := &explainedBan{ban: ban, attribution: attribution, evidence: evidence}
	r.explained[index] = explained

	return explained, ""
}

// networkScope reports whether a ban network is a single address or a wider network.
func networkScope(network string) string {
	prefix, err := netip.ParsePrefix(network)
	if err == nil && prefix.Bits() == prefix.Addr().BitLen() {
		return scopeIP
	}

	return scopeNetwork
}

// historyReference returns a valid bruteforce_history window that selects the instance.
func historyReference(row LifecycleRecord, until, queriedAt time.Time) BanHistoryReference {
	from := row.At.UTC().Truncate(time.Second)
	end := minTime(until.Add(time.Second), queriedAt).UTC().Truncate(time.Second).Add(time.Second)

	if end.Sub(from) > MaxWindow {
		end = from.Add(MaxWindow)
	}

	return BanHistoryReference{From: from, Until: end, BanRef: row.EventID, Network: row.Network}
}
