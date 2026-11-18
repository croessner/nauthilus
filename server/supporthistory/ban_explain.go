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
	"time"
)

// Evidence sources of ban answers.
const (
	evidenceRaw         = "raw"
	evidenceSummary     = "summary"
	evidenceNotRead     = "not_read"
	evidenceNotAssessed = "not_assessed"
	crossingBasis       = "heuristic_crossed_flag"
)

// rawHorizon is the oldest instant whose raw attempt rows are still complete: daily parts expire whole after 14
// days, so one day of margin keeps a partially dropped day out of raw answers.
func rawHorizon(queriedAt time.Time) time.Time {
	return queriedAt.Add(-rawBanRetention + 24*time.Hour)
}

// explainBan attributes contributions and hits to one ban instance.
func (s *Service) explainBan(ctx context.Context, scope banScope, instance banInstance) Ban {
	ban, _ := s.explainInstance(ctx, scope, instance, true)

	return ban
}

// explainInstance builds the explanation of one ban instance and returns the listed counted rows before projection;
// withHits adds the hit aggregate, which compact answers do not need.
func (s *Service) explainInstance(ctx context.Context, scope banScope, instance banInstance, withHits bool) (Ban, []CountedRecord) {
	row := instance.activation
	ban := Ban{BanRef: row.EventID, Network: row.Network, End: instance.end, Unknowns: []string{},
		Activation: Activation{At: row.At.UTC(), Kind: row.Kind, Rule: row.Rule, StoredRule: row.StoredRule,
			RuleFingerprint: row.RuleFingerprint, Instance: recordedText(row.Instance), BucketID: recorded(row.BucketID),
			WindowIndex: row.WindowIndex, WindowCurrent: row.WindowCurrent, WindowPrevious: row.WindowPrevious,
			Total: row.Total, EffectiveLimit: row.EffectiveLimit, PlannedEnd: row.ExpiresAt,
			ActivatingRequest: activatingRequest, PeriodSeconds: row.PeriodSeconds,
			BanTimeSeconds: row.BanTimeSeconds, FailedRequests: row.FailedRequests}}

	if row.Kind == kindUnconfirmed {
		ban.Unknowns = append(ban.Unknowns, unknownCreator)
	}

	// Only a release is a recorded end; a superseding activation bounds the end without recording it.
	if instance.end.Reason != endReleased {
		ban.Unknowns = append(ban.Unknowns, unknownEndUnrecorded)
	}

	if len(instance.unconfirmed) > 0 {
		ban.Unknowns = append(ban.Unknowns, unknownUnconfirmedDuring)
	}

	if scope.trimmed[row.Network] {
		ban.Unknowns = append(ban.Unknowns, unknownLifecycleTrimmed)
	}

	contributions, items, contributionErr := s.contributionsOf(ctx, scope, instance)
	ban.Contributions = contributions

	if contributionErr != nil {
		ban.Unknowns = append(ban.Unknowns, unknownContributions)
	}

	ban.Hits = HitSummary{BySource: map[string]int64{}, Claimants: []Claimant{}, Evidence: evidenceNotAssessed}
	if !withHits {
		return ban, items
	}

	from := maxTime(row.At.Add(-hitAttributionGrace), scope.window.From)
	until := minTime(instance.until.Add(hitAttributionGrace), scope.window.Until)
	ban.Hits = s.hitSummary(ctx, scope, kindHit, []string{row.Network}, from, until, nil)

	if ban.Hits.Evidence == evidenceNotRead {
		ban.Unknowns = append(ban.Unknowns, unknownHitsNotRead)
	}

	return ban, items
}

// hitSummary aggregates one volume kind from raw rows inside raw retention or from the hourly summary beyond it.
func (s *Service) hitSummary(ctx context.Context, scope banScope, kind string, networks []string, from, until time.Time, exclude []NetworkInterval) HitSummary {
	summary := HitSummary{BySource: map[string]int64{}, Claimants: []Claimant{}, Evidence: evidenceRaw}
	if !from.Before(until) {
		return summary
	}

	query := KindQuery{Kind: kind, Networks: networks, From: from, Until: until, Exclude: exclude}
	if from.Before(rawHorizon(scope.queriedAt)) {
		if len(exclude) > 0 {
			summary.Evidence = evidenceNotAssessed

			return summary
		}

		query.Summary = true
		summary.Evidence, summary.CountIsUpperBound, summary.IntervalApproximate = evidenceSummary, true, true
	}

	if scope.projection == ProjectionDetail && !query.Summary {
		query.Claimants = MaxClaimants

		if scope.matcher != nil {
			match := scope.matcher.subjectMatch()
			query.Subject = &match
		}
	}

	aggregate, err := s.bans.KindCounts(ctx, query)
	if err != nil {
		summary.Evidence = evidenceNotRead

		return summary
	}

	summary.Count, summary.DistinctClaimedNames, summary.SubjectHits = aggregate.Total, aggregate.DistinctNames, aggregate.SubjectHits
	for source, count := range aggregate.BySource {
		summary.BySource[source] = count
	}

	for _, claimant := range aggregate.Claimants {
		summary.Claimants = append(summary.Claimants, Claimant{ClaimedUsername: recorded(claimant.ClaimedUsername),
			Account: recorded(claimant.Account), Hits: claimant.Hits})
	}

	return summary
}

// orphanHits counts hits in the window that no recorded ban instance explains (bans written by scripts, evicted,
// or lost lifecycle events).
func (s *Service) orphanHits(ctx context.Context, scope banScope, instances []banInstance) HitSummary {
	exclude := make([]NetworkInterval, 0, len(instances))

	for _, instance := range instances {
		exclude = append(exclude, NetworkInterval{Network: instance.activation.Network,
			From: instance.activation.At.Add(-hitAttributionGrace), Until: instance.until.Add(hitAttributionGrace)})
	}

	if len(exclude) > maxOrphanExcludes {
		return HitSummary{BySource: map[string]int64{}, Claimants: []Claimant{}, Evidence: evidenceNotAssessed}
	}

	return s.hitSummary(ctx, scope, kindHit, scope.networks, scope.window.From, minTime(scope.window.Until,
		scope.queriedAt), exclude)
}

// toleratedCount counts suppressed bans of the candidate networks in the window.
func (s *Service) toleratedCount(ctx context.Context, scope banScope) ToleratedSummary {
	summary := s.hitSummary(ctx, scope, kindTolerated, scope.networks, scope.window.From,
		minTime(scope.window.Until, scope.queriedAt), nil)

	return ToleratedSummary{Count: summary.Count, CountIsUpperBound: summary.CountIsUpperBound, Evidence: summary.Evidence}
}

// banCoverage reports the three brute-force sources for the window; failures names sources whose read failed.
func (s *Service) banCoverage(ctx context.Context, scope banScope, failures map[Source]error) Coverage {
	reads := []sourceRead{
		{source: SourceBanLifecycle, retention: lifecycleRetention, queried: true, failed: failures[SourceBanLifecycle],
			presence: s.bans.Presence(ctx, SourceBanLifecycle)},
		{source: SourceBanAttempts, retention: rawBanRetention, queried: true, failed: failures[SourceBanAttempts],
			presence: s.bans.Presence(ctx, SourceBanAttempts)},
		{source: SourceBanSummary, retention: lifecycleRetention, queried: true,
			presence: s.bans.Presence(ctx, SourceBanSummary)},
	}

	var conditions []string
	if len(scope.networks) == 0 || scope.partial {
		conditions = append(conditions, conditionCandidatePartial)
	}

	if len(scope.trimmed) > 0 {
		conditions = append(conditions, conditionLifecycleTrimmed)
	}

	return buildCoverage(coverageInput{now: scope.queriedAt, window: scope.window, deployment: s.attempts.Deployment(),
		reads: reads, limits: banKnownLimits, conditions: conditions, contractKnown: true})
}
