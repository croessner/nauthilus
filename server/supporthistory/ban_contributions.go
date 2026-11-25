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
	"slices"
	"time"
)

// Contribution statuses (contract §13.4), ordered from best to worst.
const (
	statusNotApplicable = "not_applicable"
	statusComplete      = "complete"
	statusAggregateOnly = "aggregate_only"
	statusLossDetected  = "loss_detected"
	statusExpired       = "expired"

	windowActivation = "activation_window"
	windowPrevious   = "previous_window"

	caveatResetSkew      = "RESET_BOUNDS_COMPARE_CLOCKS_OF_DIFFERENT_INSTANCES"
	caveatSummaryCounts  = "SUMMARY_COUNTS_ARE_UPPER_BOUNDS"
	caveatItemsTruncated = "CONTRIBUTION_ITEMS_TRUNCATED"

	// caveatPartiallyRetained marks listed items of a rule whose windows reach beyond the raw retention: earlier
	// increments expired, so the items are a retained subset and never prove which increments are absent.
	caveatPartiallyRetained = "RAW_CONTRIBUTIONS_PARTIALLY_RETAINED"
)

// statusRank orders statuses so the overall status is the worst window.
var statusRank = map[string]int{statusNotApplicable: 0, statusComplete: 1, statusAggregateOnly: 2,
	statusLossDetected: 3, statusExpired: 4}

// bucketWindow is one window of the activating bucket with its expected closed set 1..expected.
type bucketWindow struct {
	label    string
	index    int64
	expected int64
}

// contributionsOf attributes counted increments to one activation by bucket, window counters, and the counter
// resets before and after the activation, then states completeness per window. Completeness, the crossing candidate,
// and the distinct names derive from the interpretation read (at most MaxContributions items); Items lists one page.
// It also returns the interpretation rows before projection, so attribution reads them once and never from the items.
func (s *Service) contributionsOf(ctx context.Context, scope banScope, instance banInstance) (Contributions, []CountedRecord, error) {
	row := instance.activation
	result := Contributions{Status: statusNotApplicable, Windows: []WindowStatus{}, Items: []Contribution{},
		Caveats: []string{}}

	windows, ok := activationWindows(row)
	if !ok {
		return result, nil, nil
	}

	resetAfter, resetBefore := resetBounds(instance)
	if resetAfter != nil || resetBefore != nil {
		result.Caveats = append(result.Caveats, caveatResetSkew)
	}

	scan := contributionScanOf(scope, row, windows, resetAfter, resetBefore)

	read, err := s.readContributions(ctx, scan, nil, MaxContributions+1)
	if err != nil {
		return result, nil, err
	}

	if scan.partial {
		result.Caveats = append(result.Caveats, caveatPartiallyRetained)
	}

	interpretation := contributionRead{items: read, bounded: len(read) > MaxContributions}
	if interpretation.bounded {
		result.Caveats = append(result.Caveats, caveatItemsTruncated)
		interpretation.items = read[:MaxContributions]
	}

	if scope.matcher != nil {
		extended := scope.matcher.withCountedAccounts(interpretation.items)
		scope.matcher = &extended
	}

	s.assessWindows(ctx, scope, instance, windows, interpretation, &result)
	result.CrossingCandidate, result.DistinctClaimedNames = crossingOf(row, interpretation.items)

	if err = s.listContributions(ctx, scope, scan, read, &result); err != nil {
		return result, nil, err
	}

	return result, interpretation.items, nil
}

// contributionRead is the bounded interpretation read of one activation's contributions; bounded tells that more
// rows than MaxContributions exist, so completeness falls back to the summary.
type contributionRead struct {
	items   []CountedRecord
	bounded bool
}

// listContributions lists one contribution page: the first page from the interpretation read, a continuation from
// a read at the cursor position that steps over the ties already listed there. Truncated and NextCursor tell whether
// more contributions follow.
func (s *Service) listContributions(ctx context.Context, scope banScope, scan contributionScan, first []CountedRecord, result *Contributions) error {
	page := scope.contributionPage(scan.banRef)
	listed := first

	if after := page.after; after != nil {
		read, err := s.readContributions(ctx, scan, &after.position, page.limit+after.ties+1)
		if err != nil {
			return err
		}

		listed = skipListed(read, after.ties, page.continued)
	}

	if len(listed) > page.limit {
		listed = listed[:page.limit]
		result.Truncated, result.NextCursor = true, page.cursor(listed, scope.queriedAt)
	}

	result.Items = make([]Contribution, 0, len(listed))
	for _, item := range listed {
		result.Items = append(result.Items, projectContribution(scope, item))
	}

	return nil
}

// activationWindows returns the activation and previous bucket windows, or false when the activation carries no
// counters to attribute against.
func activationWindows(row LifecycleRecord) ([]bucketWindow, bool) {
	if row.Kind != kindActivated || row.BucketID == "" || row.WindowIndex == nil || row.WindowCurrent == nil ||
		row.PeriodSeconds <= 0 {
		return nil, false
	}

	previous := int64(0)
	if row.WindowPrevious != nil {
		previous = *row.WindowPrevious
	}

	return []bucketWindow{{windowActivation, *row.WindowIndex, *row.WindowCurrent},
		{windowPrevious, *row.WindowIndex - 1, previous}}, true
}

// assessWindows states every window from the interpretation read and folds the worst status into the result.
func (s *Service) assessWindows(ctx context.Context, scope banScope, instance banInstance, windows []bucketWindow, read contributionRead, result *Contributions) {
	for _, window := range windows {
		status := s.windowStatus(ctx, scope, instance.activation, window, read.items, read.bounded, instance.resets)
		if status.CountsAreUpperBounds && !slices.Contains(result.Caveats, caveatSummaryCounts) {
			result.Caveats = append(result.Caveats, caveatSummaryCounts)
		}

		result.Windows = append(result.Windows, status)
		if statusRank[status.Status] > statusRank[result.Status] {
			result.Status = status.Status
		}
	}
}

// resetBounds returns the latest counter reset of the bucket before the activation and the first one after it.
func resetBounds(instance banInstance) (*time.Time, *time.Time) {
	var after, before *time.Time

	for _, reset := range instance.resets {
		if reset.BucketID != instance.activation.BucketID {
			continue
		}

		switch at := reset.At; {
		case at.Before(instance.activation.At) && (after == nil || at.After(*after)):
			after = timePointer(at)
		case at.After(instance.activation.At) && (before == nil || at.Before(*before)):
			before = timePointer(at)
		}
	}

	return after, before
}

// skewSlack widens activation-relative bounds for export delay and clock skew between instances.
const skewSlack = time.Hour

// windowBounds returns a conservative time range of a bucket window relative to the activation: the activation
// window started at most one period before the activation, the previous window at most two, and both end no later
// than the activation. The bounds do not rely
// on epoch arithmetic of window_index, so recorded indexes are only compared, never converted.
func windowBounds(row LifecycleRecord, label string) (time.Time, time.Time) {
	period := time.Duration(row.PeriodSeconds) * time.Second
	if label == windowPrevious {
		// The previous window ends anywhere in (activation - period, activation].
		return row.At.Add(-2*period - skewSlack), row.At.Add(skewSlack)
	}

	return row.At.Add(-period - skewSlack), row.At.Add(skewSlack)
}

// contributionScan is the store read of one activation's contributions inside the intersection of the conservative
// window bounds with the raw retention. Rules whose windows reach beyond the retention keep their retained increments;
// partial reports a read that covers only the retained part of the windows, skip one that covers nothing.
// Completeness stays with windowStatus.
type contributionScan struct {
	query   ContributionQuery
	banRef  string
	partial bool
	skip    bool
}

// contributionScanOf derives the contribution read of one activation.
func contributionScanOf(scope banScope, row LifecycleRecord, windows []bucketWindow, resetAfter, resetBefore *time.Time) contributionScan {
	horizon := rawHorizon(scope.queriedAt)
	activationFrom, until := windowBounds(row, windowActivation)
	previousFrom, _ := windowBounds(row, windowPrevious)

	relevantFrom := activationFrom
	if windows[1].expected > 0 {
		relevantFrom = previousFrom
	}

	query := ContributionQuery{Network: row.Network, BucketID: row.BucketID, WindowIndex: windows[0].index,
		Current: windows[0].expected, Previous: windows[1].expected, ResetAfter: resetAfter, ResetBefore: resetBefore,
		From: maxTime(previousFrom, horizon), Until: until}

	return contributionScan{query: query, banRef: row.EventID, partial: relevantFrom.Before(horizon),
		skip: !until.After(horizon)}
}

// readContributions reads at most limit contributions of a scan from an optional position, replays removed.
func (s *Service) readContributions(ctx context.Context, scan contributionScan, start *ContributionPosition, limit int) ([]CountedRecord, error) {
	if scan.skip {
		return nil, nil
	}

	query := scan.query
	query.Start, query.Limit = start, limit

	items, err := s.bans.Contributions(ctx, query)
	if err != nil {
		return nil, err
	}

	// Replays share their event id and are no loss; the reader removes them, this keeps the rule in one place here.
	items, _ = dedupeByID(items, countedEventID)

	return items, nil
}

// windowStatus states the completeness of one window from raw rows, or from the summary beyond raw retention.
func (s *Service) windowStatus(ctx context.Context, scope banScope, row LifecycleRecord, window bucketWindow, items []CountedRecord, truncated bool, resets []LifecycleRecord) WindowStatus {
	status := WindowStatus{Window: window.label, WindowIndex: window.index, Expected: int64Pointer(window.expected)}
	if window.expected <= 0 {
		status.Status, status.Evidence = statusNotApplicable, evidenceNotAssessed

		return status
	}

	start, _ := windowBounds(row, window.label)
	if !start.Before(rawHorizon(scope.queriedAt)) && !truncated {
		return rawWindowStatus(status, window, items)
	}

	return s.summaryWindowStatus(ctx, status, row, window, resets)
}

// rawWindowStatus compares the deduplicated increments of a window with the closed set 1..expected.
func rawWindowStatus(status WindowStatus, window bucketWindow, items []CountedRecord) WindowStatus {
	present, distinct := int64(0), map[int64]struct{}{}

	for _, item := range items {
		if item.WindowIndex == nil || *item.WindowIndex != window.index || item.WindowCurrent == nil {
			continue
		}

		present++
		distinct[*item.WindowCurrent] = struct{}{}
	}

	status.Present, status.Evidence = int64Pointer(present), evidenceRaw
	status.Status = statusLossDetected

	if present == window.expected && int64(len(distinct)) == window.expected {
		status.Status = statusComplete
	}

	return status
}

// summaryWindowStatus checks the hourly aggregate of a window: a provable gap is a loss, otherwise the answer is
// aggregate-only; a counter reset inside the window makes the check unreliable.
func (s *Service) summaryWindowStatus(ctx context.Context, status WindowStatus, row LifecycleRecord, window bucketWindow, resets []LifecycleRecord) WindowStatus {
	status.Evidence, status.CountsAreUpperBounds = evidenceSummary, true

	summaries, err := s.bans.WindowSummaries(ctx, SummaryQuery{Network: row.Network, BucketID: row.BucketID,
		Kind: kindCounted, WindowIndexes: []int64{window.index}})
	if err != nil || len(summaries) == 0 || summaries[0].MinCurrent == nil || summaries[0].MaxCurrent == nil {
		status.Status, status.Evidence = statusExpired, evidenceNotRead
		if err == nil {
			status.Evidence = evidenceSummary
		}

		return status
	}

	summary := summaries[0]
	status.Present = int64Pointer(summary.Events)
	status.SummaryCheckUnreliable = resetInWindow(resets, row, window)
	status.Status = statusAggregateOnly

	if !status.SummaryCheckUnreliable && summary.Events < *summary.MaxCurrent-*summary.MinCurrent+1 {
		status.Status = statusLossDetected
	}

	return status
}

// resetInWindow reports whether a counter reset of the bucket falls into the conservative window bounds.
func resetInWindow(resets []LifecycleRecord, row LifecycleRecord, window bucketWindow) bool {
	start, end := windowBounds(row, window.label)

	return slices.ContainsFunc(resets, func(reset LifecycleRecord) bool {
		return reset.BucketID == row.BucketID && !reset.At.Before(start) && reset.At.Before(end)
	})
}

// crossingOf selects the crossing candidate and counts the distinct claimed names of the interpretation items.
func crossingOf(row LifecycleRecord, items []CountedRecord) (*CrossingCandidate, *int64) {
	names := map[string]struct{}{}

	var crossing *CrossingCandidate

	for _, item := range items {
		if item.ClaimedUsername != "" {
			names[item.ClaimedUsername] = struct{}{}
		}

		if item.Crossed != nil && *item.Crossed && !item.At.After(row.At) &&
			(crossing == nil || !item.At.Before(crossing.At)) {
			crossing = &CrossingCandidate{At: item.At.UTC(), WindowCurrent: item.WindowCurrent, EventID: item.EventID,
				Basis: crossingBasis}
		}
	}

	var distinct *int64
	if len(items) > 0 {
		distinct = int64Pointer(int64(len(names)))
	}

	return crossing, distinct
}

// projectContribution projects one counted increment with its recorded claims.
func projectContribution(scope banScope, item CountedRecord) Contribution {
	contribution := Contribution{At: item.At.UTC(), WindowIndex: item.WindowIndex, WindowCurrent: item.WindowCurrent,
		Crossed: item.Crossed, AccountKnown: item.AccountKnown, EventID: item.EventID, RequestID: item.RequestID,
		CountSource: item.CountSource, Protocol: item.Protocol, ClaimedUsername: recorded(item.ClaimedUsername),
		Account: recorded(item.Account), ClientIP: recorded(item.ClientIP)}

	if scope.matcher != nil {
		_, byLogin := scope.matcher.logins[item.ClaimedUsername]
		_, byAccount := scope.matcher.accounts[item.Account]
		match := byLogin || (item.Account != "" && byAccount)
		contribution.SubjectMatch = &match
	}

	return contribution
}

// int64Pointer returns a pointer to a copy of an int64.
func int64Pointer(value int64) *int64 {
	return &value
}
