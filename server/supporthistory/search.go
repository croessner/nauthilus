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
	"errors"
	"time"
)

// minRemainingBudget stops slice scanning early so the fetch of the found attempts still fits the time budget.
const minRemainingBudget = 0.4

// SearchAttempts searches the recorded attempts of one subject, newest activity first.
//
// Attempts are ordered by their latest subject-matching activity. The window is scanned in slices; each page reports
// the fully scanned range. Paging has no snapshot isolation: a late-delivered row can repeat an attempt on a later
// page, so clients deduplicate by attempt_id.
func (s *Service) SearchAttempts(ctx context.Context, caller Caller, request AttemptSearchRequest) (*AttemptSearchResult, error) {
	ctx, call, err := s.begin(ctx, caller, operationAttemptSearch, permissionAttemptsRead,
		[]string{request.Subject.Login, request.Subject.Account}, request.AuditReference, request.validate)
	if err != nil {
		return nil, err
	}

	result, searchErr := s.searchAttempts(ctx, caller, request)
	if searchErr != nil {
		call.finish(ctx, 0, searchErr)

		return nil, searchErr
	}

	call.finish(ctx, len(result.Attempts), nil)

	return result, nil
}

// searchScope is the validated, resolved state of one search page.
type searchScope struct {
	window     Window
	queriedAt  time.Time
	cursor     *cursorState
	matcher    subjectMatcher
	projection Projection
	digest     string
	limit      int
}

// searchAttempts runs one authorized search page.
func (s *Service) searchAttempts(ctx context.Context, caller Caller, request AttemptSearchRequest) (*AttemptSearchResult, *Error) {
	scope, resolution, scopeErr := s.searchScope(ctx, caller, request)
	if scopeErr != nil {
		return nil, scopeErr
	}

	scan, err := s.scanAnchors(ctx, scope)
	if err != nil {
		return nil, mapStoreError(ctx, err)
	}

	page := scan.anchors
	if len(page) > scope.limit {
		page = page[:scope.limit]
		scan.scannedUntil = page[len(page)-1].At
	}

	attempts, eventsRead, err := s.collectAttempts(ctx, scope, page)
	if err != nil {
		return nil, mapStoreError(ctx, err)
	}

	result := &AttemptSearchResult{SchemaVersion: SchemaVersion, QueriedAt: scope.queriedAt,
		SubjectResolution: resolution, Attempts: attempts,
		Page: AttemptPage{Limit: scope.limit, ScannedUntil: scan.scannedUntil}}
	result.History = s.attemptCoverage(ctx, scope.window, scope.queriedAt, eventsRead, attempts)
	result.ResultBasis = resultBasis(len(attempts) > 0, result.History, SourceLogins,
		request.Subject.Account == "" && len(resolution.Accounts) == 0)
	result.Page.NextCursor = nextCursor(scope, scan, page)

	return result, nil
}

// searchScope validates paging, freezes the query time, and resolves the subject.
func (s *Service) searchScope(ctx context.Context, caller Caller, request AttemptSearchRequest) (searchScope, SubjectResolution, *Error) {
	scope := searchScope{window: Window{From: request.Filter.From.UTC(), Until: request.Filter.Until.UTC()},
		queriedAt: s.now().UTC(), projection: caller.projection()}
	filter := request.Filter.anchorFilter()
	scope.digest = queryDigest(operationAttemptSearch, scope.projection, request.Subject.Login, request.Subject.Account,
		filter.ClientIP, filter.Protocol, filter.OIDCClientID, filter.SAMLEntityID,
		scope.window.From.Format(time.RFC3339Nano), scope.window.Until.Format(time.RFC3339Nano))

	limit, err := pageLimit(request.Page.Limit, DefaultPageLimit, MaxAttemptPageLimit)
	if err != nil {
		return scope, SubjectResolution{}, err
	}

	scope.limit = limit
	if scope.cursor, err = decodeCursor(request.Page.Cursor, scope.digest); err != nil {
		return scope, SubjectResolution{}, err
	}

	if scope.cursor != nil {
		scope.queriedAt = scope.cursor.queriedAt()
	}

	resolution, accounts, resolveErr := subjectResolver{identity: s.identity, attempts: s.attempts}.resolve(ctx,
		request.Subject, scope.window, true)
	if resolveErr != nil {
		return scope, resolution, mapStoreError(ctx, resolveErr)
	}

	scope.matcher = newSubjectMatcher(request.Subject.Login, accounts, filter)

	return scope, resolution, nil
}

// anchorScan is the result of scanning slices for one page.
type anchorScan struct {
	scannedUntil time.Time
	anchors      []AttemptAnchor
	stoppedEarly bool
	sliceFull    bool
}

// scanAnchors scans the window newest first in slices until the page is full, shrinking a slice that exceeds the
// read budget down to the minimum span before giving up.
func (s *Service) scanAnchors(ctx context.Context, scope searchScope) (anchorScan, error) {
	upper := minTime(scope.window.Until, scope.queriedAt)

	var before *AnchorPosition

	if scope.cursor != nil {
		position := scope.cursor.position()
		before, upper = &position, minTime(upper, position.At.Add(time.Millisecond))
	}

	scan := anchorScan{scannedUntil: upper}
	seen := map[AttemptKey]struct{}{}
	span := sliceSpan

	for sliceUntil := upper; sliceUntil.After(scope.window.From) && len(scan.anchors) <= scope.limit; {
		if s.budgetLow(ctx) {
			scan.stoppedEarly = true

			break
		}

		sliceFrom := maxTime(scope.window.From, sliceUntil.Add(-span))
		want := scope.limit + 1 - len(scan.anchors)

		anchors, err := s.attempts.Anchors(ctx, AnchorQuery{From: sliceFrom, Until: sliceUntil, Before: before,
			Subject: scope.matcher.subjectMatch(), Filter: scope.matcher.filter, Limit: want})
		if errors.Is(err, ErrBudgetExceeded) && span > minSliceSpan {
			span = max(minSliceSpan, span/4)

			continue
		}

		if err != nil {
			return scan, err
		}

		for _, anchor := range anchors {
			if _, ok := seen[anchor.Key]; !ok {
				seen[anchor.Key] = struct{}{}
				scan.anchors = append(scan.anchors, anchor)
			}
		}

		if len(anchors) >= want {
			scan.scannedUntil, scan.sliceFull = anchors[len(anchors)-1].At, true

			break
		}

		scan.scannedUntil, sliceUntil = sliceFrom, sliceFrom
	}

	return scan, nil
}

// budgetLow reports whether less than the reserved share of the time budget remains.
func (s *Service) budgetLow(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return false
	}

	return time.Until(deadline) < time.Duration(float64(s.timeout)*minRemainingBudget)
}

// nextCursor continues after the last returned anchor, or after the scanned range when scanning stopped early.
func nextCursor(scope searchScope, scan anchorScan, page []AttemptAnchor) *string {
	var position AnchorPosition

	switch {
	case (len(scan.anchors) > len(page) || scan.sliceFull) && len(page) > 0:
		last := page[len(page)-1]
		position = AnchorPosition{At: last.At, Key: last.Key.Value}
	case scan.stoppedEarly && scan.scannedUntil.After(scope.window.From):
		position = AnchorPosition{At: scan.scannedUntil}
	default:
		return nil
	}

	cursor := encodeCursor(position, scope.queriedAt, scope.digest)

	return &cursor
}

// minTime returns the earlier instant.
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}

	return b
}

// maxTime returns the later instant.
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}

	return b
}
