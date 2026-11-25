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
	"math"
	"time"
)

const (
	// contributionCursorMarks is the number of integer parts of a contribution cursor: window index, window current,
	// and the ties listed at the cursor position.
	contributionCursorMarks = 3

	// claimantCursorMarks is the number of integer parts of a claimant cursor: the next offset and the aggregate hit
	// total the offset is bound to.
	claimantCursorMarks = 2
)

// innerCursorMarks returns the number of integer parts of a cursor of an inner list.
func innerCursorMarks(list string) int {
	if list == InnerListContributions {
		return contributionCursorMarks
	}

	return claimantCursorMarks
}

// contributionCursor is the decoded continuation of a contribution list: the position of the last listed item and
// how many items at exactly that position were listed.
type contributionCursor struct {
	position ContributionPosition
	ties     int
}

// contributionPositionOf returns the keyset position of a counted row whose window values are set.
func contributionPositionOf(record CountedRecord) ContributionPosition {
	return ContributionPosition{At: record.At.UTC(), EventID: record.EventID, WindowIndex: *record.WindowIndex,
		WindowCurrent: *record.WindowCurrent}
}

// holds reports whether a counted row sits at exactly this position.
func (p ContributionPosition) holds(record CountedRecord) bool {
	return record.WindowIndex != nil && record.WindowCurrent != nil && *record.WindowIndex == p.WindowIndex &&
		*record.WindowCurrent == p.WindowCurrent && record.At.Equal(p.At) && record.EventID == p.EventID
}

// sameContribution reports whether two counted rows share their whole keyset position.
func sameContribution(a, b CountedRecord) bool {
	return b.WindowIndex != nil && b.WindowCurrent != nil && contributionPositionOf(b).holds(a)
}

// innerListMaximum returns the default and maximum page size of an inner list.
func innerListMaximum(list string) int {
	if list == InnerListContributions {
		return MaxContributions
	}

	return MaxClaimants
}

// validate checks an inner page against the ban filter and the outer page cursor; cursors are checked by the scope.
func (p *BanInnerPageRequest) validate(filterBanRef, pageCursor string) *Error {
	switch p.List {
	case InnerListContributions, InnerListClaimants:
		if !banRefPattern.MatchString(p.BanRef) || (filterBanRef != "" && filterBanRef != p.BanRef) {
			return invalid(CodeInvalidRequest)
		}
	case InnerListOrphanClaimants:
		if p.BanRef != "" {
			return invalid(CodeInvalidRequest)
		}
	default:
		return invalid(CodeInvalidRequest)
	}

	if pageCursor != "" {
		return invalid(CodeInvalidRequest)
	}

	_, err := pageLimit(p.Limit, innerListMaximum(p.List), innerListMaximum(p.List))

	return err
}

// innerSelection is the validated inner page of a ban search: the list, its ban, its page size, and the position a
// cursor continues after. mismatch records a claimant cursor whose aggregate changed since it was issued.
type innerSelection struct {
	contribution *contributionCursor
	list         string
	banRef       string
	total        int64
	offset       int
	limit        int
	claimantNext bool
	mismatch     bool
}

// innerDigest binds an inner-list cursor to the list, the ban, the target, and the window of a ban search.
func (s *banScope) innerDigest(list, banRef string) string {
	return queryDigest(operationBanSearch+"/"+list, s.target.IP, s.target.Network, banRef,
		s.window.From.Format(time.RFC3339Nano), s.window.Until.Format(time.RFC3339Nano))
}

// selectInner validates the cursor of an inner page and freezes the query time of a continuation.
func (s *banScope) selectInner(page *BanInnerPageRequest) *Error {
	if page == nil {
		return nil
	}

	limit, _ := pageLimit(page.Limit, innerListMaximum(page.List), innerListMaximum(page.List))
	selection := &innerSelection{list: page.List, banRef: page.BanRef, limit: limit}
	s.inner = selection

	state, err := decodeListCursor(page.Cursor, s.innerDigest(page.List, page.BanRef), innerCursorMarks(page.List))
	if err != nil || state == nil {
		return err
	}

	s.queriedAt = state.queriedAt()

	if page.List == InnerListContributions {
		if state.AtMillis <= 0 {
			return invalid(CodeInvalidCursor)
		}

		ties, err := cursorTies(state.Marks[2])
		if err != nil {
			return err
		}

		selection.contribution = &contributionCursor{position: ContributionPosition{At: state.at(), EventID: state.Key,
			WindowIndex: state.Marks[0], WindowCurrent: state.Marks[1]}, ties: ties}

		return nil
	}

	if state.Marks[0] <= 0 || state.Marks[0] > math.MaxInt32 || state.Marks[1] < 0 {
		return invalid(CodeInvalidCursor)
	}

	selection.offset, selection.total, selection.claimantNext = int(state.Marks[0]), state.Marks[1], true

	return nil
}

// selects reports whether the inner page names this list of this ban.
func (s *innerSelection) selects(list, banRef string) bool {
	return s != nil && s.list == list && s.banRef == banRef
}

// contributionPage selects the listed contributions of one ban.
type contributionPage struct {
	after  *contributionCursor
	digest string
	limit  int
}

// contributionPage returns the contribution page of one ban: the first MaxContributions unless the inner page
// selects this ban; only a ban search issues cursors.
func (s *banScope) contributionPage(banRef string) contributionPage {
	page := contributionPage{limit: MaxContributions}
	if !s.lists {
		return page
	}

	page.digest = s.innerDigest(InnerListContributions, banRef)
	if s.inner.selects(InnerListContributions, banRef) {
		page.after, page.limit = s.inner.contribution, s.inner.limit
	}

	return page
}

// continued reports whether a counted row sits at the position this page continues from.
func (p contributionPage) continued(record CountedRecord) bool {
	return p.after != nil && p.after.position.holds(record)
}

// cursor renders the continuation after a non-empty listed page with the ties listed at its last position, or nil
// when no cursor may be issued.
func (p contributionPage) cursor(listed []CountedRecord, queriedAt time.Time) *string {
	last := listed[len(listed)-1]
	if p.digest == "" || last.WindowIndex == nil || last.WindowCurrent == nil {
		return nil
	}

	earlier := 0
	if p.after != nil {
		earlier = p.after.ties
	}

	ties := listedTies(listed, sameContribution, p.continued, earlier)
	cursor := encodeListCursor(listCursorState{Digest: p.digest, Key: last.EventID, AtMillis: last.At.UnixMilli(),
		QueriedAt: queriedAt.UnixMilli(), Marks: []int64{*last.WindowIndex, *last.WindowCurrent, int64(ties)}})

	return &cursor
}

// claimantPage selects the listed claimants of one hit summary.
type claimantPage struct {
	inner  *innerSelection
	digest string
	limit  int
}

// claimantPage returns the claimant page of one list: the first MaxClaimants unless the inner page selects it;
// only a ban search issues cursors.
func (s *banScope) claimantPage(list, banRef string) claimantPage {
	page := claimantPage{limit: MaxClaimants}
	if !s.lists {
		return page
	}

	page.digest = s.innerDigest(list, banRef)
	if s.inner.selects(list, banRef) {
		page.inner, page.limit = s.inner, s.inner.limit
	}

	return page
}

// offset returns how many claimants earlier pages listed.
func (p claimantPage) offset() int {
	if p.inner == nil {
		return 0
	}

	return p.inner.offset
}

// bind checks that a continued claimant list still has the aggregate its cursor was issued for; an offset is only
// stable while the counts behind it are.
func (p claimantPage) bind(total int64) {
	if p.inner != nil && p.inner.claimantNext && p.inner.total != total {
		p.inner.mismatch = true
	}
}

// cursor renders the continuation after the listed claimants, or nil when no cursor may be issued.
func (p claimantPage) cursor(listed int, total int64, queriedAt time.Time) *string {
	if p.digest == "" {
		return nil
	}

	cursor := encodeListCursor(listCursorState{Digest: p.digest, QueriedAt: queriedAt.UnixMilli(),
		Marks: []int64{int64(p.offset() + listed), total}})

	return &cursor
}
