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

package supportapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// segmentOperator is a verified operations caller.
var segmentOperator = supportaccess.VerifiedCredential{Method: supportaccess.CredentialOAuthUser, ClientID: "cli", Subject: "ops",
	Scopes: []string{definitions.ScopeOperationsRead}}

// largeBody returns a JSON answer of about size bytes with multi-byte characters at every chunk boundary.
func largeBody(size int) []byte {
	body, _ := json.Marshal(map[string]string{"text": strings.Repeat("ä\"€x<\\", size/10)})

	return body
}

// collectSegments fetches every segment after the first and returns the concatenated data.
func collectSegments(t *testing.T, store *SegmentStore, credential supportaccess.VerifiedCredential, first Response) []byte {
	t.Helper()

	var reassembled []byte

	for response := first; ; {
		var answer segmentAnswer
		if err := json.Unmarshal(response.Body, &answer); err != nil || response.Status != http.StatusOK {
			t.Fatalf("segment = %d %s", response.Status, response.Body)
		}

		reassembled = append(reassembled, answer.Data...)

		if answer.Segment.NextCursor == nil {
			return reassembled
		}

		response = store.Fetch(credential, SegmentRequest{SchemaVersion: "1", Cursor: *answer.Segment.NextCursor}, SizeBound{Limit: 8 << 10})
	}
}

// TestSegmentsReassembleTheCompleteAnswer reproduces the final review: an answer above the transport bound was
// replaced by RESPONSE_TOO_LARGE. It must arrive in bounded segments that concatenate to the exact answer.
func TestSegmentsReassembleTheCompleteAnswer(t *testing.T) {
	store := NewSegmentStore(nil)
	operation, _ := Lookup(OperationLogEvents)
	body := largeBody(100 << 10)
	budget := 16 << 10

	first := store.Bound(Response{Status: http.StatusOK, Body: body}, operation, segmentOperator, SizeBound{Limit: budget})
	if len(first.Body) > budget {
		t.Fatalf("first segment = %d bytes, budget %d", len(first.Body), budget)
	}

	if reassembled := collectSegments(t, store, segmentOperator, first); string(reassembled) != string(body) {
		t.Fatalf("reassembled %d bytes, want %d", len(reassembled), len(body))
	}

	if small := store.Bound(Response{Status: http.StatusOK, Body: []byte(`{}`)}, operation, segmentOperator, SizeBound{Limit: budget}); string(small.Body) != `{}` {
		t.Fatalf("a fitting answer must stay unchanged: %s", small.Body)
	}
}

// TestSegmentsStayWithTheirCaller pins that only the receiving principal with the operation's scope reads segments,
// that expired segments are unknown, and that a store-less transport still refuses an oversized answer.
func TestSegmentsStayWithTheirCaller(t *testing.T) {
	now := time.Date(2026, time.November, 25, 12, 0, 0, 0, time.UTC)
	store := NewSegmentStore(func() time.Time { return now })
	operation, _ := Lookup(OperationLogEvents)

	var answer segmentAnswer

	_ = json.Unmarshal(store.Bound(Response{Status: http.StatusOK, Body: largeBody(64 << 10)}, operation, segmentOperator, SizeBound{Limit: 8 << 10}).Body, &answer)
	request := SegmentRequest{SchemaVersion: "1", Cursor: *answer.Segment.NextCursor}
	other := segmentOperator
	other.Subject = "someone-else"
	historyOnly := segmentOperator
	historyOnly.Scopes = []string{definitions.ScopeHistoryRead}

	for name, tc := range map[string]struct {
		credential supportaccess.VerifiedCredential
		status     int
	}{
		"other principal": {other, http.StatusForbidden},
		"missing scope":   {historyOnly, http.StatusForbidden},
		"receiver":        {segmentOperator, http.StatusOK},
	} {
		if got := store.Fetch(tc.credential, request, SizeBound{Limit: 8 << 10}); got.Status != tc.status {
			t.Errorf("%s: status = %d %s", name, got.Status, got.Body)
		}
	}

	now = now.Add(segmentTTL)

	if expired := store.Fetch(segmentOperator, request, SizeBound{Limit: 8 << 10}); expired.Code != codeSegmentUnknown {
		t.Fatalf("expired = %d %s", expired.Status, expired.Body)
	}

	var none *SegmentStore
	if refused := none.Bound(Response{Status: http.StatusOK, Body: largeBody(64 << 10)}, operation, segmentOperator, SizeBound{Limit: 8 << 10}); refused.Code != codeResponseTooLarge {
		t.Fatalf("store-less bound = %s", refused.Body)
	}
}

// TestSegmentsSurviveExpiryAndEviction reproduces the final review: an answer that expired or was evicted between
// two lookups dereferenced nil. Fetch and Bound must answer without a panic.
func TestSegmentsSurviveExpiryAndEviction(t *testing.T) {
	base := time.Date(2026, time.November, 25, 12, 0, 0, 0, time.UTC)
	calls, advance := 0, false
	store := NewSegmentStore(func() time.Time {
		if advance {
			calls++
			if calls >= 2 {
				return base.Add(segmentTTL)
			}
		}

		return base
	})
	operation, _ := Lookup(OperationLogEvents)

	var answer segmentAnswer

	_ = json.Unmarshal(store.Bound(Response{Status: http.StatusOK, Body: largeBody(64 << 10)}, operation, segmentOperator, SizeBound{Limit: 8 << 10}).Body, &answer)
	advance = true

	store.Fetch(segmentOperator, SegmentRequest{SchemaVersion: "1", Cursor: *answer.Segment.NextCursor}, SizeBound{Limit: 8 << 10})

	big := []byte(`"` + strings.Repeat("a", maxPrincipalSegmentBytes-16) + `"`)

	var wait sync.WaitGroup

	for range 8 {
		wait.Go(func() {
			for range 20 {
				store.Bound(Response{Status: http.StatusOK, Body: big}, operation, segmentOperator, SizeBound{Limit: 8 << 10})
			}
		})
	}

	wait.Wait()

	if got := store.Bound(Response{Status: http.StatusOK, Body: big}, operation, segmentOperator, SizeBound{Limit: 8 << 10}); got.Status != http.StatusOK {
		t.Fatalf("bound after eviction = %d %s", got.Status, got.Body)
	}
}

// TestSegmentsKeepTheirBudgetAndShare pins that every segment fits the bound of the answer whatever a cursor says,
// and that one principal's answers never evict another principal's.
func TestSegmentsKeepTheirBudgetAndShare(t *testing.T) {
	store := NewSegmentStore(nil)
	operation, _ := Lookup(OperationLogEvents)
	other := segmentOperator
	other.Subject = "other"

	var kept segmentAnswer

	_ = json.Unmarshal(store.Bound(Response{Status: http.StatusOK, Body: largeBody(64 << 10)}, operation, other, SizeBound{Limit: 8 << 10}).Body, &kept)

	big := []byte(`"` + strings.Repeat("a", maxPrincipalSegmentBytes-16) + `"`)
	for range 8 {
		store.Bound(Response{Status: http.StatusOK, Body: big}, operation, segmentOperator, SizeBound{Limit: 8 << 10})
	}

	if got := store.Fetch(other, SegmentRequest{SchemaVersion: "1", Cursor: *kept.Segment.NextCursor}, SizeBound{Limit: 8 << 10}); got.Status != http.StatusOK || len(got.Body) > 8<<10 {
		t.Fatalf("other principal's segment = %d, %d bytes", got.Status, len(got.Body))
	}
}
