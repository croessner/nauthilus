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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// Bounds of the segment store. A segmented answer is the complete answer of one call, kept for a short time so its
// segments can be fetched one by one; the store never holds more than maxSegmentBytes in total.
const (
	segmentTTL      = 10 * time.Minute
	maxSegmentBytes = 64 << 20

	// maxPrincipalSegmentBytes is one principal's share; its own oldest answers go first, never other principals'.
	maxPrincipalSegmentBytes = 16 << 20

	segmentSchemaVersion = "1"
)

// codeSegmentUnknown marks a segment cursor whose answer expired or never existed.
const codeSegmentUnknown supportaccess.ErrorCode = "SEGMENT_UNKNOWN"

// SegmentStore keeps the complete answers that exceeded a transport bound, bound to the principal that received them
// and to the scopes of their operation. It is process-owned and shared by every transport.
type SegmentStore struct {
	now     func() time.Time
	entries map[string]*segmentEntry
	mu      sync.Mutex
	total   int
}

// segmentEntry is one stored answer; every fetch renders its segment to the bound of that call.
type segmentEntry struct {
	created   time.Time
	body      []byte
	scopes    []string
	principal string
	operation string
}

// NewSegmentStore returns an empty store; now defaults to time.Now.
func NewSegmentStore(now func() time.Time) *SegmentStore {
	if now == nil {
		now = time.Now
	}

	return &SegmentStore{now: now, entries: map[string]*segmentEntry{}}
}

// SegmentRequest asks for one segment of a stored answer.
type SegmentRequest struct {
	SchemaVersion string `json:"schema_version"`
	Cursor        string `json:"cursor"`
}

// segmentAnswer is one segment: a part of the JSON text of the complete answer. Concatenating the data of every
// segment in index order yields the complete answer byte for byte.
type segmentAnswer struct {
	Segment       segmentState `json:"segment"`
	Data          string       `json:"data"`
	SchemaVersion string       `json:"schema_version"`
}

// segmentState states where a segment lies in the complete answer.
type segmentState struct {
	NextCursor *string `json:"next_cursor"`
	Operation  string  `json:"operation"`
	Offset     int     `json:"offset"`
	TotalBytes int     `json:"total_bytes"`
}

// segmentCursor is the opaque position of the next segment; the segment size comes from the stored answer.
type segmentCursor struct {
	ID     string `json:"i"`
	Offset int    `json:"o"`
}

// SizeBound is the size limit of one transport answer: Size returns the bytes a body takes once the transport has
// serialized it (escaping, metadata, envelope), and Limit bounds that size. The zero value is no bound.
type SizeBound struct {
	Size  func(body []byte) int
	Limit int
}

// bounded reports whether the bound limits answers.
func (b SizeBound) bounded() bool {
	return b.Limit > 0
}

// fits reports whether a body stays within the bound once serialized.
func (b SizeBound) fits(body []byte) bool {
	if !b.bounded() {
		return true
	}

	if b.Size == nil {
		return len(body) <= b.Limit
	}

	return b.Size(body) <= b.Limit
}

// responseBoundKey carries the size bound of the transport answer in a context.
type responseBoundKey struct{}

// WithResponseBound returns ctx carrying the size bound of the transport answer, which the segment operation renders
// its segments to.
func WithResponseBound(ctx context.Context, bound SizeBound) context.Context {
	return context.WithValue(ctx, responseBoundKey{}, bound)
}

// responseBound returns the size bound of the transport answer, or no bound.
func responseBound(ctx context.Context) SizeBound {
	bound, _ := ctx.Value(responseBoundKey{}).(SizeBound)

	return bound
}

// Bound returns response unchanged when it fits the bound once serialized; otherwise it stores the complete body and
// returns its first segment, so no answer is discarded for its size. An answer larger than one principal's share, or
// a bound too small for any segment, is RESPONSE_TOO_LARGE.
func (s *SegmentStore) Bound(response Response, operation Operation, credential supportaccess.VerifiedCredential, bound SizeBound) Response {
	if bound.fits(response.Body) {
		return response
	}

	if s == nil || len(response.Body) > maxPrincipalSegmentBytes {
		return ResponseTooLarge(operation)
	}

	entry := &segmentEntry{body: response.Body, scopes: slices.Clone(operation.Scopes), principal: segmentPrincipal(credential),
		operation: operation.Name}

	segment, ok := renderSegment(s.put(entry), entry, 0, bound)
	if !ok {
		return ResponseTooLarge(operation)
	}

	return segment
}

// segmentPrincipal binds segments to the credential method and the principal identity, so a Basic user and an OAuth
// client of the same name never share answers.
func segmentPrincipal(credential supportaccess.VerifiedCredential) string {
	return string(credential.Method) + "\x00" + credential.Identity()
}

// Fetch returns the segment a cursor names to the principal that received the answer, while it holds one of the
// operation's scopes.
func (s *SegmentStore) Fetch(credential supportaccess.VerifiedCredential, request SegmentRequest, bound SizeBound) Response {
	var cursor segmentCursor

	if s == nil || request.SchemaVersion != segmentSchemaVersion || !supportaccess.DecodeCursor(request.Cursor, &cursor) ||
		cursor.Offset < 0 {
		return segmentError(codeInvalidRequest, "The request is malformed or inconsistent.", http.StatusBadRequest)
	}

	entry, ok := s.get(cursor.ID)

	switch {
	case !ok || cursor.Offset >= len(entry.body):
		return segmentError(codeSegmentUnknown, "The segment is unknown or expired; repeat the original call.", http.StatusNotFound)
	case entry.principal != segmentPrincipal(credential) || !slices.ContainsFunc(entry.scopes, credential.HasScope):
		return segmentError("FORBIDDEN", "The caller may not read this answer.", http.StatusForbidden)
	}

	segment, ok := renderSegment(cursor.ID, entry, cursor.Offset, bound)
	if !ok {
		return segmentError(codeResponseTooLarge, "The transport bound is too small for any segment.", http.StatusUnprocessableEntity)
	}

	return segment
}

// renderSegment renders the longest part of a stored answer from offset whose serialized segment fits the bound of
// this call, found by binary search over the chunk end, never splitting a UTF-8 character. Without a bound the rest
// is one segment. The bound comes from each call, so a fetch with a longer request id still fits. The entry is passed
// in, so an answer that expires meanwhile still renders the segment already looked up. ok is false when not even one
// character fits.
func renderSegment(id string, entry *segmentEntry, offset int, bound SizeBound) (Response, bool) {
	rest := len(entry.body) - offset

	if !bound.bounded() || rest <= bound.Limit {
		if body := segmentBody(id, entry, offset, len(entry.body)); bound.fits(body) {
			return Response{Status: http.StatusOK, Body: body}, true
		}
	}

	var best []byte

	// A segment's data is never longer than the bound, so the search starts there instead of at the end.
	for low, high := offset, offset+min(rest-1, bound.Limit); low < high; {
		end := chunkEnd(entry.body, offset, (low+high+1)/2-offset)
		if end <= low {
			end = chunkEnd(entry.body, offset, low-offset+utf8.UTFMax)
		}

		if end <= low || end > high {
			break
		}

		if body := segmentBody(id, entry, offset, end); bound.fits(body) {
			best, low = body, end
		} else {
			high = end - 1
		}
	}

	return Response{Status: http.StatusOK, Body: best}, best != nil
}

// segmentBody renders the segment of the stored answer from offset to end with the cursor of the rest.
func segmentBody(id string, entry *segmentEntry, offset int, end int) []byte {
	answer := segmentAnswer{SchemaVersion: segmentSchemaVersion, Data: string(entry.body[offset:end]),
		Segment: segmentState{Operation: entry.operation, Offset: offset, TotalBytes: len(entry.body)}}

	if end < len(entry.body) {
		next := supportaccess.EncodeCursor(segmentCursor{ID: id, Offset: end})
		answer.Segment.NextCursor = &next
	}

	body, _ := json.Marshal(answer)

	return body
}

// chunkEnd returns the end of a chunk of at most size bytes after offset that does not split a UTF-8 character.
func chunkEnd(body []byte, offset int, size int) int {
	end := min(offset+max(size, utf8.UTFMax), len(body))

	for end < len(body) && end > offset && !utf8.RuneStart(body[end]) {
		end--
	}

	return end
}

// put stores an entry under a fresh random id. Expired entries go first; then the principal's own oldest answers
// while it is above its share, and the oldest answers of all while the store is full.
func (s *SegmentStore) put(entry *segmentEntry) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry.created = s.now()
	s.expire(entry.created)

	for s.principalBytes(entry.principal)+len(entry.body) > maxPrincipalSegmentBytes {
		s.dropOldest(entry.principal)
	}

	for s.total+len(entry.body) > maxSegmentBytes && len(s.entries) > 0 {
		s.dropOldest("")
	}

	var raw [16]byte

	_, _ = rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])

	s.entries[id] = entry
	s.total += len(entry.body)

	return id
}

// principalBytes returns the stored bytes of one principal; the caller holds the lock.
func (s *SegmentStore) principalBytes(principal string) int {
	total := 0

	for _, entry := range s.entries {
		if entry.principal == principal {
			total += len(entry.body)
		}
	}

	return total
}

// get returns a live entry.
func (s *SegmentStore) get(id string) (*segmentEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expire(s.now())
	entry, ok := s.entries[id]

	return entry, ok
}

// expire drops entries older than the segment lifetime; the caller holds the lock.
func (s *SegmentStore) expire(now time.Time) {
	for id, entry := range s.entries {
		if now.Sub(entry.created) >= segmentTTL {
			s.total -= len(entry.body)
			delete(s.entries, id)
		}
	}
}

// dropOldest drops the oldest entry, of one principal when principal is set; the caller holds the lock.
func (s *SegmentStore) dropOldest(principal string) {
	oldest := ""

	for id, entry := range s.entries {
		if principal != "" && entry.principal != principal {
			continue
		}

		if oldest == "" || entry.created.Before(s.entries[oldest].created) {
			oldest = id
		}
	}

	if oldest == "" {
		return
	}

	s.total -= len(s.entries[oldest].body)
	delete(s.entries, oldest)
}

// segmentError renders a fixed segment error.
func segmentError(code supportaccess.ErrorCode, message string, status int) Response {
	body, _ := json.Marshal(errorBody{SchemaVersion: segmentSchemaVersion, Error: errorDetail{Code: string(code), Message: message}})

	return Response{Status: status, Body: body, Code: code}
}

// respondSegment answers the segment operation from the services' store, rendered to the size bound of this call.
func respondSegment(ctx context.Context, services Services, credential supportaccess.VerifiedCredential, raw []byte) Response {
	var request SegmentRequest
	if !DecodeStrict(raw, &request) {
		return segmentError(codeInvalidRequest, "The request is malformed or inconsistent.", http.StatusBadRequest)
	}

	return services.Segments.Fetch(credential, request, responseBound(ctx))
}
