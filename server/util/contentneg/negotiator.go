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

// Package contentneg implements server-driven content negotiation against the
// HTTP Accept header following RFC 9110 section 12.5.1.
//
// The package picks the server-preferred response media type from a fixed
// allow-list, honouring quality values, type/subtype wildcards, and parameter
// suffixes such as "; charset=utf-8". Comparison is case-insensitive.
package contentneg

import (
	"mime"
	"strconv"
	"strings"
)

// wildcardAny is the all-types Accept entry "*/*".
const wildcardAny = "*/*"

// Negotiator selects the server-preferred response media type for an HTTP
// Accept header. The supported set is fixed at construction time and ordered
// by server preference: earlier entries win on quality and specificity ties.
type Negotiator struct {
	supported []string
}

// acceptEntry captures a single comma-separated value of an Accept header
// after parsing.
type acceptEntry struct {
	mediaType string
	q         float64
	specifity int
}

// New constructs a Negotiator from server-preferred media types in priority
// order. The supplied values must be in canonical lowercase form
// (e.g. "application/cbor"). An empty supported set yields a Negotiator that
// always returns "".
func New(supported ...string) *Negotiator {
	canonical := make([]string, 0, len(supported))

	for _, s := range supported {
		canonical = append(canonical, strings.ToLower(strings.TrimSpace(s)))
	}

	return &Negotiator{supported: canonical}
}

// BestMatch returns the chosen media type from the supported set, or "" if
// none is acceptable. A missing or empty Accept header is treated as "*/*"
// per RFC 9110 section 12.5.1.
func (n *Negotiator) BestMatch(acceptHeader string) string {
	if len(n.supported) == 0 {
		return ""
	}

	entries := parseAccept(acceptHeader)

	if len(entries) == 0 {
		return ""
	}

	bestType := ""
	bestQ := -1.0
	bestSpec := -1
	bestIdx := len(n.supported)

	for i, candidate := range n.supported {
		for _, entry := range entries {
			if entry.q == 0 {
				continue
			}

			if !matches(entry.mediaType, candidate) {
				continue
			}

			if better(entry.q, entry.specifity, i, bestQ, bestSpec, bestIdx) {
				bestType = candidate
				bestQ = entry.q
				bestSpec = entry.specifity
				bestIdx = i
			}
		}
	}

	return bestType
}

// parseAccept tokenises an Accept header into entries with quality and
// specificity. Invalid tokens are skipped silently, in line with RFC 9110
// recommendations on tolerant parsing.
func parseAccept(header string) []acceptEntry {
	header = strings.TrimSpace(header)

	if header == "" {
		return []acceptEntry{{mediaType: wildcardAny, q: 1.0, specifity: 1}}
	}

	tokens := splitAcceptValues(header)
	entries := make([]acceptEntry, 0, len(tokens))

	for _, token := range tokens {
		token = strings.TrimSpace(token)

		if token == "" {
			continue
		}

		mediaType, params, err := mime.ParseMediaType(token)
		if err != nil {
			continue
		}

		entries = append(entries, acceptEntry{
			mediaType: strings.ToLower(mediaType),
			q:         parseQuality(params["q"]),
			specifity: specifityOf(mediaType),
		})
	}

	if len(entries) == 0 {
		return nil
	}

	return entries
}

// splitAcceptValues splits the header on top-level commas, honouring quoted
// strings so parameters such as `text/plain; foo="a,b"` survive intact.
func splitAcceptValues(header string) []string {
	var (
		out      []string
		start    = 0
		inQuotes = false
	)

	for i := 0; i < len(header); i++ {
		switch header[i] {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				out = append(out, header[start:i])
				start = i + 1
			}
		}
	}

	out = append(out, header[start:])

	return out
}

// parseQuality extracts a q-value, defaulting to 1.0 for missing or
// malformed input and clamping to [0, 1].
func parseQuality(raw string) float64 {
	if raw == "" {
		return 1.0
	}

	q, err := strconv.ParseFloat(raw, 64)

	if err != nil {
		return 1.0
	}

	if q < 0 {
		return 0
	}

	if q > 1 {
		return 1
	}

	return q
}

// specifityOf returns 3 for a fully qualified media type, 2 for a
// subtype-wildcard ("type/*"), and 1 for "*/*".
func specifityOf(mediaType string) int {
	switch {
	case mediaType == wildcardAny:
		return 1
	case strings.HasSuffix(mediaType, "/*"):
		return 2
	default:
		return 3
	}
}

// matches reports whether an Accept entry covers the given candidate type.
func matches(acceptType, candidate string) bool {
	if acceptType == wildcardAny {
		return true
	}

	if strings.HasSuffix(acceptType, "/*") {
		prefix := strings.TrimSuffix(acceptType, "/*")
		slash := strings.IndexByte(candidate, '/')

		return slash > 0 && candidate[:slash] == prefix
	}

	return acceptType == candidate
}

// better reports whether the candidate (q, specificity, supportedIdx) beats
// the current best. Higher q wins; on q ties, higher specificity wins;
// otherwise the earlier supported entry wins (server-preferred order).
func better(q float64, spec, idx int, bestQ float64, bestSpec, bestIdx int) bool {
	switch {
	case q > bestQ:
		return true
	case q < bestQ:
		return false
	case spec > bestSpec:
		return true
	case spec < bestSpec:
		return false
	default:
		return idx < bestIdx
	}
}
