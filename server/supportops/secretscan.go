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

package supportops

import (
	"cmp"
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
)

// textRange is the byte range [start, end) of a free text.
type textRange struct {
	start int
	end   int
}

// jsonSpan is an embedded JSON object or array of a free text with its structural rewrite.
type jsonSpan struct {
	rewritten string
	textRange
}

// secretScan finds the authentication secrets of one free text. The free-text rules read the original text and
// collect the byte ranges of secrets; embedded JSON values stand apart as structured segments that no rule reads
// into. The answer is assembled from the original bytes, the ranges, and the segments, so no byte of the input is
// ever taken for an internal marker.
type secretScan struct {
	text    string
	spans   []jsonSpan
	secrets []textRange
}

// redactText replaces authentication secrets in a free text. Every embedded JSON object or array is rewritten
// structurally like a JSON line (so escaped names inside a dumped body are decoded), while the free-text rules run
// over the whole text, so an assignment keeps its value together: "password=[123456]" or "password={...}" replaces
// the JSON value as a whole. Fields, stored lines, labels, and overview messages all use it, so every representation
// gets the same replacements.
func redactText(text string) (string, bool) {
	scan := secretScan{text: text, spans: embeddedJSONSpans(text)}

	return scan.redact()
}

// redactSecrets replaces authentication secrets inside a free text by the free-text rules alone and reports whether
// it replaced any: signed tokens, URL passwords, authorization credentials, and the values of secret-named
// assignments. Only the secret is replaced; identities, addresses, codes, and error texts stay.
func redactSecrets(text string) (string, bool) {
	scan := secretScan{text: text}

	return scan.redact()
}

// embeddedJSONSpans returns the JSON objects and arrays embedded in a free text, in order and without overlap, each
// with its structural rewrite.
func embeddedJSONSpans(text string) []jsonSpan {
	var spans []jsonSpan

	for index := 0; index < len(text); index++ {
		if text[index] != '{' && text[index] != '[' {
			continue
		}

		end, ok := embeddedJSONEnd(text[index:])
		if !ok {
			continue
		}

		rewritten, err := redactJSONLine(text[index : index+end])
		if err != nil {
			continue
		}

		spans = append(spans, jsonSpan{rewritten: rewritten, textRange: textRange{start: index, end: index + end}})
		index += end - 1
	}

	return spans
}

// embeddedJSONEnd returns the length of the JSON object or array at the start of text, or false when none starts
// there.
func embeddedJSONEnd(text string) (int, bool) {
	decoder := json.NewDecoder(strings.NewReader(text))

	var value json.RawMessage
	if decoder.Decode(&value) != nil {
		return 0, false
	}

	return int(decoder.InputOffset()), true
}

// redact collects the secrets and assembles the answer: every secret range becomes redactedValue, every embedded
// JSON value outside them its structural rewrite, and every other byte stays.
func (s *secretScan) redact() (string, bool) {
	s.collect()

	var out strings.Builder

	out.Grow(len(s.text))

	position := 0

	for _, secret := range s.merged() {
		s.writePlain(&out, position, secret.start)
		out.WriteString(redactedValue)

		position = secret.end
	}

	s.writePlain(&out, position, len(s.text))

	redacted := out.String()

	return redacted, redacted != s.text
}

// writePlain writes text[from:to] with every embedded JSON value in it replaced by its structural rewrite. Secret
// ranges never end inside an embedded JSON value, so every one between from and to lies there completely.
func (s *secretScan) writePlain(out *strings.Builder, from int, to int) {
	index := sort.Search(len(s.spans), func(index int) bool { return s.spans[index].start >= from })

	for ; index < len(s.spans) && s.spans[index].start < to; index++ {
		out.WriteString(s.text[from:s.spans[index].start])
		out.WriteString(s.spans[index].rewritten)

		from = s.spans[index].end
	}

	out.WriteString(s.text[from:to])
}

// collect runs every free-text rule over the text.
func (s *secretScan) collect() {
	for _, pattern := range textSecretPatterns {
		for _, match := range s.matches(pattern) {
			s.add(match[2], match[3])
		}
	}

	for _, match := range s.matches(schemeCredential) {
		if looksLikeCredential(s.text[match[6]:match[7]]) {
			s.add(match[6], match[7])
		}
	}

	s.collectAssignments()
	s.collectFlags()
}

// collectAssignments collects the values of secret-named assignments. A quoted value ends at its closing quote (an
// escaped quote for escaped JSON); an unquoted value ends at whitespace or a pair separator. A match inside the value
// of the assignment before it is part of that value.
func (s *secretScan) collectAssignments() {
	position := 0

	for _, match := range s.matches(assignment) {
		name, ok := s.assignmentName(match)
		if match[0] < position || !ok || match[1] >= len(s.text) || !isSecretField(name) {
			continue
		}

		form := assignmentForm(s.text, match)
		start := valueStart(s.text, match[1], form)
		position = s.valueEnd(start, form)

		s.add(start, position)
	}
}

// flagValueEnd ends the unquoted value of a command-line flag, like the value class of secretFlag.
const flagValueEnd = " \t\n\f\r\"',;\\"

// collectFlags collects the separate value of a secret-named command-line flag and the array item that follows a
// secret-named flag item. A flag value that starts with an embedded JSON value is that value. A search that resumes
// behind an embedded JSON value cannot match "^" there.
func (s *secretScan) collectFlags() {
	for _, match := range s.matches(secretFlag) {
		if match[2] == match[3] && match[0] > 0 || !isSecretField(strings.TrimLeft(s.text[match[4]:match[5]], "-")) {
			continue
		}

		end := match[9]
		if span, ok := s.spanAt(match[8]); ok {
			end = span.end
		} else if !strings.ContainsRune(`'"\`, rune(s.text[match[8]])) {
			end = s.tokenEnd(match[8], flagValueEnd)
		}

		s.add(match[8], end)
	}

	for _, match := range s.matches(secretFlagItem) {
		if isSecretField(strings.TrimLeft(s.text[match[2]:match[3]], "-")) {
			s.add(match[6]+1, match[7]-1)
		}
	}
}

// matches returns the matches of pattern that start outside every embedded JSON value, whose inside the structural
// rewrite owns. A match that starts inside one and reaches past it is dropped, and the search resumes at the end of
// that JSON value, so the dropped match cannot hide one behind it.
func (s *secretScan) matches(pattern *regexp.Regexp) [][]int {
	var kept [][]int

	for from := 0; ; {
		resume := -1

		for _, match := range pattern.FindAllStringSubmatchIndex(s.text[from:], -1) {
			for index := range match {
				if match[index] >= 0 {
					match[index] += from
				}
			}

			span, inside := s.spanOver(match[0])
			if !inside {
				kept = append(kept, match)

				continue
			}

			if match[1] > span.end {
				resume = span.end

				break
			}
		}

		if resume < 0 {
			return kept
		}

		from = resume
	}
}

// add records the secret range [start, end). The inside of an embedded JSON value belongs to its structural rewrite,
// so a range starting there keeps only its part behind the value; a range reaching into an embedded JSON value takes
// the whole value.
func (s *secretScan) add(start int, end int) {
	if span, inside := s.spanOver(start); inside && start > span.start {
		if end <= span.end {
			return
		}

		start = span.end
	}

	if span, inside := s.spanOver(end - 1); end > start && inside && span.end > end {
		end = span.end
	}

	s.secrets = append(s.secrets, textRange{start: start, end: end})
}

// merged returns the secret ranges in order with overlapping ranges joined, so each secret is replaced once.
func (s *secretScan) merged() []textRange {
	slices.SortFunc(s.secrets, func(left textRange, right textRange) int {
		return cmp.Or(cmp.Compare(left.start, right.start), cmp.Compare(left.end, right.end))
	})

	var merged []textRange

	for _, secret := range s.secrets {
		if last := len(merged) - 1; last >= 0 && (secret.start < merged[last].end || secret.start == merged[last].start) {
			merged[last].end = max(merged[last].end, secret.end)

			continue
		}

		merged = append(merged, secret)
	}

	return merged
}

// spanOver returns the embedded JSON value that holds the byte at position.
func (s *secretScan) spanOver(position int) (jsonSpan, bool) {
	index := sort.Search(len(s.spans), func(index int) bool { return s.spans[index].end > position })
	if index < len(s.spans) && s.spans[index].start <= position {
		return s.spans[index], true
	}

	return jsonSpan{}, false
}

// spanAt returns the embedded JSON value that starts at position.
func (s *secretScan) spanAt(position int) (jsonSpan, bool) {
	span, inside := s.spanOver(position)

	return span, inside && span.start == position
}

// tokenEnd returns the first separator at or after start outside every embedded JSON value, or the text length: an
// embedded JSON value is part of the token it stands in.
func (s *secretScan) tokenEnd(start int, separators string) int {
	for position := start; position < len(s.text); {
		end := strings.IndexAny(s.text[position:], separators)
		if end < 0 {
			break
		}

		span, inside := s.spanOver(position + end)
		if !inside {
			return position + end
		}

		position = span.end
	}

	return len(s.text)
}

// valueEnd returns where the assignment value that starts at start ends. A value that starts with an embedded JSON
// value is that value; any other unquoted value runs to its separator with embedded JSON values inside.
func (s *secretScan) valueEnd(start int, form valueForm) int {
	if span, ok := s.spanAt(start); ok {
		return span.end
	}

	rest := s.text[start:]

	switch {
	case (form == formJSON || form == formCookie) && (strings.HasPrefix(rest, "{") || strings.HasPrefix(rest, "[")):
		return start + bracketEnd(rest)
	case strings.HasPrefix(rest, `"`), strings.HasPrefix(rest, "'"):
		return start + quotedEnd(rest, rest[0])
	}

	if end, ok := escapedQuotedEnd(rest); ok {
		return start + end
	}

	return s.tokenEnd(start, valueSeparators(form))
}

// valueSeparators returns the bytes that end an unquoted value of the given form.
func valueSeparators(form valueForm) string {
	switch form {
	case formStruct:
		return structValueEnd
	case formHeader, formCookie:
		return "\r\n"
	default:
		return unquotedValueEnd
	}
}

// assignmentName returns the name of one assignment match when it does not continue a word, its quotes are balanced,
// and a colon form is either without a space or an HTTP header. Leading dashes and underscores (--password, _secret)
// do not continue a word.
func (s *secretScan) assignmentName(match []int) (string, bool) {
	text := s.text

	if match[0] > 0 && unicode.IsLetter(rune(text[match[0]-1])) {
		return "", false
	}

	if match[2] >= 0 {
		return text[match[4]:match[5]], text[match[2]:match[3]] == text[match[6]:match[7]]
	}

	name := text[match[8]:match[9]]
	spaced := text[match[1]-1] == ':' && (match[1] >= len(text) || unicode.IsSpace(rune(text[match[1]])))

	if !spaced || strings.HasSuffix(text[match[0]:match[1]], "::") {
		return name, true
	}

	return name, s.spacedAssignment(name, match[1])
}

// spacedAssignment decides a "name: value" pair with a space whose value starts at position: a cookie header needs
// cookie pairs, an Authorization header a credential, and any other name must be an identifier or a header name, not
// a word of prose.
func (s *secretScan) spacedAssignment(name string, position int) bool {
	words := nameWords(name)
	if len(words) == 0 {
		return false
	}

	value := s.text[position:]

	switch words[len(words)-1] {
	case nameCookie:
		return holdsCookiePairs(value)
	case nameAuthorization:
		return holdsCredential(value)
	default:
		return isHeaderName(name) || s.quotedValue(position) || isIdentifierName(name) && singleValue(value)
	}
}

// quotedValue reports whether the value after "name: " at position starts with a quote or an embedded JSON value, as
// a YAML or dumped value does; a wrapped error continues with an unquoted reason.
func (s *secretScan) quotedValue(position int) bool {
	for position < len(s.text) && strings.IndexByte(" \t\\", s.text[position]) >= 0 {
		position++
	}

	if position >= len(s.text) {
		return false
	}

	_, embedded := s.spanAt(position)

	return embedded || s.text[position] == '"' || s.text[position] == '\''
}
