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
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// errLineSyntax reports a line the structural redaction cannot read; it then falls back to the free-text rules.
var errLineSyntax = errors.New("log line syntax")

// redactedJSON is the JSON value that replaces a secret in a stored JSON line.
var redactedJSON = strconv.Quote(redactedValue)

// redactLine returns a stored line with authentication secrets replaced by the same rules the event fields get. A
// JSON or slog text line is read token by token: names and values are decoded (so escapes cannot hide a name or a
// value), a secret-named value is replaced, every other string value passes the free-text rules, and only a changed
// value is encoded again. Everything else of the line stays byte for byte, repeated names included. Any other line
// passes the free-text rules.
func redactLine(line string, format string) (string, bool) {
	var (
		redacted string
		err      error
	)

	switch format {
	case LogFormatJSON:
		redacted, err = redactJSONLine(line)
	case LogFormatLogfmt:
		redacted, err = redactLogfmtLine(line)
	default:
		err = errLineSyntax
	}

	if err != nil {
		return redactText(line)
	}

	return redacted, redacted != line
}

// jsonLine rewrites one JSON line: src is the line, pos the read position, and out the rewritten line.
type jsonLine struct {
	out strings.Builder
	src string
	pos int
}

// redactJSONLine rewrites a JSON line; the line must hold exactly one value.
func redactJSONLine(line string) (string, error) {
	rewriter := &jsonLine{src: line}

	if err := rewriter.value(false); err != nil {
		return "", err
	}

	rewriter.space()

	if rewriter.pos != len(line) {
		return "", errLineSyntax
	}

	return rewriter.out.String(), nil
}

// space copies whitespace.
func (j *jsonLine) space() {
	start := j.pos

	for j.pos < len(j.src) && strings.IndexByte(" \t\r\n", j.src[j.pos]) >= 0 {
		j.pos++
	}

	j.out.WriteString(j.src[start:j.pos])
}

// value rewrites one value; secret replaces a non-null value as a whole.
func (j *jsonLine) value(secret bool) error {
	j.space()

	start := j.pos

	if err := j.skip(); err != nil {
		return err
	}

	raw := j.src[start:j.pos]
	j.pos = start

	switch {
	case secret && raw != "null":
		j.out.WriteString(redactedJSON)
		j.pos += len(raw)

		return nil
	case raw[0] == '{':
		return j.object()
	case raw[0] == '[':
		return j.array()
	case raw[0] == '"':
		j.pos += len(raw)

		return j.text(raw)
	default:
		j.out.WriteString(raw)
		j.pos += len(raw)

		return nil
	}
}

// object rewrites an object; a member with a secret name gets its value replaced.
func (j *jsonLine) object() error {
	j.out.WriteByte('{')
	j.pos++

	for {
		j.space()

		if j.pos < len(j.src) && j.src[j.pos] == '}' {
			j.out.WriteByte('}')
			j.pos++

			return nil
		}

		name, err := j.name()
		if err != nil {
			return err
		}

		if err = j.value(isSecretField(name)); err != nil {
			return err
		}

		if err = j.separator('}'); err != nil {
			return err
		}
	}
}

// name copies one member name and its colon and returns the decoded name.
func (j *jsonLine) name() (string, error) {
	start := j.pos
	if err := j.skip(); err != nil || j.src[start] != '"' {
		return "", errLineSyntax
	}

	var name string
	if err := json.Unmarshal([]byte(j.src[start:j.pos]), &name); err != nil {
		return "", errLineSyntax
	}

	j.out.WriteString(j.src[start:j.pos])
	j.space()

	if j.pos >= len(j.src) || j.src[j.pos] != ':' {
		return "", errLineSyntax
	}

	j.out.WriteByte(':')
	j.pos++

	return name, nil
}

// array rewrites an array; the item after a secret-named flag item is replaced, like in the fields.
func (j *jsonLine) array() error {
	j.out.WriteByte('[')
	j.pos++

	var previous any

	for {
		j.space()

		if j.pos < len(j.src) && j.src[j.pos] == ']' {
			j.out.WriteByte(']')
			j.pos++

			return nil
		}

		start := j.pos
		if err := j.value(isSecretFlag(previous)); err != nil {
			return err
		}

		previous = nil
		_ = json.Unmarshal([]byte(strings.TrimSpace(j.src[start:j.pos])), &previous)

		if err := j.separator(']'); err != nil {
			return err
		}
	}
}

// separator copies the comma between members or items, or leaves the closing bracket for the caller.
func (j *jsonLine) separator(closing byte) error {
	j.space()

	switch {
	case j.pos < len(j.src) && j.src[j.pos] == ',':
		j.out.WriteByte(',')
		j.pos++

		return nil
	case j.pos < len(j.src) && j.src[j.pos] == closing:
		return nil
	default:
		return errLineSyntax
	}
}

// text rewrites one string value: the decoded text passes the free-text rules and is encoded again only when they
// changed it.
func (j *jsonLine) text(raw string) error {
	var decoded string
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return errLineSyntax
	}

	redacted, changed := redactText(decoded)
	if !changed {
		j.out.WriteString(raw)

		return nil
	}

	j.out.WriteString(encodeJSONText(redacted))

	return nil
}

// skip moves past one value without writing it.
func (j *jsonLine) skip() error {
	if j.pos >= len(j.src) {
		return errLineSyntax
	}

	switch j.src[j.pos] {
	case '"':
		end := quotedEnd(j.src[j.pos:], '"')
		if end < 2 || j.src[j.pos+end-1] != '"' {
			return errLineSyntax
		}

		j.pos += end
	case '{', '[':
		end := bracketEnd(j.src[j.pos:])
		if end <= 1 {
			return errLineSyntax
		}

		j.pos += end
	default:
		end := strings.IndexAny(j.src[j.pos:], ",}] \t\r\n")
		if end < 0 {
			end = len(j.src) - j.pos
		}

		if end == 0 {
			return errLineSyntax
		}

		j.pos += end
	}

	return nil
}

// encodeJSONText encodes a string as JSON without HTML escapes, so <redacted> stays readable.
func encodeJSONText(text string) string {
	var buffer bytes.Buffer

	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(text)

	return strings.TrimSuffix(buffer.String(), "\n")
}

// redactLogfmtLine rewrites a slog text line pair by pair: a secret-named value is replaced, every other value passes
// the free-text rules and is encoded again only when they changed it, quoted like before or when it needs quotes.
func redactLogfmtLine(line string) (string, error) {
	var out strings.Builder

	rest := line

	for rest != "" {
		trimmed := strings.TrimLeft(rest, " ")
		out.WriteString(rest[:len(rest)-len(trimmed)])
		rest = trimmed

		if rest == "" {
			break
		}

		key, after, found := strings.Cut(rest, "=")
		if !found || key == "" || strings.ContainsAny(key, " \"") {
			return "", errLineSyntax
		}

		value, remainder, ok := logfmtValue(after)
		if !ok {
			return "", errLineSyntax
		}

		raw := after[:len(after)-len(remainder)]
		separator := ""

		if !strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, " ") {
			raw, separator = raw[:len(raw)-1], " "
		}

		out.WriteString(key + "=" + logfmtRewrite(key, value, raw) + separator)

		rest = remainder
	}

	return out.String(), nil
}

// logfmtRewrite returns the rewritten value of one pair.
func logfmtRewrite(key string, value string, raw string) string {
	if isSecretField(key) {
		return redactedValue
	}

	redacted, changed := redactText(value)
	if !changed {
		return raw
	}

	if strings.HasPrefix(raw, `"`) || strings.ContainsAny(redacted, " \"=\t") {
		return strconv.Quote(redacted)
	}

	return redacted
}
