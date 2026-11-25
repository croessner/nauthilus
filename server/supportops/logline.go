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
	"slices"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

const (
	// LogFormatRaw marks a line that is neither slog JSON nor slog text; its text is the field "line".
	LogFormatRaw = "raw"

	// slogLevelField and slogMessageField are the level and message keys of every Nauthilus log line.
	slogLevelField   = "level"
	slogMessageField = "msg"
)

// logEventOf turns one stored line into a log event: the complete line and every field of it (a repeated name keeps
// all its values), with authentication secrets replaced and named.
func logEventOf(line LogLine) LogEvent {
	fields, repeated, format := parseLogLine(line.Line)
	event := LogEvent{At: line.At.UTC(), Instance: supportaccess.VerbatimText(line.Instance), Format: format,
		RepeatedFields: verbatimAll(repeated)}

	redactedLine, lineRedacted := redactLine(line.Line, format)
	event.Line = supportaccess.VerbatimText(redactedLine)
	event.Labels, event.RedactedFields = cleanLabels(line.Labels, labelsFieldPrefix)

	cleaned, redacted := cleanFields(fields, "", &event.SecretsRedacted)
	event.Fields, event.RedactedFields = cleaned, append(event.RedactedFields, redacted...)
	event.SecretsRedacted = event.SecretsRedacted || lineRedacted

	slices.Sort(event.RedactedFields)
	slices.Sort(event.RepeatedFields)

	event.Level = strings.ToLower(stringField(cleaned, slogLevelField))
	event.Message = stringField(cleaned, slogMessageField)

	return event
}

// stringField returns a string field or "".
func stringField(fields map[string]any, name string) string {
	value, _ := fields[name].(string)

	return value
}

// parseLogLine reads a slog JSON or slog text line with the paths of repeated names; any other line has no fields
// and is returned only as the event line.
func parseLogLine(line string) (map[string]any, []string, string) {
	trimmed := strings.TrimSpace(line)

	if strings.HasPrefix(trimmed, "{") {
		if fields, repeated, err := parseJSONFields(trimmed); err == nil {
			return fields, repeated, LogFormatJSON
		}
	}

	if fields, repeated, ok := parseLogfmt(trimmed); ok {
		return fields, repeated, LogFormatLogfmt
	}

	return map[string]any{}, nil, LogFormatRaw
}

// parseLogfmt reads a slog text line of key=value pairs whose values are bare or Go-quoted. It accepts the line only
// when it carries a level and a msg key, so free text never reads as fields.
func parseLogfmt(line string) (map[string]any, []string, bool) {
	repeated := []string{}
	set := newFieldSet("", &repeated)
	rest := line

	for rest = strings.TrimLeft(rest, " "); rest != ""; rest = strings.TrimLeft(rest, " ") {
		key, after, found := strings.Cut(rest, "=")
		if !found || key == "" || strings.ContainsAny(key, " \"") {
			return nil, nil, false
		}

		value, remainder, ok := logfmtValue(after)
		if !ok {
			return nil, nil, false
		}

		set.add(key, value)

		rest = remainder
	}

	_, hasLevel := set.values[slogLevelField]
	_, hasMessage := set.values[slogMessageField]

	return set.values, repeated, hasLevel && hasMessage
}

// logfmtValue reads one bare or quoted value and returns it with the rest of the line.
func logfmtValue(text string) (string, string, bool) {
	if !strings.HasPrefix(text, `"`) {
		value, remainder, _ := strings.Cut(text, " ")

		return value, remainder, true
	}

	prefix, err := strconv.QuotedPrefix(text)
	if err != nil {
		return "", "", false
	}

	value, err := strconv.Unquote(prefix)

	return value, text[len(prefix):], err == nil
}

// cleanFields copies fields with every string made verbatim-safe and every authentication secret replaced. Secret
// field names are returned with their path; secrets inside free text set textRedacted.
func cleanFields(fields map[string]any, path string, textRedacted *bool) (map[string]any, []string) {
	cleaned := make(map[string]any, len(fields))
	redacted := []string{}

	for name, value := range fields {
		fieldPath := joinFieldPath(path, name)
		key := supportaccess.VerbatimText(name)

		if isSecretField(name) && value != nil {
			cleaned[key] = redactedValue

			redacted = append(redacted, fieldPath)

			continue
		}

		var inner []string

		cleaned[key], inner = cleanValue(value, fieldPath, textRedacted)
		redacted = append(redacted, inner...)
	}

	return cleaned, redacted
}

// cleanValue cleans one field value; objects and arrays are cleaned recursively.
func cleanValue(value any, path string, textRedacted *bool) (any, []string) {
	switch typed := value.(type) {
	case string:
		text, replaced := redactText(supportaccess.VerbatimText(typed))
		*textRedacted = *textRedacted || replaced

		return text, nil
	case map[string]any:
		return cleanFields(typed, path, textRedacted)
	case []any:
		items := make([]any, 0, len(typed))

		var redacted []string

		for index, item := range typed {
			if index > 0 && isSecretFlag(typed[index-1]) {
				items = append(items, redactedValue)
				redacted = append(redacted, path)

				continue
			}

			cleaned, inner := cleanValue(item, path, textRedacted)
			items = append(items, cleaned)
			redacted = append(redacted, inner...)
		}

		return items, redacted
	default:
		return value, nil
	}
}

// joinFieldPath names a nested field as parent.child with the name made verbatim-safe.
func joinFieldPath(path string, name string) string {
	return fieldPathOf(path, supportaccess.VerbatimText(name))
}

// labelsFieldPrefix names stream labels in redacted_fields.
const labelsFieldPrefix = "labels"

// cleanLabels copies labels with names and values made verbatim-safe: a secret-named label is replaced and named as
// prefix.name, and secrets inside other values are replaced.
func cleanLabels(labels map[string]string, prefix string) (map[string]string, []string) {
	cleaned := make(map[string]string, len(labels))
	redacted := []string{}

	for name, value := range labels {
		key := supportaccess.VerbatimText(name)

		if isSecretField(name) {
			cleaned[key] = redactedValue

			redacted = append(redacted, fieldPathOf(prefix, key))

			continue
		}

		cleaned[key], _ = redactText(supportaccess.VerbatimText(value))
	}

	return cleaned, redacted
}

// verbatimAll returns the values made verbatim-safe, or nil for none.
func verbatimAll(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	cleaned := make([]string, 0, len(values))

	for _, value := range values {
		cleaned = append(cleaned, supportaccess.VerbatimText(value))
	}

	return cleaned
}
