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
	"regexp"
	"strings"
	"unicode"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

const (
	// maxMessageRunes bounds one normalized log message that leaves the host.
	maxMessageRunes = 160

	// maxRawMessageRunes bounds the raw message before it is normalized.
	maxRawMessageRunes = 1024

	// maxPlainTokenRunes is the longest word that can stay verbatim; longer words are identifiers or payloads.
	maxPlainTokenRunes = 32

	// maxCaseTransitions is the most lower-to-upper case changes a word such as WebAuthn may have; more mark encoded
	// values such as tokens.
	maxCaseTransitions = 1

	// maxSlashSegments is the most segments a word such as free/busy may have; more mark a path.
	maxSlashSegments = 2

	placeholderValue  = "<value>"
	placeholderQuoted = "<quoted>"
	placeholderEmpty  = "<empty>"

	// wordSeparators split words besides whitespace, so "user:alice" and "user-alice" are two words.
	wordSeparators = ":,;()[]{}-!?"

	// valueCharacters mark a word as a value: addresses, assignments, escapes, and encodings.
	valueCharacters = "@=%\\#&+$<>\"'`~*|^"
)

// quotedSpan matches a double-quoted, backquoted, or word-initial single-quoted span. Log messages put variable
// values such as usernames, IPs, and paths in quotes; the span is dropped as a whole.
var quotedSpan = regexp.MustCompile("\"[^\"]*\"|`[^`]*`|(^|[\\s=:(\\[])'[^']*'")

// urlPattern matches a URL as a whole, before the colon separator would split it.
var urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://\S*`)

// colonPath matches a word of three or more colon-joined parts, such as a Redis key "nauthilus:bf:jdoe", which the
// colon separator would otherwise split into innocent-looking words.
var colonPath = regexp.MustCompile(`[^\s:]*(?::[^\s:]+){2,}`)

// hexColonGroups matches IPv6-like hex groups, which the colon separator would otherwise split into words.
var hexColonGroups = regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,}\b`)

// sensitiveKeywords name a value that follows them in a message, such as "user alice", "login: bob", or "for carol".
var sensitiveKeywords = wordSet("user", "username", "login", "account", "subject", "mailbox", "email", "mail",
	"password", "token", "secret", "ip", "for", "from", "by", "client", "host", "peer", "session", "bearer", "dn", "uid",
	"name", "key")

// statusWords end the effect of a sensitive keyword: in "user not found" or "token expired" the next word describes
// the state, not a value.
var statusWords = wordSet("not", "no", "is", "are", "was", "were", "has", "have", "had", "be", "been", "the", "a", "an",
	"and", "or", "to", "of", "in", "on", "at", "with", "without", "found", "missing", "unknown", "invalid", "empty",
	"expired", "locked", "failed", "denied", "rejected", "unreachable", "required", "disabled", "enabled", "changed",
	"created", "deleted", "exists", "unavailable", "timeout", "error", "mismatch")

// wordSet builds a lookup set of lower-case words.
func wordSet(words ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(words))
	for _, word := range words {
		set[word] = struct{}{}
	}

	return set
}

// normalizeLogMessage returns the form of an observed log message that may leave the host, and whether it is the
// message as logged (literal) or with variable-looking parts replaced (normalized). Control and format characters
// become spaces first, so a tab or newline cannot join a value to a keyword. Quoted spans, IPv6-like groups, and every
// word that looks like a value become placeholders, and so does the word after a sensitive keyword unless it is a
// status word. A letter-only value outside quotes, brackets, and keyword positions cannot be told apart from a word
// and stays; the result is untrusted data.
func normalizeLogMessage(raw string) (string, string) {
	spaced := strings.Map(func(char rune) rune {
		if unicode.IsControl(char) || unicode.Is(unicode.Cf, char) {
			return ' '
		}

		return char
	}, raw)

	sanitized := supportaccess.SanitizeText(spaced, maxRawMessageRunes)
	if strings.TrimSpace(sanitized) == "" {
		return placeholderEmpty, MessageFormNormalized
	}

	unquoted := quotedSpan.ReplaceAllStringFunc(sanitized, func(span string) string {
		prefix := ""
		if !strings.ContainsAny(span[:1], "\"`'") {
			prefix = span[:1]
		}

		return prefix + " " + placeholderQuoted + " "
	})

	unquoted = urlPattern.ReplaceAllString(unquoted, " "+placeholderValue+" ")
	unquoted = colonPath.ReplaceAllString(unquoted, " "+placeholderValue+" ")
	unquoted = hexColonGroups.ReplaceAllString(unquoted, " "+placeholderValue+" ")

	text := supportaccess.SanitizeText(maskWords(splitWords(unquoted)), maxMessageRunes)
	if text == raw {
		return text, MessageFormLiteral
	}

	return text, MessageFormNormalized
}

// messagePiece is one word of a message and the separator text in front of it.
type messagePiece struct {
	separator string
	word      string
}

// splitWords splits a message into words and the separators in front of them; the last piece may carry only a
// trailing separator. Whitespace runs collapse to one space.
func splitWords(message string) []messagePiece {
	var (
		pieces    []messagePiece
		separator strings.Builder
		word      strings.Builder
	)

	flush := func() {
		if word.Len() > 0 {
			pieces = append(pieces, messagePiece{separator: separator.String(), word: word.String()})
			separator.Reset()
			word.Reset()
		}
	}

	for _, char := range message {
		switch {
		case unicode.IsSpace(char):
			flush()

			if !strings.HasSuffix(separator.String(), " ") {
				separator.WriteByte(' ')
			}
		case strings.ContainsRune(wordSeparators, char):
			flush()
			separator.WriteRune(char)
		default:
			word.WriteRune(char)
		}
	}

	flush()

	if separator.Len() > 0 {
		pieces = append(pieces, messagePiece{separator: separator.String()})
	}

	return pieces
}

// maskWords replaces value words, joins the pieces, and collapses placeholders separated only by whitespace or colons,
// such as a host and port. A keyword after a keyword stays, so "for user alice" keeps "user".
func maskWords(pieces []messagePiece) string {
	var builder strings.Builder

	pendingKeyword, lastPlaceholder := false, false

	for index, piece := range pieces {
		word := maskWord(pieces, index, pendingKeyword)
		_, keyword := sensitiveKeywords[strings.ToLower(piece.word)]

		listContinues := pendingKeyword && isPlaceholder(word) && nextSeparator(pieces, index) == ","
		pendingKeyword = keyword || listContinues

		if isPlaceholder(word) && lastPlaceholder && strings.Trim(piece.separator, " :") == "" {
			continue
		}

		lastPlaceholder = isPlaceholder(word)

		builder.WriteString(piece.separator)
		builder.WriteString(word)
	}

	return strings.TrimSpace(builder.String())
}

// maskWord returns the word at index or its placeholder; pendingKeyword tells that a sensitive keyword precedes it.
func maskWord(pieces []messagePiece, index int, pendingKeyword bool) string {
	word := pieces[index].word
	lower := strings.ToLower(word)
	_, status := statusWords[lower]
	_, keyword := sensitiveKeywords[lower]

	switch {
	case word == "" || isPlaceholder(word):
		return word
	case isValueWord(word), isEnclosed(pieces, index), pendingKeyword && !status && !keyword:
		return placeholderValue
	default:
		return word
	}
}

// isEnclosed reports whether the word at index stands alone in parentheses or brackets, such as "(alice)".
func isEnclosed(pieces []messagePiece, index int) bool {
	opened := strings.HasSuffix(pieces[index].separator, "(") || strings.HasSuffix(pieces[index].separator, "[")

	return opened && strings.IndexAny(nextSeparator(pieces, index), ")]") == 0
}

// nextSeparator returns the separator after the word at index, or "" at the end.
func nextSeparator(pieces []messagePiece, index int) string {
	if index+1 >= len(pieces) {
		return ""
	}

	return pieces[index+1].separator
}

// isValueWord reports whether a word looks like a value rather than a word of a fixed message: it carries a digit,
// an invalid character, an address, assignment, or encoding character, a URL scheme, an inner dot (host names,
// dotted names), a path, or several case changes, or it is long.
func isValueWord(word string) bool {
	switch {
	case len([]rune(word)) > maxPlainTokenRunes, strings.Contains(word, "://"), strings.ContainsAny(word, valueCharacters),
		strings.ContainsRune(word, '\uFFFD'), strings.ContainsFunc(word, unicode.IsDigit):
		return true
	case strings.Contains(strings.Trim(word, "."), "."):
		return true
	case strings.Contains(word, "/") && (strings.HasPrefix(word, "/") || strings.HasSuffix(word, "/") ||
		strings.Count(word, "/")+1 > maxSlashSegments):
		return true
	default:
		return caseTransitions(word) > maxCaseTransitions
	}
}

// caseTransitions counts lower-to-upper case changes inside a word.
func caseTransitions(word string) int {
	transitions, previousLower := 0, false

	for _, char := range word {
		if unicode.IsUpper(char) && previousLower {
			transitions++
		}

		previousLower = unicode.IsLower(char)
	}

	return transitions
}

// isPlaceholder reports whether a word is one of the normalization placeholders.
func isPlaceholder(word string) bool {
	return word == placeholderValue || word == placeholderQuoted
}
