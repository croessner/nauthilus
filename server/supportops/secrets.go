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
	"slices"
	"strings"
	"unicode"
)

// redactedValue replaces an authentication secret in a support answer.
const redactedValue = "<redacted>"

// secretWords end the name of a field or assignment that holds an authentication secret. The last word of the name
// decides (trailing digits and a plural s ignored), so current_password_retries or tokens_issued stay complete while
// ldap_bind_password, session_tokens, or password2 do not.
var secretWords = []string{"password", "passwd", "passphrase", "pwd", "pass", "pw", "bindpw", "passcode", "passwort",
	"kennwort", "secret", "token", nameAuthorization, nameCookie, "assertion", "jwt", "otp", "totp", "apikey", "credential"}

// Last words of header names whose values are secrets.
const (
	nameCookie        = "cookie"
	nameAuthorization = "authorization"
)

// secretPairs are two-word name endings that hold a secret, such as api_key, password_hash, or code_verifier.
var secretPairs = []string{"api key", "private key", "secret key", "signing key", "access key", "client key",
	"recovery code", "totp code", "otp code", "password hash", "code verifier"}

// nameWordSeparators split a field name into words besides case changes.
const nameWordSeparators = "_-. /:[]"

// unquotedValueEnd ends an unquoted assignment value: whitespace, the pair separators of query strings and logfmt
// lists, a quote, and a backslash, which end a value inside a stored JSON string or start an escaped newline. structValueEnd adds the
// closing brackets of a struct dump ("{Name:value}"), where ":" separates.
const (
	unquotedValueEnd = " \t\r\n,;&\\\""
	structValueEnd   = unquotedValueEnd + "}])"
)

// textSecretPatterns are the secret forms inside free text that carry no name: signed tokens, URL passwords, and the
// credential of an Authorization header. The first group of each pattern is the secret.
var textSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)`),
	regexp.MustCompile(`://[^/\s:@]*:([^@\s/]+)@`),
	regexp.MustCompile(`[?&](?:code|access_token|id_token|refresh_token|client_secret|token|password)=([^&\s#"']+)`),
	regexp.MustCompile(`(?i)\b(?:proxy-)?authorization\s*[:=]\s*(?:bearer|basic|negotiate|digest|ntlm)\s+([^\s"',;]+)`),
}

// schemeCredential matches an authorization scheme with a following word, such as "Basic YTpi" or "Bearer abc...".
var schemeCredential = regexp.MustCompile(`(?i)\b(bearer|basic|negotiate|digest)(\s+)([A-Za-z0-9._~+/-]+=*)`)

// assignment matches a name and its separator in the unambiguous assignment forms: a quoted name with ":" (JSON, also
// escaped inside a string), an unquoted name directly followed by "=" or by ":" without a space (logfmt, query
// strings, command-line flags, struct dumps), and an HTTP header ("X-API-Key: ..."). Any other "name: reason" with a
// space is how errors are wrapped and never an assignment.
var assignment = regexp.MustCompile(`(\\*["'])([^"'\\\r\n]{1,128})(\\*["'])\s*:\s*|([A-Za-z][A-Za-z0-9_.\[\]-]*)(?:\s*=\s*|::?)`)

// secretFlag matches a command-line flag and its separate value, such as "--password hunter2".
var secretFlag = regexp.MustCompile(`(^|\s)(--?[A-Za-z][A-Za-z0-9_.-]*)(\s+)('[^']*'|\\*"(?:[^"\\]|\\[^"])*\\*"|[^\s"',;\\-][^\s"',;\\]*)`)

// secretFlagItem matches a secret-named flag and its value as neighbouring items of a JSON array.
var secretFlagItem = regexp.MustCompile(`"(--?[A-Za-z][A-Za-z0-9_.-]*)"(\s*,\s*)("(?:[^"\\]|\\.)*")`)

// isSecretField reports whether a field or assignment name names an authentication secret.
func isSecretField(name string) bool {
	words := nameWords(name)
	if len(words) == 0 {
		return false
	}

	if last := words[len(words)-1]; slices.Contains(secretWords, last) || slices.Contains(secretWords, strings.TrimSuffix(last, "s")) {
		return true
	}

	return len(words) > 1 && slices.Contains(secretPairs, words[len(words)-2]+" "+words[len(words)-1])
}

// parenthetical matches an annotation in parentheses inside a name, such as "client secret (new)".
var parenthetical = regexp.MustCompile(`\s*\([^)]*\)`)

// nameWords splits a name into lower-case words at separators and at lower-to-upper case changes, without digits
// around a word and without annotations in parentheses.
func nameWords(name string) []string {
	name = parenthetical.ReplaceAllString(name, "")

	var (
		words   []string
		current strings.Builder
		lower   bool
	)

	flush := func() {
		if word := strings.TrimFunc(strings.ToLower(current.String()), unicode.IsDigit); word != "" {
			words = append(words, word)
		}

		current.Reset()
	}

	for _, char := range name {
		switch {
		case strings.ContainsRune(nameWordSeparators, char):
			flush()

			lower = false

			continue
		case unicode.IsUpper(char) && lower:
			flush()
		}

		current.WriteRune(char)
		lower = unicode.IsLower(char)
	}

	flush()

	return words
}

// looksLikeCredential reports whether a word after an authorization scheme is a credential rather than a word: base64
// with both letter cases (a Basic credential such as YTpi), a word of at least eight characters mixing letters and
// digits without a dot (so SHA256 or TLSv1.3 stay), or any word of at least 32 characters.
func looksLikeCredential(word string) bool {
	switch {
	case len(word) >= 32:
		return true
	case len(word)%4 == 0 && strings.ContainsFunc(word, unicode.IsUpper) && strings.ContainsFunc(word, unicode.IsLower) &&
		!strings.ContainsAny(word, "._~-"):
		return true
	default:
		return len(word) >= 8 && strings.ContainsFunc(word, unicode.IsDigit) && strings.ContainsFunc(word, unicode.IsLetter) &&
			!strings.Contains(word, ".")
	}
}

// singleValue reports whether a value after "name: " is one token up to the line, quote, or pair end, as an attribute
// value is, while "userPassword: attribute missing" is prose.
func singleValue(value string) bool {
	line := strings.TrimLeft(value, " \t")
	if end := strings.IndexAny(line, "\r\n\\\",;}]"); end >= 0 {
		line = line[:end]
	}

	return len(strings.Fields(line)) == 1
}

// isIdentifierName reports whether a name is written as an identifier rather than a word of prose: it has an inner
// capital letter or an underscore (userPassword, client_secret), so "userPassword: value" is an attribute while
// "invalid password: reason" is a wrapped error.
func isIdentifierName(name string) bool {
	return strings.Contains(name, "_") || len(name) > 1 && strings.ContainsFunc(name[1:], unicode.IsUpper)
}

// holdsCredential reports whether an Authorization header value starts with a scheme or a credential-looking word,
// so "Authorization: header missing" stays.
func holdsCredential(value string) bool {
	trimmed := strings.TrimLeft(value, " \t")

	if headerScheme.MatchString(trimmed) {
		return true
	}

	first := strings.Fields(trimmed)

	return len(first) > 0 && looksLikeCredential(first[0])
}

// holdsCookiePairs reports whether a header value starts with a name=value cookie pair, as a Cookie or Set-Cookie
// header does, while a wrapped error such as "cookie: invalid or tampered cookie" does not.
func holdsCookiePairs(value string) bool {
	first := strings.Fields(value)
	if len(first) == 0 {
		return false
	}

	name, _, found := strings.Cut(first[0], "=")

	return found && name != "" && !strings.ContainsAny(name, "\"':")
}

// isHeaderName reports whether a name is written like an HTTP header: words joined by dashes (X-API-Key,
// x-api-key). A single word such as "token:" or "secret:" prefixes a wrapped error and is no header.
func isHeaderName(name string) bool {
	words := strings.Split(name, "-")

	return len(words) > 1 && !slices.Contains(words, "")
}

// valueForm selects how an unquoted assignment value ends.
type valueForm int

const (
	// formPair ends at whitespace or a pair separator (name=value).
	formPair valueForm = iota

	// formJSON is a JSON member value: a string, an object or array as a whole, or a bare scalar.
	formJSON

	// formStruct also ends at a closing bracket (Name:value in a struct dump).
	formStruct

	// formHeader runs to the line end (X-API-Key: value).
	formHeader

	// formCookie runs to the line end or, for a bracketed header dump, to the closing bracket.
	formCookie
)

// assignmentForm returns the value form of one assignment match.
func assignmentForm(text string, match []int) valueForm {
	switch {
	case match[2] >= 0:
		return formJSON
	case text[match[1]-1] != ':':
		return formPair
	case strings.HasSuffix(text[match[0]:match[1]], "::"):
		return formPair
	}

	if words := nameWords(text[match[8]:match[9]]); len(words) > 0 && words[len(words)-1] == nameCookie {
		return formCookie
	}

	if match[1] < len(text) && unicode.IsSpace(rune(text[match[1]])) {
		return formHeader
	}

	return formStruct
}

// headerScheme matches the authorization scheme at the start of a header value, which stays visible.
var headerScheme = regexp.MustCompile(`(?i)^(bearer|basic|negotiate|digest|ntlm)\s+`)

// valueStart returns where the secret of a value starts: after the spaces and the scheme of a header value.
func valueStart(text string, start int, form valueForm) int {
	for start < len(text) && (text[start] == ' ' || text[start] == '\t') {
		start++
	}

	if form != formHeader && form != formCookie {
		return start
	}

	if scheme := headerScheme.FindString(text[start:]); scheme != "" {
		start += len(scheme)
	}

	return start
}

// escapedQuotedEnd returns the length of a value quoted with escaped quotes (\"value\" inside a stored JSON string,
// or more backslashes for deeper escaping) at the start of text; an unclosed value runs to the end.
func escapedQuotedEnd(text string) (int, bool) {
	if !strings.HasPrefix(text, `\`) {
		return 0, false
	}

	quote := text[:strings.IndexFunc(text, func(char rune) bool { return char != '\\' })+1]
	if !strings.HasSuffix(quote, `"`) {
		return 0, false
	}

	if end := strings.Index(text[len(quote):], quote); end >= 0 {
		return len(quote) + end + len(quote), true
	}

	return len(text), true
}

// quotedEnd returns the index after the closing quote of a quoted value with backslash escapes, or the text length.
func quotedEnd(text string, quote byte) int {
	for index := 1; index < len(text); index++ {
		switch text[index] {
		case '\\':
			index++
		case quote:
			return index + 1
		}
	}

	return len(text)
}

// bracketEnd returns the index after the bracket that closes the object or array at the start of text, skipping
// quoted strings, or the text length.
func bracketEnd(text string) int {
	depth := 0

	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '"':
			index += quotedEnd(text[index:], '"') - 1
		case '{', '[':
			depth++
		case '}', ']':
			if depth--; depth == 0 {
				return index + 1
			}
		}
	}

	return len(text)
}

// isSecretFlag reports whether a value is a secret-named command-line flag such as "--password".
func isSecretFlag(value any) bool {
	text, ok := value.(string)

	return ok && strings.HasPrefix(text, "-") && len(strings.TrimLeft(text, "-")) > 0 && !strings.Contains(text, " ") &&
		!strings.Contains(text, "=") && isSecretField(strings.TrimLeft(text, "-"))
}
