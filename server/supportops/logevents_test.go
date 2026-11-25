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
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// fakeEventSource is a Loki-named source that answers its pages in call order and records its queries.
type fakeEventSource struct {
	fakeSource

	pages []LogEventsSourceResult
	asked []LogEventsQuery
}

// LogEvents records the query and answers the next fixed page.
func (f *fakeEventSource) LogEvents(_ context.Context, query LogEventsQuery) LogEventsSourceResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.asked = append(f.asked, query)
	page := f.pages[min(len(f.asked), len(f.pages))-1]
	page.LimitApplied = query.Limit
	page.Report = SourceReport{Status: SourceStatusOK, Coverage: Coverage{Instances: []string{}}}

	return page
}

// newEventSource returns a Loki source that answers one page with the given lines.
func newEventSource(lines ...LogLine) *fakeEventSource {
	return &fakeEventSource{fakeSource: fakeSource{name: SourceLoki, kind: SourceKindHistorical},
		pages: []LogEventsSourceResult{{Lines: lines}}}
}

// eventsRequest asks for the last 30 minutes.
func eventsRequest() LogEventsRequest {
	return LogEventsRequest{SchemaVersion: SchemaVersion, Window: &Window{From: testNow.Add(-30 * time.Minute), Until: testNow}}
}

// TestLogEventsReturnCompleteFields pins that a stored line leaves complete in both slog formats: users, addresses,
// error texts, and nested fields stay, and only authentication secrets are replaced and named.
func TestLogEventsReturnCompleteFields(t *testing.T) {
	at := testNow.Add(-time.Minute)
	jsonLine := `{"time":"t","level":"ERROR","msg":"LDAP search error","username":"alice","client_ip":"203.0.113.9",` +
		`"error":"LDAP Result Code 32 \"No Such Object\": uid=alice,ou=people,dc=example,dc=org","password":"hunter2",` +
		`"request":{"authorization":"Basic YWxpY2U6aHVudGVyMg==","path":"/login"},"attempts":3}`
	textLine := `time=t level=WARN msg="RBL check failed" guid=abc error="lookup 9.113.0.203.zen.spamhaus.org on 10.96.0.10:53: i/o timeout" detail="session token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"`

	source := newEventSource(
		LogLine{At: at, Instance: "mx-1", Labels: map[string]string{"pod": "mx-1"}, Line: jsonLine},
		LogLine{At: at.Add(-time.Second), Instance: "mx-2", Labels: map[string]string{"pod": "mx-2"}, Line: textLine},
		LogLine{At: at.Add(-2 * time.Second), Instance: "mx-2", Line: "panic: something odd"},
	)

	result, err := newTestService(t, &auditLog{}, source).LogEvents(context.Background(), operator(), eventsRequest())
	if err != nil || len(result.Events) != 3 || result.Page.NextCursor != nil {
		t.Fatalf("result = %+v, %v", result, err)
	}

	assertJSONEvent(t, result.Events[0], at)
	assertTextEvent(t, result.Events[1])

	if raw := result.Events[2]; raw.Format != LogFormatRaw || raw.Line != "panic: something odd" || len(raw.Fields) != 0 {
		t.Fatalf("raw event = %+v", raw)
	}

	if !slices.Contains(result.Notes, NoteLogSecretsRedacted) {
		t.Fatalf("notes = %v", result.Notes)
	}
}

// assertJSONEvent checks the JSON line: identities, addresses, the error text with its DN, numbers, and nested
// fields stay, the password and the nested authorization are replaced and named.
func assertJSONEvent(t *testing.T, event LogEvent, at time.Time) {
	t.Helper()

	if event.Format != LogFormatJSON || event.Level != LogLevelError || event.Message != "LDAP search error" || !event.At.Equal(at) ||
		!slices.Equal(event.RedactedFields, []string{"password", "request.authorization"}) {
		t.Fatalf("json event = %+v", event)
	}

	for name, want := range map[string]any{"username": "alice", "client_ip": "203.0.113.9", "password": redactedValue,
		"attempts": json.Number("3")} {
		if event.Fields[name] != want {
			t.Errorf("field %s = %v, want %v", name, event.Fields[name], want)
		}
	}

	request, _ := event.Fields["request"].(map[string]any)
	if text, _ := event.Fields["error"].(string); !strings.Contains(text, "uid=alice,ou=people") || request["path"] != "/login" {
		t.Fatalf("json event fields = %v", event.Fields)
	}
}

// assertTextEvent checks the slog text line: quoted values unquoted, the resolver error complete, a token inside free
// text replaced, and the stream labels kept.
func assertTextEvent(t *testing.T, event LogEvent) {
	t.Helper()

	if event.Format != LogFormatLogfmt || event.Level != LogLevelWarn || !event.SecretsRedacted || event.Labels["pod"] != "mx-2" {
		t.Fatalf("text event = %+v", event)
	}

	for name, want := range map[string]any{"guid": "abc", "detail": "session token=<redacted>",
		"error": "lookup 9.113.0.203.zen.spamhaus.org on 10.96.0.10:53: i/o timeout"} {
		if event.Fields[name] != want {
			t.Errorf("field %s = %v, want %v", name, event.Fields[name], want)
		}
	}
}

// TestLogEventsCursorContinuesTheSourcePosition pins that next_cursor carries the source position and the window, so
// a follow-up that repeats the request without a window (the default window has moved on) continues the same query,
// and that the filters reach the source.
func TestLogEventsCursorContinuesTheSourcePosition(t *testing.T) {
	at := testNow.Add(-time.Minute)
	source := newEventSource()
	source.pages = []LogEventsSourceResult{
		{Lines: []LogLine{{At: at, Instance: "mx-1", Line: `{"level":"WARN","msg":"m"}`}}, More: true,
			Next: &LogPosition{Before: at, Skip: 2}},
		{Lines: []LogLine{{At: at.Add(-time.Second), Instance: "mx-1", Line: `{"level":"WARN","msg":"m"}`}}},
	}

	message := "m"
	request := LogEventsRequest{SchemaVersion: SchemaVersion, Instance: "mx-1", Message: &message, Levels: []string{LogLevelWarn}}

	first, err := newTestService(t, &auditLog{}, source).LogEvents(context.Background(), operator(), request)
	if err != nil || first.Page.NextCursor == nil || !slices.Contains(first.Notes, NoteLogMorePages) {
		t.Fatalf("first page = %+v, %v", first, err)
	}

	later, err := NewService(Options{Sources: []Source{source}, Now: func() time.Time { return testNow.Add(2 * time.Second) }})
	if err != nil {
		t.Fatal(err)
	}

	request.Page = &LogPage{Cursor: *first.Page.NextCursor}

	second, err := later.LogEvents(context.Background(), operator(), request)
	if err != nil || second.Page.NextCursor != nil || second.Scope.Window != first.Scope.Window {
		t.Fatalf("second page = %+v, %v", second, err)
	}

	assertContinuedQuery(t, source.asked[1], at, first.Scope.Window)
}

// assertContinuedQuery checks that a continued query keeps the filters and window and carries the source position.
func assertContinuedQuery(t *testing.T, asked LogEventsQuery, at time.Time, window Window) {
	t.Helper()

	if asked.Instance != "mx-1" || asked.Message == nil || *asked.Message != "m" || !slices.Equal(asked.Levels, []string{LogLevelWarn}) ||
		!asked.Position.Before.Equal(at) || asked.Position.Skip != 2 || asked.Window != window {
		t.Fatalf("second query = %+v", asked)
	}
}

// TestLogEventsValidationAuthorizationAndAudit pins the operations scope, the filter bounds, cursor binding, and one
// audit entry per call.
func TestLogEventsValidationAuthorizationAndAudit(t *testing.T) {
	audit := &auditLog{}
	service := newTestService(t, audit, newEventSource())
	historyOnly := NewCaller(supportaccess.VerifiedCredential{Method: supportaccess.CredentialOIDCBearer, ClientID: "console",
		Scopes: []string{definitions.ScopeHistoryRead}})
	empty := ""
	long := strings.Repeat("a", maxMessageFilterRunes+1)
	foreign := supportaccess.EncodeCursor(pageCursor{Digest: "other", Before: 1})

	for name, tc := range map[string]struct {
		caller  Caller
		request func(*LogEventsRequest)
		code    ErrorCode
	}{
		"missing scope":   {historyOnly, func(*LogEventsRequest) {}, CodeForbidden},
		"empty message":   {operator(), func(r *LogEventsRequest) { r.Message = &empty }, CodeInvalidRequest},
		"long message":    {operator(), func(r *LogEventsRequest) { r.Message = &long }, CodeInvalidRequest},
		"invalid utf8":    {operator(), func(r *LogEventsRequest) { r.Instance = "mx\xff" }, CodeInvalidRequest},
		"page too large":  {operator(), func(r *LogEventsRequest) { r.Page = &LogPage{Limit: MaxLogEventPageLimit + 1} }, CodeInvalidRequest},
		"foreign cursor":  {operator(), func(r *LogEventsRequest) { r.Page = &LogPage{Cursor: foreign} }, CodeInvalidCursor},
		"unknown level":   {operator(), func(r *LogEventsRequest) { r.Levels = []string{"trace"} }, CodeInvalidRequest},
		"window too long": {operator(), func(r *LogEventsRequest) { r.Window.From = testNow.Add(-25 * time.Hour) }, CodeWindowTooLarge},
	} {
		request := eventsRequest()
		tc.request(&request)

		if _, err := service.LogEvents(context.Background(), tc.caller, request); AsError(err).Code != tc.code {
			t.Errorf("%s: err = %v, want %s", name, err, tc.code)
		}
	}

	if len(audit.entries) != 8 || audit.entries[0].Operation != operationLogEvents {
		t.Fatalf("audit = %+v", audit.entries)
	}

	result, err := newTestService(t, &auditLog{}, &fakeSource{name: SourceRuntime, kind: SourceKindLocalCurrent}).LogEvents(context.Background(), operator(), eventsRequest())
	if err != nil || result.Source.Status != SourceStatusNotConfigured || !slices.Contains(result.Notes, NoteNoHistoricalSource) {
		t.Fatalf("not configured = %+v, %v", result, err)
	}
}

// TestRedactSecrets pins the secret forms replaced inside free text and the review findings: JSON (also escaped
// inside a string), struct dumps, prefixed and camel-case names, short credentials, and header forms are replaced,
// while wrapped errors ("token: reason"), scheme words in prose, counters, and identities stay complete.
func TestRedactSecrets(t *testing.T) {
	for input, want := range map[string]string{
		"login alice@example.org from 203.0.113.9 failed":                            "login alice@example.org from 203.0.113.9 failed",
		"Authorization: Bearer abcdefghijklmnopqrstuvwxyz012":                        "Authorization: Bearer <redacted>",
		"Authorization: Basic YTpi":                                                  "Authorization: Basic <redacted>",
		"header Basic YWxpY2U6aHVudGVyMg==":                                          "header Basic <redacted>",
		"Authorization: Negotiate YIIGhgYJKoZIhvcSAQICAQBuggZ1":                      "Authorization: Negotiate <redacted>",
		"retry with Basic YTpi":                                                      "retry with Basic <redacted>",
		"dial https://svc:s3cr3t@idp.example.org/token":                              "dial https://svc:<redacted>@idp.example.org/token",
		"client_secret=abc123 grant=client_credentials":                              "client_secret=<redacted> grant=client_credentials",
		`password="hunter 2" rejected`:                                               `password=<redacted> rejected`,
		"token=abc,user=alice,ip=203.0.113.9":                                        "token=<redacted>,user=alice,ip=203.0.113.9",
		"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln end":                          "jwt <redacted> end",
		`request body {"username":"alice","password":"hunter2"}`:                     `request body {"username":"alice","password":<redacted>}`,
		`request body {"password": "hun\"ter2", "user": "bob"}`:                      `request body {"password": <redacted>, "user": "bob"}`,
		`response body: "{\"username\":\"alice\",\"password\":\"hunter2\"}"`:         `response body: "{\"username\":\"alice\",\"password\":<redacted>}"`,
		"{Username:alice Password:hunter2 ClientIP:203.0.113.9 Protocol:imap}":       "{Username:alice Password:<redacted> ClientIP:203.0.113.9 Protocol:imap}",
		"ldap_bind_password=hunter2 dn=cn=admin":                                     "ldap_bind_password=<redacted> dn=cn=admin",
		"oidc_client_secret=s3cr3tvalue password_hash={SSHA}abc Passwort=geheim":     "oidc_client_secret=<redacted> password_hash=<redacted> Passwort=<redacted>",
		"pwd=hunter2 pass=other session_token=abc password2=x":                       "pwd=<redacted> pass=<redacted> session_token=<redacted> password2=<redacted>",
		"client_assertion=eyJx.eyJ.sig":                                              "client_assertion=<redacted>",
		"X-API-Key=k-123":                                                            "X-API-Key=<redacted>",
		"cookie: invalid or tampered cookie":                                         "cookie: invalid or tampered cookie",
		"failed to sign access token: crypto/rsa: message too long for RSA key size": "failed to sign access token: crypto/rsa: message too long for RSA key size",
		"invalid or expired opaque token: redis: connection pool timeout":            "invalid or expired opaque token: redis: connection pool timeout",
		"Failed to decrypt LDAP TOTP secret: cipher: message authentication failed":  "Failed to decrypt LDAP TOTP secret: cipher: message authentication failed",
		"Device code token: missing persisted claims":                                "Device code token: missing persisted claims",
		`invalid password: LDAP Result Code 49 "Invalid Credentials" for uid=alice`:  `invalid password: LDAP Result Code 49 "Invalid Credentials" for uid=alice`,
		"HTTP basic authentication failed for alice":                                 "HTTP basic authentication failed for alice",
		"digest mismatch for artifact":                                               "digest mismatch for artifact",
		"bearer authorization header missing":                                        "bearer authorization header missing",
		"user basic auth disabled":                                                   "user basic auth disabled",
		"current_password_retries=3 total_passwords_seen=4 tokens_issued=2":          "current_password_retries=3 total_passwords_seen=4 tokens_issued=2",
	} {
		if got, _ := redactSecrets(input); got != want {
			t.Errorf("redactSecrets(%q)\n got %q\nwant %q", input, got, want)
		}
	}
}

// TestSecretFieldNames pins which field names carry a secret: the last word of the name decides, so counters and ids
// named after a secret stay, and every spelling (underscore, dash, camel case, nested) of a secret name is caught.
func TestSecretFieldNames(t *testing.T) {
	for name, want := range map[string]bool{
		"password": true, "ldap_bind_password": true, "userPassword": true, "new-password": true, "pwd": true,
		"pass": true, "client_secret": true, "api-key": true, "X-API-Key": true, "private-key": true, "jwt": true,
		"session_token": true, "refresh_token": true, "Authorization": true, "Proxy-Authorization": true, "cookie": true,
		"Set-Cookie": true, "client_assertion": true, "otp": true, "totp_code": true, "recovery_code": true,
		"password_hash": true, "passwords": true, "tokens": true, "cookies": true, "password2": true, "client_key": true,
		"code_verifier": true, "Passwort": true,
		"current_password_retries": false, "account_passwords_seen": false, "total_passwords_seen": false,
		"tokens_issued": false, "credential_id": false, "recovery_code_count": false, "token_endpoint_auth_method": false,
		"session_id": false, "username": false, "client_ip": false, "error": false, "msg": false, "bypass": false,
	} {
		if got := isSecretField(name); got != want {
			t.Errorf("isSecretField(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestLogEventsKeepRepeatedFields reproduces the final review: a field name repeated in a JSON or logfmt line kept
// only its last value. Every value must stay, in line order, and the line itself is returned with secrets replaced.
func TestLogEventsKeepRepeatedFields(t *testing.T) {
	for _, line := range []string{
		`{"level":"ERROR","msg":"failed","error":"first failure","error":"second failure","password":"hunter2"}`,
		`level=ERROR msg=failed error="first failure" error="second failure" password=hunter2`,
	} {
		event := logEventOf(LogLine{Line: line})
		values, _ := event.Fields["error"].([]any)

		if len(values) != 2 || values[0] != "first failure" || values[1] != "second failure" ||
			!slices.Equal(event.RepeatedFields, []string{"error"}) {
			t.Errorf("%s: fields = %v, repeated = %v", event.Format, event.Fields, event.RepeatedFields)
		}

		if !strings.Contains(event.Line, "first failure") || !strings.Contains(event.Line, "second failure") ||
			strings.Contains(event.Line, "hunter2") {
			t.Errorf("%s: line = %q", event.Format, event.Line)
		}
	}
}

// TestLogEventsRedactSecretLabelsAndCookies reproduces the final review: a secret-named stream label and a Cookie
// header inside a text survived, while wrapped errors stay complete.
func TestLogEventsRedactSecretLabelsAndCookies(t *testing.T) {
	event := logEventOf(LogLine{Line: `{"level":"ERROR","msg":"upstream request headers: Cookie: session=synthetic-live-cookie"}`,
		Labels: map[string]string{"access_token": "synthetic-live-token", "pod": "mx-1"}})
	rendered, _ := json.Marshal(event)

	if strings.Contains(string(rendered), "synthetic-live-") || event.Labels["pod"] != "mx-1" ||
		!slices.Contains(event.RedactedFields, "labels.access_token") {
		t.Fatalf("event = %s", rendered)
	}

	for _, text := range []string{"parse token: illegal base64 data", "cookie: invalid or tampered cookie",
		"Set-Cookie: rejected by browser policy"} {
		if got, _ := redactSecrets(text); got != text {
			t.Errorf("redactSecrets(%q) = %q", text, got)
		}
	}

	for text, want := range map[string]string{
		"upstream request headers: Cookie: session=synthetic-live-cookie; theme=dark": "upstream request headers: Cookie: <redacted>",
		"cookie: nauthilus_session=abc":                                               "cookie: <redacted>",
		"Set-Cookie: sid=abc; HttpOnly":                                               "Set-Cookie: <redacted>",
	} {
		if got, _ := redactSecrets(text); got != want {
			t.Errorf("redactSecrets(%q) = %q, want %q", text, got, want)
		}
	}
}

// TestRedactSecretsReviewForms pins the secret forms of the final review that leaked, and the error texts that must
// stay complete.
func TestRedactSecretsReviewForms(t *testing.T) {
	for input, want := range map[string]string{
		`{"_password":"s1","__secret":"s2","user password":"s3"}`:      `{"_password":<redacted>,"__secret":<redacted>,"user password":<redacted>}`,
		`map[Cookie:[lang=en; session=s4] Accept:[*/*]]`:               `map[Cookie:<redacted> Accept:[*/*]]`,
		"ldap entry userPassword:: czU=":                               "ldap entry userPassword:: <redacted>",
		"ldap entry userPassword: s6":                                  "ldap entry userPassword: <redacted>",
		"run ldapsearch --password s7 -D cn=admin":                     "run ldapsearch --password <redacted> -D cn=admin",
		`{"args":["--password","s8","-v"]}`:                            `{"args":["--password","<redacted>","-v"]}`,
		"x-api-key: s9":                                                "x-api-key: <redacted>",
		"redirect https://app.example.org/cb?code=s10&state=abc":       "redirect https://app.example.org/cb?code=<redacted>&state=abc",
		"auth/token=s11 db:password=s12 1password=s13 password[0]=s14": "auth/token=<redacted> db:password=<redacted> 1password=<redacted> password[0]=<redacted>",
		"Authorization: header missing":                                "Authorization: header missing",
		"config password: value with spaces":                           "config password: value with spaces",
		"Set-Cookie: header too large":                                 "Set-Cookie: header too large",
	} {
		if got, _ := redactSecrets(input); got != want {
			t.Errorf("redactSecrets(%q)\n got %q\nwant %q", input, got, want)
		}
	}

	event := logEventOf(LogLine{Line: `{"level":"ERROR","msg":"x","args":["--password","s8"],"db:password":"s12","password[0]":"s14"}`})
	if rendered, _ := json.Marshal(event); strings.Contains(string(rendered), `s8"`) || strings.Contains(string(rendered), "s12") ||
		strings.Contains(string(rendered), "s14") {
		t.Fatalf("event = %s", rendered)
	}
}

// TestRedactSecretsQuotedAndEscapedForms pins the forms of the last review: quoted flag values, an escaped newline
// between two LDIF attributes in a stored JSON line, doubly escaped JSON, quoted YAML values, and annotated keys, while
// "userPassword: attribute missing" stays.
func TestRedactSecretsQuotedAndEscapedForms(t *testing.T) {
	for input, want := range map[string]string{
		`run --password 'S x' now`:                        `run --password <redacted> now`,
		`run --bind-password "a S" now`:                   `run --bind-password <redacted> now`,
		`"msg":"ldap userPassword:: a\nuserPassword:: S"`: `"msg":"ldap userPassword:: <redacted>\nuserPassword:: <redacted>"`,
		`"dump":"{\\\"password\\\":\\\"S\\\"}"`:           `"dump":"{\\\"password\\\":<redacted>}"`,
		`yaml password: "a S"`:                            `yaml password: <redacted>`,
		`{"client secret (new)":"S"}`:                     `{"client secret (new)":<redacted>}`,
		"userPassword: attribute missing":                 "userPassword: attribute missing",
	} {
		if got, _ := redactSecrets(input); got != want {
			t.Errorf("redactSecrets(%q)\n got %q\nwant %q", input, got, want)
		}
	}
}

// lineRedactionCases are stored lines whose secrets hide behind JSON escapes, repeated names, or nested strings; the
// secret values are "s3cr3t-<n>" and must never appear in any representation.
var lineRedactionCases = []string{
	`{"level":"ERROR","msg":"x","pass\u0077ord":"s3cr3t-1"}`,
	`{"level":"ERROR","msg":"login password=hunter\u0032s3cr3t-2 failed","user":"alice"}`,
	`{"level":"ERROR","msg":"x","error":"first","error":"second","token":"s3cr3t-3","token":"s3cr3t-4"}`,
	`{"level":"ERROR","msg":"x","request":{"headers":{"Authori\u007aation":"Bearer s3cr3t-5"}}}`,
	`{"level":"ERROR","msg":"x","body":"{\"user\":\"bob\",\"pass\\u0077ord\":\"s3cr3t-6\"}"}`,
	`{"level":"ERROR","msg":"x","args":["--pass\u0077ord","s3cr3t-7"],"note":"keep me"}`,
	`{"level":"ERROR","msg":"Cookie: sid\u003ds3cr3t-8; theme=dark"}`,
	`level=ERROR msg="login password=\"s3cr3t-9\" failed" user=alice password=s3cr3t-10 password=s3cr3t-11`,
	`level=ERROR msg=x detail="url https://svc:s3cr3t-12@idp.example.org/x"`,
	`panic: dial failed password=s3cr3t-13`,
}

// TestLogLineRedactionMatchesFields reproduces the review defect: the stored line kept JSON-escaped secrets that the
// structured fields replaced. The line must carry no secret, decode to exactly the redacted fields (repeated names
// included), and keep ordinary diagnostics.
func TestLogLineRedactionMatchesFields(t *testing.T) {
	for _, line := range lineRedactionCases {
		event := logEventOf(LogLine{Line: line})

		rendered, _ := json.Marshal(event)
		if strings.Contains(string(rendered), "s3cr3t-") {
			t.Errorf("%s: secret left in %s", line, rendered)

			continue
		}

		if event.Format == LogFormatRaw {
			continue
		}

		reparsed, repeated, format := parseLogLine(event.Line)
		redacted := false
		cleaned, _ := cleanFields(reparsed, "", &redacted)

		if format != event.Format || !reflect.DeepEqual(cleaned, event.Fields) || len(repeated) != len(event.RepeatedFields) {
			t.Errorf("%s:\n line   %s\n fields %v\n reparsed %v", line, event.Line, event.Fields, cleaned)
		}
	}

	event := logEventOf(LogLine{Line: lineRedactionCases[2]})
	if errors, _ := event.Fields["error"].([]any); len(errors) != 2 || !strings.Contains(event.Line, `"error":"first","error":"second"`) {
		t.Fatalf("repeated fields = %v, line = %s", event.Fields, event.Line)
	}

	if plain := logEventOf(LogLine{Line: `{"level":"WARN","msg":"parse token: illegal base64 data","error":"cookie: invalid or tampered cookie"}`}); plain.Line != `{"level":"WARN","msg":"parse token: illegal base64 data","error":"cookie: invalid or tampered cookie"}` || plain.SecretsRedacted {
		t.Fatalf("ordinary line changed: %s", plain.Line)
	}
}

// assertErrorField checks a message as the error field of a JSON line: the field holds the expected text, and no
// secret of a redacted message is left anywhere in the event, its stored line included.
func assertErrorField(t *testing.T, message string, want string) {
	t.Helper()

	encoded, _ := json.Marshal(message)
	event := logEventOf(LogLine{Line: `{"level":"ERROR","msg":"failed","error":` + string(encoded) + `}`})
	rendered, _ := json.Marshal(event)

	for _, secret := range []string{"123456", "s3cr3t-", `[1,2] for`} {
		if strings.Contains(want, "<redacted>") && strings.Contains(string(rendered), secret) {
			t.Errorf("%q: %q left in %s", message, secret, rendered)
		}
	}

	if event.Fields["error"] != want {
		t.Errorf("%q: field = %q, want %q", message, event.Fields["error"], want)
	}
}

// TestJSONShapedSecretValuesStayTogether reproduces the third review: redactText split an embedded JSON array or
// object from the text before it, so "password=" lost its value and a JSON-shaped password came out complete. The
// whole value must be replaced in the fields and in the stored line, while the surrounding text, repeated fields, and
// non-secret JSON stay complete.
func TestJSONShapedSecretValuesStayTogether(t *testing.T) {
	for message, want := range map[string]string{
		`upstream failed password=[123456]`:                     `upstream failed password=<redacted>`,
		`upstream failed password={"a":"s3cr3t-1"} retry later`: `upstream failed password=<redacted> retry later`,
		`login password=[1,2] for alice`:                        `login password=<redacted> for alice`,
		`config client_secret: {"nested":["s3cr3t-2"]} applied`: `config client_secret: <redacted> applied`,
		`run --password ["s3cr3t-3"] -v`:                        `run --password <redacted> -v`,
		`{Username:alice Password:{"x":"s3cr3t-4"}}`:            `{Username:alice Password:<redacted>}`,
		`body {"user":"bob","password":["s3cr3t-5"]} rejected`:  `body {"user":"bob","password":"<redacted>"} rejected`,
		`ids=[1,2,3] user={"name":"alice"} error=[timeout]`:     `ids=[1,2,3] user={"name":"alice"} error=[timeout]`,
		`parse token: illegal base64 data at [12]`:              `parse token: illegal base64 data at [12]`,
	} {
		if got, _ := redactText(message); got != want {
			t.Errorf("redactText(%q)\n got %q\nwant %q", message, got, want)
		}

		assertErrorField(t, message, want)
	}

	escaped := logEventOf(LogLine{Line: `{"level":"ERROR","msg":"x","error":"pass\u0077ord=[1,2] for alice","note":{"pass\u0077ord":{"k":"s3cr3t-6"}}}`})
	if escaped.Fields["error"] != "password=<redacted> for alice" || strings.Contains(escaped.Line, "[1,2]") ||
		strings.Contains(escaped.Line, "s3cr3t-6") || !strings.Contains(escaped.Line, "for alice") {
		t.Fatalf("escaped = %v, line = %s", escaped.Fields, escaped.Line)
	}

	repeated := logEventOf(LogLine{Line: `{"level":"ERROR","msg":"x","error":"password=[1]","error":"timeout [5s]"}`})
	if errors, _ := repeated.Fields["error"].([]any); len(errors) != 2 || errors[0] != "password=<redacted>" || errors[1] != "timeout [5s]" ||
		!strings.Contains(repeated.Line, `"error":"password=<redacted>","error":"timeout [5s]"`) {
		t.Fatalf("repeated = %v, line = %s", repeated.Fields, repeated.Line)
	}
}

// TestInputMarkersStayData reproduces the fourth review: redactText stood every embedded JSON value in the text as a
// NUL-delimited placeholder and put the values back by searching for the placeholders, so input holding such a
// placeholder got a JSON value in its place: a replaced password came back, or non-secret text changed. Input bytes
// must stay data in the fields and in the stored line of a JSON and a slog text line, and in the overview text.
func TestInputMarkersStayData(t *testing.T) {
	assertTextCases(t, []textCase{
		{"note=\x00json0\x00 password=[123456]", "note=\x00json0\x00 password=<redacted>"},
		{"note=\x00json0\x00 ids=[1,2,3]", "note=\x00json0\x00 ids=[1,2,3]"},
		{"password=[123456] note=\x00json0\x00 ids=[7]", "password=<redacted> note=\x00json0\x00 ids=[7]"},
		{"\x00json1\x00 token={\"a\":\"s3cr3t-7\"} body {\"k\":1} \x00json0\x00", "\x00json1\x00 token=<redacted> body {\"k\":1} \x00json0\x00"},
		{"password=\x00json0\x00 body [1]", "password=<redacted> body [1]"},
		{"user: \x00\x00 [1] {\"password\":\"s3cr3t-8\"} \x00", "user: \x00\x00 [1] {\"password\":\"<redacted>\"} \x00"},
	})
}

// TestEmbeddedJSONSegmentBoundaries pins how the free-text rules meet embedded JSON values: no rule reads into one
// (its inside is rewritten structurally), a match starting inside one cannot hide a secret behind it, and a value
// that runs through one takes it as a whole.
func TestEmbeddedJSONSegmentBoundaries(t *testing.T) {
	assertTextCases(t, []textCase{
		{`["X-API-Key: abc"] password=s3cr3t-9 done`, `["X-API-Key: <redacted>"] password=<redacted> done`},
		{`{"a":"b"} token": x`, `{"a":"b"} token": x`},
		{`[" --x "]--password z"`, `[" --x "]--password z"`},
		{`[" --x "] --password s3cr3t-10"`, `[" --x "] --password <redacted>"`},
		{`token=abc[1,2]def ok`, `token=<redacted> ok`},
		{"Authorization: Bearer abc {\"k\":[1,\n2]}\nnext", "Authorization: Bearer <redacted>\nnext"},
	})
}

// textCase is one free text and its expected redaction.
type textCase struct{ message, want string }

// assertTextCases checks every case in redactText and in both output paths of a log event.
func assertTextCases(t *testing.T, cases []textCase) {
	t.Helper()

	for _, test := range cases {
		if got, _ := redactText(test.message); got != test.want {
			t.Errorf("redactText(%q)\n got %q\nwant %q", test.message, got, test.want)
		}

		assertBothOutputPaths(t, test.message, test.want)
	}
}

// assertBothOutputPaths checks one error message in a JSON and a slog text line: the event field and the value in
// the stored line must equal want, and no secret may remain anywhere in the event.
func assertBothOutputPaths(t *testing.T, message string, want string) {
	t.Helper()

	encoded, _ := json.Marshal(message)

	for _, line := range []string{`{"level":"ERROR","msg":"failed","error":` + string(encoded) + `}`,
		`level=ERROR msg=failed error=` + strconv.Quote(message)} {
		event := logEventOf(LogLine{Line: line})
		rendered, _ := json.Marshal(event)

		if strings.Contains(string(rendered), "123456") || strings.Contains(string(rendered), "s3cr3t-") {
			t.Errorf("%s: secret left in %s", line, rendered)
		}

		if event.Fields["error"] != want {
			t.Errorf("%s: field = %q, want %q", line, event.Fields["error"], want)
		}

		if stored := storedErrorValue(t, event.Line); stored != want {
			t.Errorf("%s: stored line value = %q, want %q", line, stored, want)
		}

		if want == message && event.Line != line {
			t.Errorf("unchanged line rewritten:\n got %s\nwant %s", event.Line, line)
		}
	}
}

// storedErrorValue decodes the error value of a stored JSON or slog text line.
func storedErrorValue(t *testing.T, line string) string {
	t.Helper()

	var stored map[string]any
	if json.Unmarshal([]byte(line), &stored) == nil {
		value, _ := stored["error"].(string)

		return value
	}

	_, quoted, _ := strings.Cut(line, " error=")

	value, err := strconv.Unquote(quoted)
	if err != nil {
		t.Fatalf("stored line %q: %v", line, err)
	}

	return value
}
