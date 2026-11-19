// Copyright (C) 2026 Christian Roessner
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

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/bruteforce"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib/cacheflush"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	bf "github.com/croessner/nauthilus/v4/server/model/bruteforce"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// countingCacheFlushRunner records every cache-flush callback invocation.
type countingCacheFlushRunner struct {
	calls int
}

// Run counts one callback invocation and returns no result.
func (r *countingCacheFlushRunner) Run(context.Context, string, string) (*cacheflush.Result, error) {
	r.calls++

	return nil, nil
}

// blockingAccountMappingReader waits until its context ends and proves the caller applied a deadline.
type blockingAccountMappingReader struct {
	sawDeadline bool
}

// ReadMany blocks until ctx is done and reports the context error for every name.
func (r *blockingAccountMappingReader) ReadMany(ctx context.Context, usernames []string) []backend.AccountMappingLookup {
	_, r.sawDeadline = ctx.Deadline()

	<-ctx.Done()

	lookups := make([]backend.AccountMappingLookup, len(usernames))
	for index, username := range usernames {
		lookups[index] = backend.AccountMappingLookup{Username: username, Err: ctx.Err()}
	}

	return lookups
}

// accountResolutionPayload decodes the account section including the resolution metadata.
type accountResolutionPayload struct {
	Accounts          map[string][]string       `json:"accounts"`
	Error             *string                   `json:"error"`
	Page              *bruteForceListPageResult `json:"page"`
	AccountResolution string                    `json:"account_resolution"`
	Resolutions       []bf.AccountResolution    `json:"resolutions"`
}

// listSideEffectSpies holds every collaborator a listing must never touch.
type listSideEffectSpies struct {
	flushRunner *countingCacheFlushRunner
	tokens      *recordingTokenFlusher
	authCache   *recordingAuthCacheInvalidator
}

// withListSpies installs side-effect spies on the fixture dependencies.
func (f *accountHistoryFixture) withListSpies() *listSideEffectSpies {
	spies := &listSideEffectSpies{
		flushRunner: &countingCacheFlushRunner{},
		tokens:      &recordingTokenFlusher{},
		authCache:   &recordingAuthCacheInvalidator{},
	}

	f.deps.CacheFlushRunner = spies.flushRunner
	f.deps.TokenFlusher = spies.tokens
	f.deps.AuthCacheInvalidator = spies.authCache

	return spies
}

// assertUntouched fails when any flush, token, or local-cache collaborator was used.
func (s *listSideEffectSpies) assertUntouched(t *testing.T) {
	t.Helper()

	if s.flushRunner.calls != 0 || len(s.tokens.users) != 0 || s.authCache.calls != 0 {
		t.Fatalf("listing touched side-effect collaborators: flush=%d tokens=%v auth-cache=%v",
			s.flushRunner.calls, s.tokens.users, s.authCache.calls)
	}
}

// markAffected stores synthetic affected-account state with an optional IP history.
func (f *accountHistoryFixture) markAffected(t *testing.T, account string, ips ...string) {
	t.Helper()

	if _, err := f.server.SAdd(rediscli.GetAffectedAccountsKey(f.prefix), account); err != nil {
		t.Fatalf("seed affected account: %v", err)
	}

	if len(ips) > 0 {
		if _, err := f.server.SAdd(bruteforce.GetPWHistIPsRedisKey(account, f.deps.Cfg), ips...); err != nil {
			t.Fatalf("seed IP history: %v", err)
		}
	}
}

// postList runs the list handler with a JSON body, optional query, and optional bearer claims.
func (f *accountHistoryFixture) postList(t *testing.T, body string, query string, claims jwt.MapClaims) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, engine := gin.CreateTestContext(recorder)
	engine.ContextWithFallback = true
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/bruteforce/list"+query, bytes.NewBufferString(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	if claims != nil {
		oidcbearer.BindClaims(ctx, claims)
	}

	handleBruteForceList(ctx, f.deps)

	return recorder
}

// decodeAccountResolution extracts the account section of a list response.
func decodeAccountResolution(t *testing.T, recorder *httptest.ResponseRecorder) accountResolutionPayload {
	t.Helper()

	var envelope struct {
		Result []json.RawMessage `json:"result"`
	}

	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil || len(envelope.Result) != 2 {
		t.Fatalf("decode envelope (%v): %s", err, recorder.Body.String())
	}

	var payload accountResolutionPayload
	if err := json.Unmarshal(envelope.Result[1], &payload); err != nil {
		t.Fatalf("decode account section: %v", err)
	}

	return payload
}

// mappedListBody builds a mapping-resolved account filter body.
func mappedListBody(names ...string) string {
	encoded, _ := json.Marshal(names)

	return `{"accounts":` + string(encoded) + `,"account_resolution":"account_mapping"}`
}

// resolutionFor returns the resolution entry of one input.
func resolutionFor(t *testing.T, payload accountResolutionPayload, input string) bf.AccountResolution {
	t.Helper()

	for _, resolution := range payload.Resolutions {
		if resolution.Input == input {
			return resolution
		}
	}

	t.Fatalf("no resolution for %q in %+v", input, payload.Resolutions)

	return bf.AccountResolution{}
}

// assertResolution compares status, checked, and matched names of one resolution.
func assertResolution(t *testing.T, resolution bf.AccountResolution, status string, checked []string, matched []string, literal bool) {
	t.Helper()

	if resolution.Status != status || !slices.Equal(resolution.Checked, checked) || !slices.Equal(resolution.Matched, matched) ||
		resolution.LiteralMatch != literal || resolution.Source != bf.AccountResolutionAccountMapping {
		t.Fatalf("resolution %q = %+v, want status=%s checked=%v matched=%v literal=%v",
			resolution.Input, resolution, status, checked, matched, literal)
	}
}

// seedIdentityScenario stores synthetic identities covering every resolution outcome.
func (f *accountHistoryFixture) seedIdentityScenario(t *testing.T) {
	t.Helper()

	f.mapLogin(t, "alice@example.test", "imap", "", "alice")
	f.mapLogin(t, "alice@example.test", "smtp", "", "alice")
	f.mapLogin(t, "alice", "imap", "", "alice")
	f.mapLogin(t, "shared@example.test", "imap", "", "alice")
	f.mapLogin(t, "shared@example.test", "oidc", "client-a", "bob")
	f.markAffected(t, "alice", "2001:db8::1")
	f.markAffected(t, "bob")
	f.markAffected(t, "removed-user", "2001:db8::2")
}

func TestBruteForceListResolvesIdentitiesThroughAccountMappings(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.seedIdentityScenario(t)

	recorder := fixture.postList(t, mappedListBody(
		"alice@example.test", "alice", "alice@example.test", "", "shared@example.test", "removed-user", "nobody@example.test",
	), "", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	payload := decodeAccountResolution(t, recorder)

	if payload.AccountResolution != bf.AccountResolutionAccountMapping || len(payload.Resolutions) != 5 || payload.Error != nil {
		t.Fatalf("payload = %+v", payload)
	}

	assertResolution(t, resolutionFor(t, payload, "alice@example.test"), bf.AccountResolutionStatusMapped,
		[]string{"alice@example.test", "alice"}, []string{"alice"}, false)
	assertResolution(t, resolutionFor(t, payload, "alice"), bf.AccountResolutionStatusMapped,
		[]string{"alice"}, []string{"alice"}, true)
	assertResolution(t, resolutionFor(t, payload, "shared@example.test"), bf.AccountResolutionStatusAmbiguous,
		[]string{"shared@example.test", "alice", "bob"}, []string{"alice", "bob"}, false)
	assertResolution(t, resolutionFor(t, payload, "removed-user"), bf.AccountResolutionStatusUnmapped,
		[]string{"removed-user"}, []string{"removed-user"}, true)
	assertResolution(t, resolutionFor(t, payload, "nobody@example.test"), bf.AccountResolutionStatusUnmapped,
		[]string{"nobody@example.test"}, []string{}, false)

	if len(payload.Accounts) != 3 || !slices.Equal(payload.Accounts["alice"], []string{"2001:db8::1"}) ||
		!slices.Equal(payload.Accounts["removed-user"], []string{"2001:db8::2"}) || payload.Accounts["bob"] == nil {
		t.Fatalf("accounts = %v", payload.Accounts)
	}
}

func TestBruteForceListLiteralModeKeepsContract(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.seedIdentityScenario(t)

	for _, body := range []string{
		`{"accounts":["alice@example.test","removed-user"]}`,
		`{"accounts":["alice@example.test","removed-user"],"account_resolution":"none"}`,
	} {
		recorder := fixture.postList(t, body, "", nil)
		payload := decodeAccountResolution(t, recorder)

		if recorder.Code != http.StatusOK || payload.AccountResolution != "" || payload.Resolutions != nil {
			t.Fatalf("%s: status=%d payload=%+v", body, recorder.Code, payload)
		}

		if len(payload.Accounts) != 1 || payload.Accounts["removed-user"] == nil {
			t.Fatalf("%s: literal accounts = %v", body, payload.Accounts)
		}

		if strings.Contains(recorder.Body.String(), `"resolutions"`) || strings.Contains(recorder.Body.String(), `"account_resolution"`) {
			t.Fatalf("%s: literal mode leaked resolution fields: %s", body, recorder.Body.String())
		}
	}
}

func TestBruteForceListResolutionIsReadOnly(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.seedIdentityScenario(t)
	spies := fixture.withListSpies()
	before := fixture.server.Dump()

	fixture.recorder.Reset()

	recorder := fixture.postList(t, mappedListBody("alice@example.test", "shared@example.test", "nobody"), "?limit=10", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}

	if after := fixture.server.Dump(); after != before {
		t.Fatalf("listing changed Redis state:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	readOnly := []string{"hscan", "sismember", "smembers", "zrange", "zrangebyscore", "get", "mget", "exists", "ttl", "pttl"}

	for _, trip := range fixture.recorder.RoundTrips() {
		for _, command := range trip {
			if !slices.Contains(readOnly, command) {
				t.Fatalf("listing issued non-read command %q in %v", command, fixture.recorder.RoundTrips())
			}
		}
	}

	spies.assertUntouched(t)
}

func TestBruteForceListResolutionCostFollowsRequestedNames(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.seedIdentityScenario(t)

	for index := range 5000 {
		fixture.mapLogin(t, fmt.Sprintf("bulk-%d@example.test", index), "imap", "", fmt.Sprintf("bulk-%d", index))
	}

	fixture.recorder.Reset()

	recorder := fixture.postList(t, mappedListBody("alice@example.test", "shared@example.test", "nobody"), "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}

	// The account section needs one pipelined HSCAN round for the three names, one SISMEMBER pipeline, and
	// one bounded IP-history pipeline, regardless of the 5000 unrelated mappings. The independent IP section
	// keeps its own ban-index read.
	accountTrips := make([][]string, 0, 3)

	for _, trip := range fixture.recorder.RoundTrips() {
		if trip[0] != "zrange" {
			accountTrips = append(accountTrips, trip)
		}
	}

	if len(accountTrips) != 3 || !slices.Equal(accountTrips[0], []string{"hscan", "hscan", "hscan"}) ||
		accountTrips[1][0] != "sismember" || accountTrips[2][0] != "smembers" {
		t.Fatalf("account round trips = %v", accountTrips)
	}
}

func TestBruteForceListResolutionPagesMatchedUnion(t *testing.T) {
	fixture := newAccountHistoryFixture(t)

	for index := range 3 {
		fixture.mapLogin(t, fmt.Sprintf("user%d@example.test", index), "imap", "", fmt.Sprintf("user%d", index))
		fixture.markAffected(t, fmt.Sprintf("user%d", index))
	}

	body := mappedListBody("user0@example.test", "user1@example.test", "user2@example.test")
	first := decodeAccountResolution(t, fixture.postList(t, body, "?limit=2", nil))
	second := decodeAccountResolution(t, fixture.postList(t, body, "?limit=2&offset=2", nil))

	if len(first.Accounts) != 2 || first.Accounts["user0"] == nil || first.Accounts["user1"] == nil || !first.Page.HasMore {
		t.Fatalf("first page = %+v", first)
	}

	if len(second.Accounts) != 1 || second.Accounts["user2"] == nil || second.Page.HasMore {
		t.Fatalf("second page = %+v", second)
	}

	if len(first.Resolutions) != 3 || len(second.Resolutions) != 3 {
		t.Fatalf("resolutions must be page independent: %d / %d", len(first.Resolutions), len(second.Resolutions))
	}
}

func TestBruteForceListResolutionReportsUndecidedNames(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*testing.T, *accountHistoryFixture) context.Context
	}{
		{
			name: "backend failure",
			prepare: func(_ *testing.T, f *accountHistoryFixture) context.Context {
				f.server.SetError("synthetic outage")

				return context.Background()
			},
		},
		{
			name: "canceled request",
			prepare: func(*testing.T, *accountHistoryFixture) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				return ctx
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAccountHistoryFixture(t)
			fixture.seedIdentityScenario(t)

			recorder := fixture.postListWithContext(tc.prepare(t, fixture), t, mappedListBody("alice@example.test"))
			assertUndecidedListing(t, recorder, "alice@example.test")
		})
	}
}

func TestBruteForceListResolutionAppliesReadDeadline(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.seedIdentityScenario(t)
	fixture.deps.Cfg.(*config.FileSettings).Server.Timeouts.RedisRead = 20 * time.Millisecond

	reader := &blockingAccountMappingReader{}
	fixture.deps.AccountMappings = reader

	recorder := fixture.postList(t, mappedListBody("alice@example.test"), "", nil)

	if !reader.sawDeadline {
		t.Fatal("resolver ran without a deadline")
	}

	assertUndecidedListing(t, recorder, "alice@example.test")
}

// postListWithContext runs a mapping-resolved list request bound to ctx.
func (f *accountHistoryFixture) postListWithContext(ctx context.Context, t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ginCtx, engine := gin.CreateTestContext(recorder)
	engine.ContextWithFallback = true
	ginCtx.Request = httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/bruteforce/list", bytes.NewBufferString(body))
	ginCtx.Request.Header.Set("Content-Type", "application/json")

	handleBruteForceList(ginCtx, f.deps)

	return recorder
}

// assertUndecidedListing requires an explicit error instead of a silent "not blocked".
func assertUndecidedListing(t *testing.T, recorder *httptest.ResponseRecorder, input string) {
	t.Helper()

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", recorder.Code, recorder.Body.String())
	}

	payload := decodeAccountResolution(t, recorder)
	resolution := resolutionFor(t, payload, input)

	if payload.Error == nil || resolution.Status != bf.AccountResolutionStatusError || resolution.Error == nil {
		t.Fatalf("undecided name not reported: %+v", payload)
	}
}

func TestBruteForceListResolutionRejectsInvalidRequests(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	tooMany := make([]string, bruteForceAccountResolutionMaxNames+1)

	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("user%d", index)
	}

	for _, body := range []string{
		`{"accounts":["alice"],"account_resolution":"ldap"}`,
		`{"account_resolution":"account_mapping"}`,
		`{"ip_addresses":["2001:db8::1"],"account_resolution":"account_mapping"}`,
		mappedListBody(tooMany...),
	} {
		fixture.recorder.Reset()

		recorder := fixture.postList(t, body, "", nil)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), bruteForceAccountResolutionField) {
			t.Fatalf("%.80s: status=%d body=%s", body, recorder.Code, recorder.Body.String())
		}

		if fixture.recorder.Count() != 0 {
			t.Fatalf("%.80s: rejected request still read Redis: %v", body, fixture.recorder.RoundTrips())
		}
	}
}

func TestBruteForceListResolutionRequiresManagementScope(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.seedIdentityScenario(t)

	denied := fixture.postList(t, mappedListBody("alice@example.test"), "", jwt.MapClaims{"scope": definitions.ScopeAuthenticate})
	if denied.Code != http.StatusForbidden || strings.Contains(denied.Body.String(), "alice") {
		t.Fatalf("denied status=%d body=%s", denied.Code, denied.Body.String())
	}

	allowed := fixture.postList(t, mappedListBody("alice@example.test"), "", jwt.MapClaims{"scope": definitions.ScopeSecurity})
	if allowed.Code != http.StatusOK {
		t.Fatalf("security scope status=%d", allowed.Code)
	}
}

func TestBruteForceListResolutionWithoutRedisFailsClosed(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.deps.Redis = nil

	blocked, err := listBlockedAccounts(context.Background(), fixture.deps,
		&bf.FilterCmd{Accounts: []string{"alice"}, AccountResolution: bf.AccountResolutionAccountMapping},
		bruteForceListPageQuery{}, "guid")

	if err == nil || blocked.Error == nil {
		t.Fatalf("missing resolver dependency must fail: err=%v blocked=%+v", err, blocked)
	}
}
