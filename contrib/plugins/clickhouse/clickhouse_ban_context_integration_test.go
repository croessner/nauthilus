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

//go:build clickhouse_integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/handler/support"
	"github.com/croessner/nauthilus/v4/server/mcpserver"
	"github.com/croessner/nauthilus/v4/server/mcpserver/mcptest"
	"github.com/croessner/nauthilus/v4/server/supportapi"
	"github.com/croessner/nauthilus/v4/server/supporthistory/clickhousestore"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// banContextSubject is the customer whose request request-05 of the shared-IP fixture hit the /24 ban.
	banContextSubject = "dave@example.test"
	banContextAccount = "dave@example.test"
	banContextClient  = "198.51.100.17"
	adminClientPath   = "../../client/nauthilus-admin.py"
)

// banContextTransports are the HTTP endpoints per scope and the MCP sessions per token of one service.
type banContextTransports struct {
	http map[string]string
	mcp  map[string]*mcp.ClientSession
}

// writeBanContextScenario writes the shared-IP ban so that the subject's request hits it now, the subject's
// brute-force rejected login row of that request, and an earlier successful login that recorded the account.
func writeBanContextScenario(t *testing.T, env historyEnv) {
	t.Helper()

	brute := pluginapi.AuthOutcome{Decision: pluginapi.AuthOutcomeFail, Operation: "authenticate", Stage: "pre_auth",
		OutcomeMarker: "auth.outcome.brute_force_reject", ResponseMarker: "auth.response.fail",
		PolicyRule: "standard_brute_force_deny", FSMState: "auth_fail", StatusMessage: "Invalid login or password",
		Transport: pluginapi.AuthTransportHTTP, HTTPStatus: 403, TransportStatus: 403, Known: true}

	for _, row := range []struct {
		outcome pluginapi.AuthOutcome
		session string
		account string
	}{{loadOutcomeFixture(t)["success"], "dave-earlier", banContextAccount}, {brute, "request-05", ""}} {
		request := boundRequest(t, row.outcome)
		request.Snapshot.Session, request.Snapshot.Username, request.Snapshot.Account = row.session, banContextSubject, row.account
		request.Snapshot.ClientIP, request.Snapshot.Protocol = banContextClient, "imap"

		if _, err := env.harness.enqueuePostAction(t.Context(), request); err != nil {
			t.Fatalf("Enqueue(%s) error = %v", row.session, err)
		}
	}

	flushStreams(t, env.harness)
	waitRows(t, env.db, "SELECT event_id FROM nauthilus.logins", 2)
	observeBruteForceEvents(t, env.harness, bruteForceFixtureAt(t, 5, time.Now().UTC()))
	waitRows(t, env.db, "SELECT event_id FROM nauthilus.bruteforce_attempts", 7)
}

// startBanContextTransports serves one service over the management HTTP adapter per scope and over MCP per token.
func startBanContextTransports(t *testing.T, services supportapi.Services) banContextTransports {
	t.Helper()
	gin.SetMode(gin.TestMode)

	scopes := map[string]string{"read": definitions.ScopeHistoryRead, "detail": definitions.ScopeHistoryDetail,
		"operations": definitions.ScopeOperationsRead}
	transports := banContextTransports{http: map[string]string{}, mcp: map[string]*mcp.ClientSession{}}
	authority := mcptest.NewAuthority(definitions.ScopeHistoryRead, definitions.ScopeHistoryDetail, definitions.ScopeOperationsRead)

	for name, scope := range scopes {
		engine := gin.New()
		group := engine.Group("/api/v1", func(ctx *gin.Context) {
			ctx.Set(definitions.CtxOIDCClaimsKey, jwt.MapClaims{definitions.ClaimClientID: "support-console",
				"sub": "support-console", "scope": scope})
			ctx.Next()
		})
		support.New(&handlerdeps.Deps{SupportHistory: services.History, SupportOperations: services.Operations}).Register(group)

		server := httptest.NewServer(engine)
		t.Cleanup(server.Close)

		transports.http[name] = server.URL
		authority.Tokens[name] = mcptest.ResourceToken(scope)
	}

	endpoint, err := mcpserver.New(mcpserver.Deps{Settings: &config.RuntimeMCPServerSection{Enabled: true,
		HostedResource: mcptest.HostedName, TrustedProxies: []string{"127.0.0.1/32", "::1/128"}}, Tokens: authority,
		Services: services, Version: "test"})
	if err != nil {
		t.Fatalf("mcpserver.New() error = %v", err)
	}

	for name := range scopes {
		transports.mcp[name] = mcptest.Connect(t, endpoint.Handler(), name, "2025-06-18")
	}

	return transports
}

// callBoth runs one attempt search over HTTP and MCP with the same scope, requires byte parity, and returns the
// status and body.
func (b banContextTransports) callBoth(t *testing.T, scope, arguments string) (int, string) {
	t.Helper()

	response, err := http.Post(b.http[scope]+"/api/v1/support/authentication-attempts/search", "application/json", //nolint:noctx // test client
		strings.NewReader(arguments))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()

	var body bytes.Buffer
	if _, err = body.ReadFrom(response.Body); err != nil {
		t.Fatal(err)
	}

	result, err := b.mcp[scope].CallTool(context.Background(), &mcp.CallToolParams{Name: supportapi.OperationAttemptSearch,
		Arguments: json.RawMessage(arguments)})
	if err != nil {
		t.Fatal(err)
	}

	if text := result.Content[0].(*mcp.TextContent).Text; text != body.String() || result.IsError != (response.StatusCode != http.StatusOK) {
		t.Fatalf("parity broken for %s: HTTP %d %s\nMCP isError=%v %s", scope, response.StatusCode, body.String(), result.IsError, text)
	}

	return response.StatusCode, body.String()
}

// pythonSearch runs the standalone admin client against the HTTP endpoint and returns its JSON answer.
func pythonSearch(t *testing.T, url string, from, until time.Time, extra ...string) map[string]any {
	t.Helper()

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}

	args := append([]string{"-I", adminClientPath, "--url", url, "--bearer-token", "synthetic", "--token-cache", "off",
		"--output", "json", "support", "attempts", "search", "--login", banContextSubject, "--from",
		from.Format(time.RFC3339), "--until", until.Format(time.RFC3339), "--limit", "10"}, extra...)
	command := exec.Command(python, args...) //nolint:gosec // fixed test client path and arguments
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "PYTHONDONTWRITEBYTECODE=1"}

	var stdout, stderr bytes.Buffer

	command.Stdout, command.Stderr = &stdout, &stderr

	if err = command.Run(); err != nil && command.ProcessState.ExitCode() != 3 {
		t.Fatalf("admin client error = %v\n%s", err, stderr.String())
	}

	var answer map[string]any
	if err = json.Unmarshal(stdout.Bytes(), &answer); err != nil {
		t.Fatalf("admin client output %q: %v", stdout.String(), err)
	}

	return answer
}

// decodeAnswer decodes one JSON answer into a generic map.
func decodeAnswer(t *testing.T, body string) map[string]any {
	t.Helper()

	var answer map[string]any
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}

	return answer
}

// TestClickHouseBanContextEndToEnd answers the telephone-support question from the stored schema through HTTP, the
// Python client, and MCP: both output variants, the unchanged default, result parity, the tool schema, and identical
// rights and error handling.
func TestClickHouseBanContextEndToEnd(t *testing.T) {
	env := newHistoryEnv(t)
	writeBanContextScenario(t, env)

	now := time.Now().UTC()
	service := historyServiceAt(t, provisionReader(t, env.db, "2", clickhousestore.BudgetQuerySettings), now.Add(10*time.Minute))
	transports := startBanContextTransports(t, supportapi.Services{History: service})
	from, until := now.Add(-time.Hour).Truncate(time.Second), now.Add(time.Hour).Truncate(time.Second)
	base := fmt.Sprintf(`{"schema_version":"1","subject":{"login":%q},"filter":{"from":%q,"until":%q},"page":{"limit":10}`,
		banContextSubject, from.Format(time.RFC3339), until.Format(time.RFC3339))

	_, plain := transports.callBoth(t, "read", base+`}`)
	for _, member := range []string{"response_mode", "attempt_summaries", "ban_contexts", "ban_history"} {
		if _, ok := decodeAnswer(t, plain)[member]; ok {
			t.Fatalf("default answer carries %s, want the unchanged answer", member)
		}
	}

	status, compact := transports.callBoth(t, "read", base+`,"include_ban_context":true,"response_mode":"compact"}`)
	if status != http.StatusOK {
		t.Fatalf("compact status = %d %s", status, compact)
	}

	assertCompactBanContext(t, decodeAnswer(t, compact))

	if python := pythonSearch(t, transports.http["read"], from, until, "--include-ban-context", "--response-mode", "compact"); !jsonEqualValues(python, decodeAnswer(t, compact)) {
		t.Fatalf("python answer differs from HTTP:\n%v\n%v", python, compact)
	}

	_, detailed := transports.callBoth(t, "detail", base+`,"include_ban_context":true,"response_mode":"detailed"}`)
	assertDetailedBanContext(t, decodeAnswer(t, detailed))

	if status, body := transports.callBoth(t, "read", base+`,"response_mode":"verbose"}`); status != http.StatusBadRequest ||
		!strings.Contains(body, `"INVALID_REQUEST"`) {
		t.Fatalf("unknown mode = %d %s, want the same INVALID_REQUEST envelope on both transports", status, body)
	}

	transports.assertForbiddenWithoutHistoryScope(t, base+`,"include_ban_context":true,"response_mode":"compact"}`)
	assertToolSchema(t, transports.mcp["read"])
}

// assertForbiddenWithoutHistoryScope pins that a token without a history scope reads nothing on either transport,
// with or without the new output choice: HTTP answers the FORBIDDEN envelope, and MCP refuses the call at its
// transport before any tool runs (the existing MCP authorization, unchanged by this feature).
func (b banContextTransports) assertForbiddenWithoutHistoryScope(t *testing.T, arguments string) {
	t.Helper()

	response, err := http.Post(b.http["operations"]+"/api/v1/support/authentication-attempts/search", "application/json", //nolint:noctx // test client
		strings.NewReader(arguments))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()

	var body bytes.Buffer

	_, _ = body.ReadFrom(response.Body)

	if response.StatusCode != http.StatusForbidden || !strings.Contains(body.String(), `"FORBIDDEN"`) {
		t.Fatalf("HTTP without history scope = %d %s, want FORBIDDEN", response.StatusCode, body.String())
	}

	result, err := b.mcp["operations"].CallTool(context.Background(), &mcp.CallToolParams{Name: supportapi.OperationAttemptSearch,
		Arguments: json.RawMessage(arguments)})
	if err == nil && !result.IsError {
		t.Fatalf("MCP without history scope = %+v, want a refused call", result)
	}
}

// assertCompactBanContext checks the support projection of the shared-IP ban behind the subject's rejected request.
func assertCompactBanContext(t *testing.T, answer map[string]any) {
	t.Helper()

	contexts, _ := answer["ban_contexts"].([]any)
	if attempts, _ := answer["attempts"].([]any); len(attempts) != 0 || len(contexts) != 1 {
		t.Fatalf("compact answer = %v, want no attempts and one ban context", answer)
	}

	entry := contexts[0].(map[string]any)
	ban := entry["bans"].([]any)[0].(map[string]any)
	attribution := ban["attribution"].(map[string]any)
	counts := attribution["counts"].(map[string]any)
	got := fmt.Sprintf("%v/%v/%v/%v/%v/%v/%v/%v/%v/%v", entry["status"], ban["network"], ban["subject_relation"],
		ban["end"].(map[string]any)["reason"], attribution["code"], attribution["other_contributors"], counts["listed"],
		counts["other_accounts"], counts["unresolved"], attribution["contributing_accounts"])

	// alice and bob are other recorded accounts; ceo@foreign.test has no recorded account, so exclusivity stays open.
	if got != "matched/198.51.100.0/24/HIT_EXISTING_BAN/released/NOT_SUFFICIENTLY_ATTRIBUTABLE/observed/3/2/1/<nil>" {
		t.Fatalf("ban context = %s", got)
	}

	limitations, _ := ban["evidence"].(map[string]any)["limitations"].([]any)
	if !slices.Contains(limitations, any("UNRESOLVED_CONTRIBUTOR_IDENTITIES")) || ban["detail"] != nil {
		t.Fatalf("evidence = %v detail = %v, want the unresolved claim named and no detail in compact mode", limitations, ban["detail"])
	}
}

// assertDetailedBanContext checks that the detail role sees the full attempts, the ban detail, and the accounts.
func assertDetailedBanContext(t *testing.T, answer map[string]any) {
	t.Helper()

	ban := answer["ban_contexts"].([]any)[0].(map[string]any)["bans"].([]any)[0].(map[string]any)
	detail, _ := ban["detail"].(map[string]any)
	accounts := ban["attribution"].(map[string]any)["contributing_accounts"]

	if attempts, _ := answer["attempts"].([]any); len(attempts) == 0 || detail == nil ||
		len(detail["contributions"].(map[string]any)["items"].([]any)) != 3 ||
		fmt.Sprint(accounts) != "[alice@example.test bob@example.test]" {
		t.Fatalf("detailed answer = attempts %v detail %v accounts %v", answer["attempts"], detail, accounts)
	}
}

// assertToolSchema checks that the MCP tool offers the same output choice as HTTP.
func assertToolSchema(t *testing.T, session *mcp.ClientSession) {
	t.Helper()

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	index := slices.IndexFunc(tools.Tools, func(tool *mcp.Tool) bool { return tool.Name == supportapi.OperationAttemptSearch })
	if index < 0 {
		t.Fatal("attempt search tool missing")
	}

	schema, _ := json.Marshal(tools.Tools[index].InputSchema)
	if !strings.Contains(string(schema), `"include_ban_context"`) || !strings.Contains(string(schema), `"compact"`) {
		t.Fatalf("tool schema = %s, want response_mode and include_ban_context", schema)
	}
}

// jsonEqualValues compares two decoded JSON documents semantically.
func jsonEqualValues(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)

	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}
