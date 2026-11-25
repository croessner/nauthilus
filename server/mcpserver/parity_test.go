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

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/handler/support"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v4/server/supportapi"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/historytest"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// parityBase is the instant the newest fixture row is shifted to.
var parityBase = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

// parityServices returns one history and one diagnostics service shared by both transports.
func parityServices(t *testing.T) supportapi.Services {
	t.Helper()

	store, err := historytest.LoadFixture("../supporthistory/testdata/attempt_scenarios.json", parityBase)
	if err != nil {
		t.Fatal(err)
	}

	history, err := supporthistory.NewService(supporthistory.Options{Attempts: store, Bans: historytest.WithRecordedBan(store, "req-brute"),
		Now: func() time.Time { return parityBase.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}

	services := testServices(t)
	services.History = history

	return services
}

// httpBody runs one operation through the management HTTP adapter with a service token of the given scopes.
func httpBody(t *testing.T, services supportapi.Services, operation supportapi.Operation, arguments string, scopes string) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	group := engine.Group("/api/v1", func(ctx *gin.Context) {
		oidcbearer.BindClaims(ctx, jwt.MapClaims{definitions.ClaimClientID: "support-console", "sub": "support-console",
			"scope": scopes})
		ctx.Next()
	})
	support.New(&handlerdeps.Deps{SupportHistory: services.History, SupportOperations: services.Operations}).Register(group)

	request := httptest.NewRequest(http.MethodPost, "/api/v1"+operation.HTTPPath, strings.NewReader(arguments))
	request.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	return recorder.Code, recorder.Body.String()
}

// parityCase is one operation call of the parity matrix.
type parityCase struct {
	operation string
	arguments string
	token     string
}

// parityCases returns every operation call, result and error, that both transports must answer identically.
func parityCases(window, around string) map[string]parityCase {
	return map[string]parityCase{
		"forbidden without detail": {supportapi.OperationAttemptDetail, `{"schema_version":"1","attempt_id":"fl1.22222222222222222222222222222222","around":"` + around + `"}`, "read-only"},
		"attempt search":           {supportapi.OperationAttemptSearch, `{"schema_version":"1","subject":{"login":"anna@example.test"},"filter":{` + window + `},"page":{"limit":5}}`, "detail"},
		"compact ban context":      {supportapi.OperationAttemptSearch, `{"schema_version":"1","subject":{"login":"anna@example.test"},"filter":{` + window + `},"page":{"limit":20},"include_ban_context":true,"response_mode":"compact"}`, "detail"},
		"compact ban context read": {supportapi.OperationAttemptSearch, `{"schema_version":"1","subject":{"login":"anna@example.test"},"filter":{` + window + `},"page":{"limit":20},"include_ban_context":true,"response_mode":"compact"}`, "read-only"},
		"detailed ban context":     {supportapi.OperationAttemptSearch, `{"schema_version":"1","subject":{"login":"anna@example.test"},"filter":{` + window + `},"page":{"limit":20},"include_ban_context":true,"response_mode":"detailed"}`, "read-only"},
		"unknown response mode":    {supportapi.OperationAttemptSearch, `{"schema_version":"1","subject":{"login":"anna@example.test"},"filter":{` + window + `},"response_mode":"verbose"}`, "read-only"},
		"attempt detail":           {supportapi.OperationAttemptDetail, `{"schema_version":"1","attempt_id":"fl1.22222222222222222222222222222222","around":"` + around + `"}`, "detail"},
		"ban history":              {supportapi.OperationBanHistory, `{"schema_version":"1","target":{"network":"198.51.100.0/24"},"filter":{` + window + `}}`, "detail"},
		"diagnostics":              {supportapi.OperationDiagnostics, `{"schema_version":"1","components":["ldap"]}`, "detail"},
		"invalid window":           {supportapi.OperationAttemptSearch, `{"schema_version":"1","subject":{"login":"a"},"filter":{"from":"2020-01-01T00:00:00Z","until":"2021-01-01T00:00:00Z"}}`, "detail"},
		"unknown field":            {supportapi.OperationDiagnostics, `{"schema_version":"1","shell":"id"}`, "detail"},
		"log overview":             {supportapi.OperationLogOverview, `{"schema_version":"1","levels":["error"]}`, "detail"},
		"unknown log level":        {supportapi.OperationLogOverview, `{"schema_version":"1","levels":["debug"]}`, "detail"},
	}
}

// TestHTTPAndMCPAnswerTheSameBytes pins byte-for-byte parity of every operation, for results and errors: the MCP
// text content equals the HTTP body, the structured content is the same JSON, and isError mirrors a non-200 status.
func TestHTTPAndMCPAnswerTheSameBytes(t *testing.T) {
	services := parityServices(t)
	authority := newAuthority()
	authority.Tokens["detail"] = userToken(staticClient, []any{staticClient, testResource}, definitions.ScopeHistoryDetail,
		definitions.ScopeOperationsRead)

	server, err := New(Deps{Settings: &config.RuntimeMCPServerSection{Enabled: true, HostedResource: "support-mcp",
		TrustedProxies: []string{"127.0.0.1/32", "::1/128"}}, Tokens: authority, Services: services, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}

	authority.Tokens["read-only"] = userToken(staticClient, []any{staticClient, testResource}, definitions.ScopeHistoryRead)

	sessions := map[string]*mcp.ClientSession{"detail": connect(t, server, "detail", "2025-06-18"),
		"read-only": connect(t, server, "read-only", "2025-06-18")}
	httpScopes := map[string]string{"detail": definitions.ScopeHistoryDetail + " " + definitions.ScopeOperationsRead,
		"read-only": definitions.ScopeHistoryRead}
	window := fmt.Sprintf(`"from":%q,"until":%q`, parityBase.Add(-2*time.Hour).Format(time.RFC3339), parityBase.Add(time.Minute).Format(time.RFC3339))
	around := parityBase.Add(-10 * time.Minute).Format(time.RFC3339)

	for name, tc := range parityCases(window, around) {
		t.Run(name, func(t *testing.T) {
			token := tc.token
			if token == "" {
				token = "detail"
			}

			operation, _ := supportapi.Lookup(tc.operation)
			status, body := httpBody(t, services, operation, tc.arguments, httpScopes[token])

			result, err := sessions[token].CallTool(context.Background(), &mcp.CallToolParams{Name: tc.operation, Arguments: json.RawMessage(tc.arguments)})
			if err != nil {
				t.Fatal(err)
			}

			text := result.Content[0].(*mcp.TextContent).Text
			if text != body || result.IsError != (status != http.StatusOK) {
				t.Fatalf("parity broken: HTTP %d %s\nMCP isError=%v %s", status, body, result.IsError, text)
			}

			structured, err := json.Marshal(result.StructuredContent)
			if err != nil || !jsonEqual(t, structured, []byte(body)) {
				t.Fatalf("structured content differs: %s", structured)
			}

			if strings.Contains(tc.arguments, `"include_ban_context":true`) && !strings.Contains(body, `"status":"matched"`) {
				t.Fatal("ban context body links no recorded ban over both transports")
			}
		})
	}
}

// jsonEqual compares two JSON documents semantically.
func jsonEqual(t *testing.T, left []byte, right []byte) bool {
	t.Helper()

	var leftValue, rightValue any

	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}

	leftJSON, _ := json.Marshal(leftValue)
	rightJSON, _ := json.Marshal(rightValue)

	return string(leftJSON) == string(rightJSON)
}
