// Copyright (C) 2025 Christian Rößner
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

package luatest

import (
	"fmt"
	"strings"
)

// MockData contains test data for mocking nauthilus modules.
type MockData struct {
	Context        *ContextMock        `json:"context"`
	Redis          *RedisMock          `json:"redis"`
	LDAP           *LDAPMock           `json:"ldap"`
	DB             *DBMock             `json:"db"`
	BackendResult  *BackendResultMock  `json:"backend_result"`
	HTTPRequest    *HTTPRequestMock    `json:"http_request"`
	HTTPResponse   *HTTPResponseMock   `json:"http_response"`
	ExpectedOutput *ExpectedOutputMock `json:"expected_output"`
}

// ContextMock contains mock data for nauthilus_context module.
type ContextMock struct {
	Username        string            `json:"username"`
	Password        string            `json:"password"`
	ClientIP        string            `json:"client_ip"`
	ClientPort      string            `json:"client_port"`
	ClientHost      string            `json:"client_host"`
	ClientID        string            `json:"client_id"`
	LocalIP         string            `json:"local_ip"`
	LocalPort       string            `json:"local_port"`
	Service         string            `json:"service"`
	Protocol        string            `json:"protocol"`
	UserAgent       string            `json:"user_agent"`
	Session         string            `json:"session"`
	Debug           bool              `json:"debug"`
	NoAuth          bool              `json:"no_auth"`
	Authenticated   bool              `json:"authenticated"`
	UserFound       bool              `json:"user_found"`
	Account         string            `json:"account"`
	UniqueUserID    string            `json:"unique_user_id"`
	DisplayName     string            `json:"display_name"`
	StatusMessage   string            `json:"status_message"`
	Attributes      map[string]string `json:"attributes"`
	BruteForceCount int               `json:"brute_force_count"`
}

// RedisMock contains mock responses for nauthilus_redis module.
type RedisMock struct {
	Responses map[string]any `json:"responses"`
}

// LDAPMock contains mock data for nauthilus_ldap module.
type LDAPMock struct {
	SearchResult  map[string][]string `json:"search_result"`
	SearchError   string              `json:"search_error"`
	ModifyOK      *bool               `json:"modify_ok"`
	ModifyError   string              `json:"modify_error"`
	EndpointHost  string              `json:"endpoint_host"`
	EndpointPort  int                 `json:"endpoint_port"`
	EndpointError string              `json:"endpoint_error"`
}

// DBMock contains mock data for db module.
type DBMock struct {
	OpenError       string           `json:"open_error"`
	ExecError       string           `json:"exec_error"`
	QueryError      string           `json:"query_error"`
	DeclarativeMode bool             `json:"declarative_mode"`
	ExpectedCalls   []DBExpectedCall `json:"expected_calls"`

	callIndex        int    `json:"-"`
	lastMatchedIndex int    `json:"-"`
	runtimeErr       string `json:"-"`
}

// DBExpectedCall defines an expected DB interaction in test mode.
type DBExpectedCall struct {
	Method        string   `json:"method"`
	QueryContains string   `json:"query_contains,omitempty"`
	RowsAffected  *int64   `json:"rows_affected,omitempty"`
	LastInsertID  *int64   `json:"last_insert_id,omitempty"`
	Columns       []string `json:"columns,omitempty"`
	Rows          [][]any  `json:"rows,omitempty"`
}

// ResetRuntimeState clears DB mock runtime validation state.
func (m *DBMock) ResetRuntimeState() {
	if m == nil {
		return
	}

	m.callIndex = 0
	m.lastMatchedIndex = -1
	m.runtimeErr = ""
}

// RecordCall validates one DB call against expected_calls in order.
func (m *DBMock) RecordCall(method, query string) error {
	if m == nil {
		return nil
	}

	if m.runtimeErr != "" {
		return fmt.Errorf("%s", m.runtimeErr)
	}

	if len(m.ExpectedCalls) == 0 {
		return nil
	}

	if m.callIndex >= len(m.ExpectedCalls) {
		m.runtimeErr = fmt.Sprintf("unexpected db call #%d: method=%s query=%q", m.callIndex+1, method, query)

		return fmt.Errorf("%s", m.runtimeErr)
	}

	expected := m.ExpectedCalls[m.callIndex]
	wantMethod := strings.ToLower(strings.TrimSpace(expected.Method))
	gotMethod := strings.ToLower(strings.TrimSpace(method))

	if wantMethod != gotMethod {
		m.runtimeErr = fmt.Sprintf(
			"db call #%d method mismatch: expected=%s got=%s",
			m.callIndex+1, expected.Method, method,
		)

		return fmt.Errorf("%s", m.runtimeErr)
	}

	if expected.QueryContains != "" {
		if !strings.Contains(strings.ToLower(query), strings.ToLower(expected.QueryContains)) {
			m.runtimeErr = fmt.Sprintf(
				"db call #%d query mismatch: expected to contain %q, got %q",
				m.callIndex+1, expected.QueryContains, query,
			)

			return fmt.Errorf("%s", m.runtimeErr)
		}
	}

	m.lastMatchedIndex = m.callIndex
	m.callIndex++

	return nil
}

// LastMatchedCall returns the most recently matched expected DB call.
func (m *DBMock) LastMatchedCall() *DBExpectedCall {
	if m == nil {
		return nil
	}

	if m.lastMatchedIndex < 0 || m.lastMatchedIndex >= len(m.ExpectedCalls) {
		return nil
	}

	return &m.ExpectedCalls[m.lastMatchedIndex]
}

// ValidateComplete checks that all expected DB calls were consumed.
func (m *DBMock) ValidateComplete() error {
	if m == nil {
		return nil
	}

	if m.runtimeErr != "" {
		return fmt.Errorf("%s", m.runtimeErr)
	}

	if len(m.ExpectedCalls) == 0 {
		return nil
	}

	if m.callIndex < len(m.ExpectedCalls) {
		next := m.ExpectedCalls[m.callIndex]

		return fmt.Errorf(
			"missing expected db call #%d: method=%s query_contains=%q",
			m.callIndex+1, next.Method, next.QueryContains,
		)
	}

	return nil
}

// BackendResultMock contains mock data for nauthilus_backend_result module.
type BackendResultMock struct {
	Authenticated bool              `json:"authenticated"`
	UserFound     bool              `json:"user_found"`
	AccountField  string            `json:"account_field"`
	TOTPSecret    string            `json:"totp_secret"`
	TOTPRecovery  []string          `json:"totp_recovery"`
	UniqueUserID  string            `json:"unique_user_id"`
	DisplayName   string            `json:"display_name"`
	Attributes    map[string]string `json:"attributes"`
}

// HTTPRequestMock contains mock HTTP request data.
type HTTPRequestMock struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// HTTPResponseMock contains mock HTTP response data.
type HTTPResponseMock struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

// ExpectedOutputMock defines expected test results.
type ExpectedOutputMock struct {
	FilterResult   *int     `json:"filter_result,omitempty"`
	FeatureResult  *bool    `json:"feature_result,omitempty"`
	ActionResult   *bool    `json:"action_result,omitempty"`
	BackendResult  *bool    `json:"backend_result,omitempty"`
	LogsContain    []string `json:"logs_contain,omitempty"`
	LogsNotContain []string `json:"logs_not_contain,omitempty"`
	ErrorExpected  bool     `json:"error_expected"`
}

// TestResult contains the results of a Lua script test.
type TestResult struct {
	Success       bool
	FilterResult  *int
	FeatureResult *bool
	ActionResult  *bool
	BackendResult *bool
	Logs          []string
	Errors        []error
}
