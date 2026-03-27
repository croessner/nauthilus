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

// ModuleExpectedCall defines one order-sensitive expected module call.
type ModuleExpectedCall struct {
	Method      string `json:"method"`
	ArgContains string `json:"arg_contains,omitempty"`
}

func resetCallState(callIndex *int, runtimeErr *string) {
	if callIndex != nil {
		*callIndex = 0
	}
	if runtimeErr != nil {
		*runtimeErr = ""
	}
}

func recordModuleCall(moduleName string, expectedCalls []ModuleExpectedCall, callIndex *int, runtimeErr *string, method, args string) error {
	if runtimeErr != nil && *runtimeErr != "" {
		return fmt.Errorf("%s", *runtimeErr)
	}

	if len(expectedCalls) == 0 {
		return nil
	}

	if callIndex == nil || runtimeErr == nil {
		return nil
	}

	if *callIndex >= len(expectedCalls) {
		*runtimeErr = fmt.Sprintf("unexpected %s call #%d: method=%s args=%q", moduleName, *callIndex+1, method, args)
		return fmt.Errorf("%s", *runtimeErr)
	}

	expected := expectedCalls[*callIndex]
	wantMethod := strings.ToLower(strings.TrimSpace(expected.Method))
	gotMethod := strings.ToLower(strings.TrimSpace(method))

	if wantMethod != gotMethod {
		*runtimeErr = fmt.Sprintf("%s call #%d method mismatch: expected=%s got=%s", moduleName, *callIndex+1, expected.Method, method)
		return fmt.Errorf("%s", *runtimeErr)
	}

	if expected.ArgContains != "" && !strings.Contains(strings.ToLower(args), strings.ToLower(expected.ArgContains)) {
		*runtimeErr = fmt.Sprintf("%s call #%d args mismatch: expected to contain %q, got %q", moduleName, *callIndex+1, expected.ArgContains, args)
		return fmt.Errorf("%s", *runtimeErr)
	}

	(*callIndex)++

	return nil
}

func validateModuleCalls(moduleName string, expectedCalls []ModuleExpectedCall, callIndex int, runtimeErr string) error {
	if runtimeErr != "" {
		return fmt.Errorf("%s", runtimeErr)
	}

	if len(expectedCalls) == 0 {
		return nil
	}

	if callIndex < len(expectedCalls) {
		next := expectedCalls[callIndex]
		return fmt.Errorf("missing expected %s call #%d: method=%s arg_contains=%q", moduleName, callIndex+1, next.Method, next.ArgContains)
	}

	return nil
}

// MockData contains test data for mocking nauthilus modules.
type MockData struct {
	Context        *ContextMock        `json:"context"`
	Redis          *RedisMock          `json:"redis"`
	LDAP           *LDAPMock           `json:"ldap"`
	Backend        *BackendMock        `json:"backend"`
	Misc           *MiscMock           `json:"misc"`
	Password       *PasswordMock       `json:"password"`
	SoftWhitelist  *SoftWhitelistMock  `json:"soft_whitelist"`
	Mail           *MailMock           `json:"mail"`
	DNS            *DNSMock            `json:"dns"`
	OpenTelemetry  *OpenTelemetryMock  `json:"opentelemetry"`
	BruteForce     *BruteForceMock     `json:"brute_force"`
	Psnet          *PsnetMock          `json:"psnet"`
	Prometheus     *PrometheusMock     `json:"prometheus"`
	Util           *UtilMock           `json:"util"`
	Cache          *CacheMock          `json:"cache"`
	DB             *DBMock             `json:"db"`
	BackendResult  *BackendResultMock  `json:"backend_result"`
	HTTPRequest    *HTTPRequestMock    `json:"http_request"`
	HTTPResponse   *HTTPResponseMock   `json:"http_response"`
	HTTPClient     *HTTPClientMock     `json:"http_client"`
	ExpectedOutput *ExpectedOutputMock `json:"expected_output"`
}

// ContextMock contains mock data for nauthilus_context module.
type ContextMock struct {
	Username        string               `json:"username"`
	Password        string               `json:"password"`
	ClientIP        string               `json:"client_ip"`
	ClientPort      string               `json:"client_port"`
	ClientHost      string               `json:"client_host"`
	ClientID        string               `json:"client_id"`
	LocalIP         string               `json:"local_ip"`
	LocalPort       string               `json:"local_port"`
	Service         string               `json:"service"`
	Protocol        string               `json:"protocol"`
	UserAgent       string               `json:"user_agent"`
	Session         string               `json:"session"`
	Debug           bool                 `json:"debug"`
	NoAuth          bool                 `json:"no_auth"`
	Authenticated   bool                 `json:"authenticated"`
	UserFound       bool                 `json:"user_found"`
	Account         string               `json:"account"`
	UniqueUserID    string               `json:"unique_user_id"`
	DisplayName     string               `json:"display_name"`
	StatusMessage   string               `json:"status_message"`
	Attributes      map[string]string    `json:"attributes"`
	BruteForceCount int                  `json:"brute_force_count"`
	ExpectedCalls   []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *ContextMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *ContextMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("context", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *ContextMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("context", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// RedisMock contains mock responses for nauthilus_redis module.
type RedisMock struct {
	// Responses is kept for fixture compatibility and is converted into Redis seed data.
	Responses     map[string]any       `json:"responses"`
	InitialData   *RedisInitialData    `json:"initial_data"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *RedisMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *RedisMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("redis", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *RedisMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("redis", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// RedisInitialData defines miniredis seed content for Lua test runtime.
type RedisInitialData struct {
	Strings      map[string]string            `json:"strings"`
	Hashes       map[string]map[string]string `json:"hashes"`
	Sets         map[string][]string          `json:"sets"`
	Lists        map[string][]string          `json:"lists"`
	ZSets        map[string][]RedisZSetMember `json:"zsets"`
	HyperLogLogs map[string][]string          `json:"hyperloglogs"`
	TTLSeconds   map[string]int64             `json:"ttl_seconds"`
}

// RedisZSetMember is one sorted-set member entry used for fixture seed data.
type RedisZSetMember struct {
	Member string  `json:"member"`
	Score  float64 `json:"score"`
}

// LDAPMock contains mock data for nauthilus_ldap module.
type LDAPMock struct {
	SearchResult  map[string][]string  `json:"search_result"`
	SearchError   string               `json:"search_error"`
	ModifyOK      *bool                `json:"modify_ok"`
	ModifyError   string               `json:"modify_error"`
	EndpointHost  string               `json:"endpoint_host"`
	EndpointPort  int                  `json:"endpoint_port"`
	EndpointError string               `json:"endpoint_error"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *LDAPMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *LDAPMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("ldap", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *LDAPMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("ldap", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// BackendMock contains mock data/runtime state for nauthilus_backend module.
type BackendMock struct {
	BackendServers []BackendServerMock  `json:"backend_servers"`
	ExpectedCalls  []ModuleExpectedCall `json:"expected_calls"`

	RuntimeSelectedHost          string         `json:"-"`
	RuntimeSelectedPort          *int           `json:"-"`
	RuntimeAppliedBackendResult  map[string]any `json:"-"`
	RuntimeRemovedFromAttributes []string       `json:"-"`
	callIndex                    int            `json:"-"`
	runtimeErr                   string         `json:"-"`
}

// ResetRuntimeState clears backend mock runtime state.
func (m *BackendMock) ResetRuntimeState() {
	if m == nil {
		return
	}

	resetCallState(&m.callIndex, &m.runtimeErr)
	m.RuntimeSelectedHost = ""
	m.RuntimeSelectedPort = nil
	m.RuntimeAppliedBackendResult = nil
	m.RuntimeRemovedFromAttributes = nil
}

func (m *BackendMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("backend", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}

func (m *BackendMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("backend", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// BackendServerMock represents one backend server entry exposed to Lua filters.
type BackendServerMock struct {
	Protocol      string `json:"protocol"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	RequestURI    string `json:"request_uri"`
	TestUsername  string `json:"test_username"`
	TestPassword  string `json:"test_password"`
	HAProxyV2     bool   `json:"haproxy_v2"`
	TLS           bool   `json:"tls"`
	TLSSkipVerify bool   `json:"tls_skip_verify"`
	DeepCheck     bool   `json:"deep_check"`
}

// MiscMock contains mock data for nauthilus_misc module.
type MiscMock struct {
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *MiscMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *MiscMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("misc", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *MiscMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("misc", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// PasswordMock contains mock data for nauthilus_password module.
type PasswordMock struct {
	CompareResult bool                 `json:"compare_result"`
	PolicyResult  bool                 `json:"policy_result"`
	GeneratedHash string               `json:"generated_hash"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *PasswordMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *PasswordMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("password", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *PasswordMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("password", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// SoftWhitelistMock contains mock data for nauthilus_soft_whitelist module.
type SoftWhitelistMock struct {
	Entries       map[string][]string  `json:"entries"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *SoftWhitelistMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *SoftWhitelistMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("soft_whitelist", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *SoftWhitelistMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("soft_whitelist", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// MailMock contains mock data for nauthilus_mail module.
type MailMock struct {
	SendError     string               `json:"send_error"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *MailMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *MailMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("mail", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *MailMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("mail", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// DNSMock contains mock data for nauthilus_dns module.
type DNSMock struct {
	LookupResult  map[string]any       `json:"lookup_result"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *DNSMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *DNSMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("dns", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *DNSMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("dns", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// OpenTelemetryMock contains mock data for nauthilus_opentelemetry module.
type OpenTelemetryMock struct {
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *OpenTelemetryMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *OpenTelemetryMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("opentelemetry", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *OpenTelemetryMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("opentelemetry", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// BruteForceMock contains mock data for nauthilus_brute_force module.
type BruteForceMock struct {
	IsBlocked     bool                 `json:"is_blocked"`
	IncrementBy   int                  `json:"increment_by"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *BruteForceMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *BruteForceMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("brute_force", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *BruteForceMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("brute_force", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// PsnetMock contains mock data for nauthilus_psnet module.
type PsnetMock struct {
	Stats         map[string]any       `json:"stats"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *PsnetMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *PsnetMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("psnet", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *PsnetMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("psnet", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// PrometheusMock contains mock data for nauthilus_prometheus module.
type PrometheusMock struct {
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *PrometheusMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *PrometheusMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("prometheus", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *PrometheusMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("prometheus", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// UtilMock contains mock data for nauthilus_util module.
type UtilMock struct {
	Envs          map[string]string    `json:"envs"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *UtilMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *UtilMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("util", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *UtilMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("util", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// CacheMock contains mock data for nauthilus_cache module.
type CacheMock struct {
	Entries       map[string]any       `json:"entries"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *CacheMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *CacheMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("cache", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *CacheMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("cache", m.ExpectedCalls, m.callIndex, m.runtimeErr)
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
	Authenticated bool                 `json:"authenticated"`
	UserFound     bool                 `json:"user_found"`
	AccountField  string               `json:"account_field"`
	TOTPSecret    string               `json:"totp_secret"`
	TOTPRecovery  []string             `json:"totp_recovery"`
	UniqueUserID  string               `json:"unique_user_id"`
	DisplayName   string               `json:"display_name"`
	Attributes    map[string]string    `json:"attributes"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *BackendResultMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *BackendResultMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("backend_result", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *BackendResultMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("backend_result", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// HTTPRequestMock contains mock HTTP request data.
type HTTPRequestMock struct {
	Method        string               `json:"method"`
	Path          string               `json:"path"`
	Headers       map[string]string    `json:"headers"`
	Body          string               `json:"body"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *HTTPRequestMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *HTTPRequestMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("http_request", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *HTTPRequestMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("http_request", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// HTTPResponseMock contains mock HTTP response data.
type HTTPResponseMock struct {
	StatusCode    int                  `json:"status_code"`
	Headers       map[string]string    `json:"headers"`
	Body          string               `json:"body"`
	ExpectedCalls []ModuleExpectedCall `json:"expected_calls"`

	callIndex  int    `json:"-"`
	runtimeErr string `json:"-"`
}

func (m *HTTPResponseMock) ResetRuntimeState() { resetCallState(&m.callIndex, &m.runtimeErr) }
func (m *HTTPResponseMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}
	return recordModuleCall("http_response", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}
func (m *HTTPResponseMock) ValidateComplete() error {
	if m == nil {
		return nil
	}
	return validateModuleCalls("http_response", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// HTTPClientMock contains mock data for glua_http module.
type HTTPClientMock struct {
	Responses     []HTTPClientResponse       `json:"responses"`
	ExpectedCalls []ModuleExpectedCall       `json:"expected_calls"`
	Captured      []HTTPClientCapturedRecord `json:"-"`
	callIndex     int                        `json:"-"`
	responseIndex int                        `json:"-"`
	runtimeErr    string                     `json:"-"`
}

// HTTPClientResponse defines one mocked HTTP response for glua_http.
type HTTPClientResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Error      string            `json:"error"`
}

// HTTPClientCapturedRecord stores one captured glua_http request invocation.
type HTTPClientCapturedRecord struct {
	Method  string
	URL     string
	Body    string
	Headers map[string]string
}

// ResetRuntimeState resets call-tracking and captured-request runtime data.
func (m *HTTPClientMock) ResetRuntimeState() {
	if m == nil {
		return
	}

	resetCallState(&m.callIndex, &m.runtimeErr)
	m.responseIndex = 0
	m.Captured = nil
}

// RecordCall validates one glua_http call against the configured expectations.
func (m *HTTPClientMock) RecordCall(method, args string) error {
	if m == nil {
		return nil
	}

	return recordModuleCall("http_client", m.ExpectedCalls, &m.callIndex, &m.runtimeErr, method, args)
}

// ValidateComplete verifies that all expected glua_http calls were consumed.
func (m *HTTPClientMock) ValidateComplete() error {
	if m == nil {
		return nil
	}

	return validateModuleCalls("http_client", m.ExpectedCalls, m.callIndex, m.runtimeErr)
}

// ExpectedOutputMock defines expected test results.
type ExpectedOutputMock struct {
	FilterResult            *int     `json:"filter_result,omitempty"`
	FeatureResult           *bool    `json:"feature_result,omitempty"`
	ActionResult            *bool    `json:"action_result,omitempty"`
	BackendResult           *bool    `json:"backend_result,omitempty"`
	BackendAuthenticated    *bool    `json:"backend_authenticated,omitempty"`
	BackendUserFound        *bool    `json:"backend_user_found,omitempty"`
	BackendAccountField     *string  `json:"backend_account_field,omitempty"`
	BackendDisplayName      *string  `json:"backend_display_name,omitempty"`
	BackendUniqueUserID     *string  `json:"backend_unique_user_id,omitempty"`
	UsedBackendAddress      *string  `json:"used_backend_address,omitempty"`
	UsedBackendPort         *int     `json:"used_backend_port,omitempty"`
	StatusMessageContain    []string `json:"status_message_contain,omitempty"`
	StatusMessageNotContain []string `json:"status_message_not_contain,omitempty"`
	LogsContain             []string `json:"logs_contain,omitempty"`
	LogsNotContain          []string `json:"logs_not_contain,omitempty"`
	ErrorExpected           bool     `json:"error_expected"`
}

// TestResult contains the results of a Lua script test.
type TestResult struct {
	Success              bool
	FilterResult         *int
	FeatureResult        *bool
	ActionResult         *bool
	BackendResult        *bool
	BackendAuthenticated *bool
	BackendUserFound     *bool
	BackendAccountField  *string
	BackendDisplayName   *string
	BackendUniqueUserID  *string
	UsedBackendAddress   *string
	UsedBackendPort      *int
	StatusMessages       []string
	Logs                 []string
	Errors               []error
}
