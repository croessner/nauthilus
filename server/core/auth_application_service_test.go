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

package core

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/model/authdto"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
)

func TestAuthApplicationService_AuthenticateCapturesOutcomeWithoutHTTPRendering(t *testing.T) {
	deps, mock := setupPhase4AuthApplicationServiceTest(t, "test(phase4_auth_ok)")
	deps.Resp = panicResponseWriter{}

	expectPhase4UserAccountMapping(t, mock, "phase4-auth-ok@example.test", "imap")

	service := NewAuthApplicationService(deps)
	input := NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeAuthenticate, authdto.Request{
		Username:  "phase4-auth-ok@example.test",
		Password:  "secret",
		ClientIP:  "203.0.113.10",
		Protocol:  "imap",
		Method:    "plain",
		UserAgent: "grpc-test/1.0",
	})

	outcome, err := service.Authenticate(context.Background(), input)
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if outcome.Decision != AuthDecisionOK {
		t.Fatalf("decision = %q, want %q", outcome.Decision, AuthDecisionOK)
	}

	if outcome.Session == "" {
		t.Fatal("expected generated session")
	}

	if outcome.AccountField != "uid" {
		t.Fatalf("account field = %q, want uid", outcome.AccountField)
	}

	if outcome.Backend != definitions.BackendTest {
		t.Fatalf("backend = %v, want %v", outcome.Backend, definitions.BackendTest)
	}

	values := outcome.Attributes["uid"]
	if len(values) != 1 || values[0] != "phase4-auth-ok@example.test" {
		t.Fatalf("uid attribute = %#v, want authenticated username", values)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}
}

func TestAuthApplicationService_LookupIdentityUsesNoAuthBoundary(t *testing.T) {
	deps, mock := setupPhase4AuthApplicationServiceTest(t, "test(phase4_lookup_identity)")
	deps.Resp = panicResponseWriter{}

	expectPhase4UserAccountMapping(t, mock, "phase4-lookup@example.test", "imap")

	service := NewAuthApplicationService(deps)
	input := NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeAuthenticate, authdto.Request{
		Username: "phase4-lookup@example.test",
		ClientIP: "203.0.113.14",
		Protocol: "imap",
		Method:   "lookup",
	})

	outcome, err := service.LookupIdentity(context.Background(), input)
	if err != nil {
		t.Fatalf("LookupIdentity returned error: %v", err)
	}

	if outcome.Decision != AuthDecisionOK {
		t.Fatalf("decision = %q, want %q", outcome.Decision, AuthDecisionOK)
	}

	if outcome.AccountField != "uid" {
		t.Fatalf("account field = %q, want uid", outcome.AccountField)
	}

	values := outcome.Attributes["uid"]
	if len(values) != 1 || values[0] != "phase4-lookup@example.test" {
		t.Fatalf("uid attribute = %#v, want lookup username", values)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}
}

func TestAuthApplicationService_CapturesDomainFailure(t *testing.T) {
	for _, testCase := range authApplicationDomainFailureCases() {
		t.Run(testCase.name, func(t *testing.T) {
			assertAuthApplicationOutcome(t, testCase)
		})
	}
}

func TestAuthApplicationService_CapturesTempFail(t *testing.T) {
	for _, testCase := range authApplicationTempFailCases() {
		t.Run(testCase.name, func(t *testing.T) {
			assertAuthApplicationOutcome(t, testCase)
		})
	}
}

type authApplicationOutcomeCase struct {
	verifier     PasswordVerifier
	run          func(AuthApplicationService, context.Context, AuthInput) (*AuthOutcome, error)
	name         string
	setupName    string
	username     string
	password     string
	clientIP     string
	method       string
	wantStatus   string
	mode         AuthMode
	wantDecision AuthDecision
	expectLookup bool
}

// authApplicationDomainFailureCases lists service methods that capture password-domain failures.
func authApplicationDomainFailureCases() []authApplicationOutcomeCase {
	return []authApplicationOutcomeCase{
		{
			verifier:     failingPasswordVerifier{},
			name:         "lookup identity",
			setupName:    "test(phase6_lookup_identity_fail)",
			username:     "phase6-lookup-fail@example.test",
			clientIP:     "203.0.113.16",
			method:       "lookup",
			wantStatus:   definitions.PasswordFail,
			mode:         AuthModeLookupIdentity,
			wantDecision: AuthDecisionFail,
			expectLookup: true,
			run: func(service AuthApplicationService, ctx context.Context, input AuthInput) (*AuthOutcome, error) {
				return service.LookupIdentity(ctx, input)
			},
		},
		{
			verifier:     failingPasswordVerifier{},
			name:         "authenticate",
			setupName:    "test(phase4_auth_fail)",
			username:     "phase4-auth-fail@example.test",
			password:     "wrong",
			clientIP:     "203.0.113.12",
			wantStatus:   definitions.PasswordFail,
			mode:         AuthModeAuthenticate,
			wantDecision: AuthDecisionFail,
			expectLookup: true,
			run: func(service AuthApplicationService, ctx context.Context, input AuthInput) (*AuthOutcome, error) {
				return service.Authenticate(ctx, input)
			},
		},
	}
}

// authApplicationTempFailCases lists service methods that capture backend temporary failures.
func authApplicationTempFailCases() []authApplicationOutcomeCase {
	return []authApplicationOutcomeCase{
		{
			verifier:     tempfailPasswordVerifier{},
			name:         "lookup identity",
			setupName:    "test(phase6_lookup_identity_tempfail)",
			username:     "phase6-lookup-tempfail@example.test",
			clientIP:     "203.0.113.17",
			method:       "lookup",
			wantStatus:   definitions.TempFailDefault,
			mode:         AuthModeLookupIdentity,
			wantDecision: AuthDecisionTempFail,
			run: func(service AuthApplicationService, ctx context.Context, input AuthInput) (*AuthOutcome, error) {
				return service.LookupIdentity(ctx, input)
			},
		},
		{
			verifier:     tempfailPasswordVerifier{},
			name:         "authenticate",
			setupName:    "test(phase4_auth_tempfail)",
			username:     "phase4-auth-tempfail@example.test",
			password:     "secret",
			clientIP:     "203.0.113.13",
			wantStatus:   definitions.TempFailDefault,
			mode:         AuthModeAuthenticate,
			wantDecision: AuthDecisionTempFail,
			run: func(service AuthApplicationService, ctx context.Context, input AuthInput) (*AuthOutcome, error) {
				return service.Authenticate(ctx, input)
			},
		},
	}
}

// assertAuthApplicationOutcome verifies one service-level captured auth outcome case.
func assertAuthApplicationOutcome(t *testing.T, testCase authApplicationOutcomeCase) {
	t.Helper()

	deps, mock := setupPhase4AuthApplicationServiceTest(t, testCase.setupName)

	RegisterPasswordVerifier(testCase.verifier)

	if testCase.expectLookup {
		expectPhase4UserAccountLookup(t, mock, testCase.username, "imap")
	}

	service := NewAuthApplicationService(deps)
	input := NewAuthInputFromStructuredRequest(definitions.ServGRPC, testCase.mode, authdto.Request{
		Username: testCase.username,
		Password: testCase.password,
		ClientIP: testCase.clientIP,
		Protocol: "imap",
		Method:   testCase.method,
	})

	outcome, err := testCase.run(service, context.Background(), input)
	if err != nil {
		t.Fatalf("%s returned error: %v", testCase.name, err)
	}

	if outcome.Decision != testCase.wantDecision {
		t.Fatalf("decision = %q, want %q", outcome.Decision, testCase.wantDecision)
	}

	if outcome.StatusMessage != testCase.wantStatus {
		t.Fatalf("status message = %q, want %q", outcome.StatusMessage, testCase.wantStatus)
	}

	if testCase.expectLookup {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("redis expectations were not met: %v", err)
		}
	}
}

func TestAuthApplicationService_AuthenticateValidatesStructuredInput(t *testing.T) {
	deps, _ := setupPhase4AuthApplicationServiceTest(t, "test(phase4_auth_validation)")
	service := NewAuthApplicationService(deps)
	input := NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeAuthenticate, authdto.Request{
		Username: "phase4-auth-validation@example.test",
		Protocol: "imap",
	})

	_, err := service.Authenticate(context.Background(), input)
	if err == nil {
		t.Fatal("expected validation error")
	}

	inputErr, ok := stderrors.AsType[*AuthInputError](err)
	if !ok {
		t.Fatalf("error = %T, want *AuthInputError", err)
	}

	if inputErr.Field != "password" {
		t.Fatalf("field = %q, want password", inputErr.Field)
	}
}

func TestAuthApplicationService_ValidatesRequiredInputs(t *testing.T) {
	deps, _ := setupPhase4AuthApplicationServiceTest(t, "test(phase6_required_inputs)")
	service := NewAuthApplicationService(deps)

	cases := []struct {
		name      string
		run       func(context.Context, AuthInput) (*AuthOutcome, error)
		input     AuthInput
		wantField string
	}{
		{
			name: "authenticate empty username",
			run:  service.Authenticate,
			input: NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeAuthenticate, authdto.Request{
				Password: "secret",
				Protocol: "imap",
			}),
			wantField: "username",
		},
		{
			name: "authenticate empty password",
			run:  service.Authenticate,
			input: NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeAuthenticate, authdto.Request{
				Username: "phase6-required-password@example.test",
				Protocol: "imap",
			}),
			wantField: "password",
		},
		{
			name: "lookup identity empty username",
			run:  service.LookupIdentity,
			input: NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeLookupIdentity, authdto.Request{
				Protocol: "imap",
			}),
			wantField: "username",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := testCase.run(context.Background(), testCase.input)
			if err == nil {
				t.Fatal("expected validation error")
			}

			inputErr, ok := stderrors.AsType[*AuthInputError](err)
			if !ok {
				t.Fatalf("error = %T, want *AuthInputError", err)
			}

			if inputErr.Field != testCase.wantField {
				t.Fatalf("field = %q, want %q", inputErr.Field, testCase.wantField)
			}
		})
	}
}

func TestAuthApplicationService_ListAccountsUsesApplicationBoundary(t *testing.T) {
	deps, mock := setupPhase4AuthApplicationServiceTest(t, "test(phase4_list_accounts)")
	service := NewAuthApplicationService(deps)

	for _, username := range []string{"zeta.phase4@example.test", "alpha.phase4@example.test"} {
		expectPhase4UserAccountMapping(t, mock, username, "imap")

		input := NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeAuthenticate, authdto.Request{
			Username: username,
			Password: "secret",
			ClientIP: "203.0.113.11",
			Protocol: "imap",
		})

		if _, err := service.Authenticate(context.Background(), input); err != nil {
			t.Fatalf("seed Authenticate(%q) returned error: %v", username, err)
		}
	}

	input := NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeListAccounts, authdto.Request{
		ClientIP: "203.0.113.11",
	})

	outcome, err := service.ListAccounts(context.Background(), input)
	if err != nil {
		t.Fatalf("ListAccounts returned error: %v", err)
	}

	want := []string{"alpha.phase4@example.test", "zeta.phase4@example.test"}
	if len(outcome.Accounts) != len(want) {
		t.Fatalf("accounts = %#v, want %#v", outcome.Accounts, want)
	}

	for index := range want {
		if outcome.Accounts[index] != want[index] {
			t.Fatalf("accounts = %#v, want %#v", outcome.Accounts, want)
		}
	}

	if outcome.Session == "" {
		t.Fatal("expected generated session")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}
}

func TestAuthApplicationService_ListAccountsRejectsOIDCClaimsWithoutScope(t *testing.T) {
	deps, _ := setupPhase4AuthApplicationServiceTest(t, "test(phase6_list_accounts_scope)")
	service := NewAuthApplicationService(deps)
	ctx := ContextWithOIDCClaims(context.Background(), jwt.MapClaims{
		"scope": definitions.ScopeAuthenticate,
	})
	input := NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeListAccounts, authdto.Request{
		ClientIP: "203.0.113.15",
	})

	_, err := service.ListAccounts(ctx, input)
	if err == nil {
		t.Fatal("expected list-accounts scope rejection")
	}

	if _, ok := stderrors.AsType[*AuthPermissionDeniedError](err); !ok {
		t.Fatalf("error = %T, want *AuthPermissionDeniedError", err)
	}
}

func setupPhase4AuthApplicationServiceTest(t *testing.T, backendName string) (AuthDeps, redismock.ClientMock) {
	t.Helper()

	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)

	var backend config.Backend
	if err := backend.Set(backendName); err != nil {
		t.Fatalf("backend.Set(%q) failed: %v", backendName, err)
	}

	cfg, ok := config.GetFile().(*config.FileSettings)
	if !ok {
		t.Fatalf("unexpected config type %T", config.GetFile())
	}

	cfg.Server.Backends = []*config.Backend{&backend}

	util.SetDefaultConfigFile(config.GetFile())
	util.SetDefaultEnvironment(config.GetEnvironment())

	previousVerifier := getPasswordVerifier()
	previousFilter := getLuaSubject()

	RegisterPasswordVerifier(testPasswordVerifier{})
	RegisterLuaSubject(testLuaSubject{})

	t.Cleanup(func() {
		RegisterPasswordVerifier(previousVerifier)
		RegisterLuaSubject(previousFilter)
	})

	db, mock := redismock.NewClientMock()
	deps := setupAuthDeps()
	deps.Cfg = config.GetFile()
	deps.Redis = rediscli.NewTestClient(db)
	deps.AccountCache = accountcache.NewManager(config.GetFile())

	return deps, mock
}

func TestAuthApplicationServiceUsesCurrentConfigAtRequestBoundary(t *testing.T) {
	db, _ := redismock.NewClientMock()
	startup := &config.FileSettings{}
	current := &config.FileSettings{}
	service := &authApplicationService{deps: AuthDeps{
		Cfg:           startup,
		CurrentConfig: func() config.File { return current },
		Env:           config.NewTestEnvironmentConfig(),
		Redis:         rediscli.NewTestClient(db),
	}}

	deps, err := service.effectiveDeps()
	if err != nil {
		t.Fatalf("effectiveDeps() error = %v", err)
	}

	if deps.Cfg != current {
		t.Fatalf("effectiveDeps().Cfg = %p, want current snapshot %p", deps.Cfg, current)
	}
}

func expectPhase4UserAccountMapping(t *testing.T, mock redismock.ClientMock, username, protocol string) {
	t.Helper()

	cfg := config.GetFile()
	key := rediscli.GetUserHashKey(cfg.GetServer().GetRedis().GetPrefix(), username)
	field := accountcache.GetAccountMappingField(username, protocol, "")

	mock.ExpectHGet(key, field).RedisNil()
	mock.ExpectHSet(key, field, username).SetVal(1)
}

func expectPhase4UserAccountLookup(t *testing.T, mock redismock.ClientMock, username, protocol string) {
	t.Helper()

	cfg := config.GetFile()
	key := rediscli.GetUserHashKey(cfg.GetServer().GetRedis().GetPrefix(), username)
	field := accountcache.GetAccountMappingField(username, protocol, "")

	mock.ExpectHGet(key, field).RedisNil()
}

type testPasswordVerifier struct{}

func (testPasswordVerifier) Verify(
	ctx *gin.Context,
	auth *AuthState,
	passDBs []*PassDBMap,
) (*PassDBResult, error) {
	return VerifyPasswordPipeline(ctx, auth, passDBs)
}

type failingPasswordVerifier struct{}

func (failingPasswordVerifier) Verify(
	_ *gin.Context,
	auth *AuthState,
	_ []*PassDBMap,
) (*PassDBResult, error) {
	result := GetPassDBResultFromPool()
	result.UserFound = true
	result.Authenticated = false
	result.AccountField = "uid"
	result.Account = auth.Request.Username
	result.Backend = definitions.BackendTest
	result.Attributes = map[string][]any{
		"uid": {auth.Request.Username},
	}

	return result, nil
}

type tempfailPasswordVerifier struct{}

func (tempfailPasswordVerifier) Verify(
	_ *gin.Context,
	_ *AuthState,
	_ []*PassDBMap,
) (*PassDBResult, error) {
	return nil, stderrors.New("backend unavailable")
}

type testLuaSubject struct{}

func (testLuaSubject) Analyze(_ *gin.Context, view *StateView, result *PassDBResult) definitions.AuthResult {
	if result != nil && result.Authenticated {
		view.Auth().Runtime.Authorized = true

		return definitions.AuthResultOK
	}

	return definitions.AuthResultFail
}

type panicResponseWriter struct{}

func (panicResponseWriter) OK(*gin.Context, *StateView) {
	panic("unexpected HTTP OK rendering")
}

func (panicResponseWriter) Fail(*gin.Context, *StateView) {
	panic("unexpected HTTP failure rendering")
}

func (panicResponseWriter) TempFail(*gin.Context, *StateView, string) {
	panic("unexpected HTTP tempfail rendering")
}
