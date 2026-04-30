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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/model/authdto"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
	"go.opentelemetry.io/otel/attribute"
)

// AuthMode describes the application-level auth operation.
type AuthMode string

const (
	// AuthModeAuthenticate runs the normal password authentication pipeline.
	AuthModeAuthenticate AuthMode = "auth"
	// AuthModeLookupIdentity runs the trusted identity lookup path without a password.
	AuthModeLookupIdentity AuthMode = "lookup-identity"
	// AuthModeListAccounts runs the account-provider listing path.
	AuthModeListAccounts AuthMode = "list-accounts"
)

// AuthDecision is the terminal application-level authentication decision.
type AuthDecision string

const (
	// AuthDecisionUnset indicates that no terminal decision was produced.
	AuthDecisionUnset AuthDecision = "unset"
	// AuthDecisionOK indicates successful authentication.
	AuthDecisionOK AuthDecision = "ok"
	// AuthDecisionFail indicates a domain authentication failure.
	AuthDecisionFail AuthDecision = "fail"
	// AuthDecisionTempFail indicates a temporary authentication failure.
	AuthDecisionTempFail AuthDecision = "tempfail"
)

// AuthInput contains transport-neutral authentication input.
type AuthInput struct {
	Credentials      Credentials
	Context          AuthContext
	Mode             AuthMode
	Service          string
	AuthLoginAttempt uint
}

// AuthOutcome contains the captured terminal authentication result.
type AuthOutcome struct {
	Attributes      bktype.AttributeMapping
	Decision        AuthDecision
	TerminalState   string
	Session         string
	AccountField    string
	TOTPSecretField string
	StatusMessage   string
	Error           string
	Backend         definitions.Backend
	HTTPStatus      int
}

// ListAccountsOutcome contains the account-provider response.
type ListAccountsOutcome struct {
	Accounts AccountList
	Session  string
}

// AuthApplicationService runs auth use cases behind transport adapters.
type AuthApplicationService interface {
	Authenticate(ctx context.Context, input AuthInput) (*AuthOutcome, error)
	LookupIdentity(ctx context.Context, input AuthInput) (*AuthOutcome, error)
	ListAccounts(ctx context.Context, input AuthInput) (*ListAccountsOutcome, error)
}

// AuthInputError reports an invalid transport-neutral request field.
type AuthInputError struct {
	Field  string
	Reason string
}

type authApplicationContextKey string

const authApplicationOIDCClaimsKey authApplicationContextKey = "oidc_claims"

func (e *AuthInputError) Error() string {
	if e == nil {
		return ""
	}

	if e.Field == "" {
		return e.Reason
	}

	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}

var (
	// ErrAuthApplicationDependencyMissing means the service was built without required dependencies.
	ErrAuthApplicationDependencyMissing = stderrors.New("auth application service dependency missing")
	// ErrAuthOutcomeMissing means the auth FSM returned without a captured terminal outcome.
	ErrAuthOutcomeMissing = stderrors.New("auth application service outcome missing")
)

// AuthPreprocessRejectedError reports a list-accounts preprocessing rejection.
type AuthPreprocessRejectedError struct {
	Outcome *AuthOutcome
}

func (e *AuthPreprocessRejectedError) Error() string {
	return "auth application service preprocessing rejected request"
}

// AuthPermissionDeniedError reports a domain authorization rejection before
// the auth use case can proceed.
type AuthPermissionDeniedError struct {
	Reason string
}

func (e *AuthPermissionDeniedError) Error() string {
	if e == nil || e.Reason == "" {
		return "auth application service permission denied"
	}

	return e.Reason
}

type authApplicationService struct {
	deps AuthDeps
}

// NewAuthApplicationService constructs the transport-neutral auth service.
func NewAuthApplicationService(deps AuthDeps) AuthApplicationService {
	return &authApplicationService{deps: deps}
}

// ContextWithOIDCClaims stores validated backchannel OIDC claims for auth
// application execution that has to preserve existing list-accounts scope checks.
func ContextWithOIDCClaims(ctx context.Context, claims any) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	if claims == nil {
		return ctx
	}

	return context.WithValue(ctx, authApplicationOIDCClaimsKey, claims)
}

// NewAuthInputFromStructuredRequest maps the shared structured auth DTO into
// transport-neutral application input.
func NewAuthInputFromStructuredRequest(service string, mode AuthMode, request authdto.Request) AuthInput {
	if service == "" {
		service = definitions.ServGRPC
	}

	if mode == "" {
		mode = AuthModeAuthenticate
	}

	return AuthInput{
		Credentials:      NewCredentials(buildCredentialOptions(&request)...),
		Context:          NewAuthContext(buildAuthContextOptions(&request)...),
		Mode:             mode,
		Service:          service,
		AuthLoginAttempt: request.AuthLoginAttempt,
	}
}

// Authenticate runs the existing auth FSM and returns a captured outcome.
func (s *authApplicationService) Authenticate(ctx context.Context, input AuthInput) (*AuthOutcome, error) {
	return s.runAuthPipeline(ctx, input, AuthModeAuthenticate, validateAuthenticateInput)
}

// LookupIdentity runs the existing no-auth identity lookup path and returns a captured outcome.
func (s *authApplicationService) LookupIdentity(ctx context.Context, input AuthInput) (*AuthOutcome, error) {
	return s.runAuthPipeline(ctx, input, AuthModeLookupIdentity, validateLookupIdentityInput)
}

func (s *authApplicationService) runAuthPipeline(
	ctx context.Context,
	input AuthInput,
	defaultMode AuthMode,
	validate func(AuthInput) error,
) (*AuthOutcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	input = normalizeAuthInput(input, defaultMode)
	if err := validate(input); err != nil {
		return nil, err
	}

	auth, ginCtx, capture, err := s.newAuthState(ctx, input)
	if err != nil {
		return nil, err
	}

	if reject := auth.PreproccessAuthRequest(ginCtx); reject {
		return authOutcomeFromCaptured(capture.Outcome()), nil
	}

	auth.HandleAuthentication(ginCtx)

	outcome := authOutcomeFromCaptured(capture.Outcome())
	if outcome.Decision == AuthDecisionUnset {
		return nil, ErrAuthOutcomeMissing
	}

	return outcome, nil
}

// ListAccounts runs the existing account-provider backend path without HTTP rendering.
func (s *authApplicationService) ListAccounts(ctx context.Context, input AuthInput) (*ListAccountsOutcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	input = normalizeAuthInput(input, AuthModeListAccounts)

	auth, ginCtx, capture, err := s.newAuthState(ctx, input)
	if err != nil {
		return nil, err
	}

	if !auth.Request.ListAccounts {
		return nil, &AuthPermissionDeniedError{Reason: "missing required scope: " + definitions.ScopeListAccounts}
	}

	if reject := auth.PreproccessAuthRequest(ginCtx); reject {
		return nil, &AuthPreprocessRejectedError{Outcome: authOutcomeFromCaptured(capture.Outcome())}
	}

	accounts := auth.ListUserAccounts()
	_ = level.Info(auth.logger()).Log(definitions.LogKeyGUID, auth.Runtime.GUID, definitions.LogKeyMode, string(AuthModeListAccounts))

	return &ListAccountsOutcome{
		Accounts: accounts,
		Session:  auth.Runtime.GUID,
	}, nil
}

func normalizeAuthInput(input AuthInput, defaultMode AuthMode) AuthInput {
	if input.Service == "" {
		input.Service = definitions.ServGRPC
	}

	input.Mode = defaultMode

	return input
}

func validateAuthenticateInput(input AuthInput) error {
	if err := validateUsernameInput(input); err != nil {
		return err
	}

	if input.Credentials.Password.IsZero() {
		return &AuthInputError{Field: "password", Reason: "required"}
	}

	return nil
}

func validateLookupIdentityInput(input AuthInput) error {
	return validateUsernameInput(input)
}

func validateUsernameInput(input AuthInput) error {
	if input.Credentials.Username == "" {
		return &AuthInputError{Field: "username", Reason: "required"}
	}

	if !util.ValidateUsername(input.Credentials.Username) {
		return &AuthInputError{Field: "username", Reason: "invalid"}
	}

	return nil
}

func (s *authApplicationService) newAuthState(
	parent context.Context,
	input AuthInput,
) (*AuthState, *gin.Context, *CaptureResponseWriter, error) {
	deps, err := s.effectiveDeps()
	if err != nil {
		return nil, nil, nil, err
	}

	capture := NewDefaultCaptureResponseWriter(ResponseDeps{
		Cfg:    deps.Cfg,
		Env:    deps.Env,
		Logger: deps.Logger,
	})
	deps.Resp = capture

	tr := monittrace.New("nauthilus/auth")
	setupCtx, span := tr.Start(parent, "auth.setup",
		attribute.String("service", input.Service),
		attribute.String("mode", string(input.Mode)),
	)

	defer span.End()

	ginCtx := newApplicationGinContext(setupCtx, input)
	auth := NewAuthStateFromContextWithDeps(ginCtx, deps).(*AuthState)
	auth.SetProtocol(&config.Protocol{})
	auth.ApplyCredentials(input.Credentials)
	auth.ApplyContextData(input.Context)

	if input.AuthLoginAttempt > 0 {
		auth.SyncLoginAttemptsFromAttemptOrdinal(input.AuthLoginAttempt)
	}

	auth.postResolvDNS(ginCtx.Request.Context())
	auth.InitMethodAndUserAgent()
	auth.WithDefaults(ginCtx)
	auth.SetStatusCodes(input.Service)
	auth.SetOperationMode(ginCtx)
	auth.traceSetupDetails(span)
	logProcessingRequest(ginCtx, auth)

	return auth, ginCtx, capture, nil
}

func (s *authApplicationService) effectiveDeps() (AuthDeps, error) {
	deps := s.deps
	if deps.Cfg == nil {
		return AuthDeps{}, fmt.Errorf("%w: cfg", ErrAuthApplicationDependencyMissing)
	}

	if deps.Env == nil {
		return AuthDeps{}, fmt.Errorf("%w: env", ErrAuthApplicationDependencyMissing)
	}

	if deps.Redis == nil {
		return AuthDeps{}, fmt.Errorf("%w: redis", ErrAuthApplicationDependencyMissing)
	}

	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}

	return deps, nil
}

func newApplicationGinContext(parent context.Context, input AuthInput) *gin.Context {
	path := "/grpc/auth/v1/Authenticate"
	switch input.Mode {
	case AuthModeLookupIdentity:
		path = "/grpc/auth/v1/LookupIdentity?mode=no-auth"
	case AuthModeListAccounts:
		path = "/grpc/auth/v1/ListAccounts?mode=list-accounts"
	}

	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(http.MethodPost, path, http.NoBody).WithContext(parent)
	ginCtx.Set(definitions.CtxCategoryKey, definitions.CatAuth)
	ginCtx.Set(definitions.CtxServiceKey, input.Service)
	ginCtx.Set(definitions.CtxGUIDKey, ksuid.New().String())
	ginCtx.Set(definitions.CtxLocalCacheAuthKey, false)
	ginCtx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
	if claims := parent.Value(authApplicationOIDCClaimsKey); claims != nil {
		ginCtx.Set(definitions.CtxOIDCClaimsKey, claims)
	}

	return ginCtx
}

func authOutcomeFromCaptured(captured CapturedAuthOutcome) *AuthOutcome {
	return &AuthOutcome{
		Attributes:      captured.Attributes,
		Decision:        authDecisionFromCaptured(captured.Decision),
		TerminalState:   captured.TerminalState,
		Session:         captured.Session,
		AccountField:    captured.AccountField,
		TOTPSecretField: captured.TOTPSecretField,
		StatusMessage:   captured.StatusMessage,
		Error:           captured.Error,
		Backend:         captured.Backend,
		HTTPStatus:      captured.HTTPStatus,
	}
}

func authDecisionFromCaptured(decision CapturedAuthDecision) AuthDecision {
	switch decision {
	case CapturedAuthDecisionOK:
		return AuthDecisionOK
	case CapturedAuthDecisionFail:
		return AuthDecisionFail
	case CapturedAuthDecisionTempFail:
		return AuthDecisionTempFail
	default:
		return AuthDecisionUnset
	}
}
