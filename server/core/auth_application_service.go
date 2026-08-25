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

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/model/authdto"
	"github.com/croessner/nauthilus/v3/server/util"
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

	authModeNoAuth = "no-auth"
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

const (
	authInputFieldMode            = "mode"
	authInputFieldUsername        = "username"
	authInputReasonRequired       = "required"
	authInputReasonUnsupported    = "unsupported"
	authResponseJSONErrorsKey     = "errors"
	authStatusMessageOK           = "OK"
	authUnsupportedAuthorization  = "missing or invalid authorization header"
	claimAddressFormatted         = "formatted"
	claimGroupDistinguishedNames  = definitions.LuaBackendResultGroupDistinguishedNames
	defaultClientIPAny            = "0.0.0.0"
	ldapAttributeObjectClass      = "objectClass"
	rblReasonDNSSuchHost          = "dns_no_such_host"
	webAuthnDebugAAGUID           = "aaguid"
	webAuthnDebugCredentialIDHash = "credential_id_hash"
	webAuthnDebugFlagsUP          = "flags_up"
	webAuthnDebugFlagsUV          = "flags_uv"
	webAuthnDebugIsResidentKey    = "is_resident_key"
	webAuthnDebugSignCount        = "sign_count"
	webAuthnDebugSignCountZero    = "sign_count_zero"
)

// AuthInput contains transport-neutral authentication input.
type AuthInput struct {
	Credentials        Credentials
	Context            AuthContext
	CorrelationID      string
	Mode               AuthMode
	Service            string
	AuthLoginAttempt   uint
	DisableMemoryCache bool
	DisableCache       bool
}

// AuthResponseSettings snapshots config-derived response inputs from one runtime generation.
type AuthResponseSettings struct {
	SMTPBackendAddress  string
	IMAPBackendAddress  string
	POP3BackendAddress  string
	DefaultLanguage     string
	InstanceName        string
	SMTPBackendPort     int
	IMAPBackendPort     int
	POP3BackendPort     int
	NginxWaitDelay      uint
	BackendHealthChecks bool
	Captured            bool
}

// AuthOutcome contains the captured terminal authentication result.
type AuthOutcome struct {
	Attributes              bktype.AttributeMapping
	ResponseHeaders         http.Header
	ResponseHeaderDeletes   []string
	FSMEventPath            []string
	ResponseSettings        AuthResponseSettings
	Decision                AuthDecision
	TerminalState           string
	Session                 string
	Account                 string
	AccountField            string
	TOTPSecretField         string
	TOTPRecoveryField       string
	UniqueUserIDField       string
	DisplayNameField        string
	StatusMessage           string
	StatusMessageI18NKey    string
	ResponseLanguage        string
	Error                   string
	Groups                  []string
	GroupDistinguishedNames []string
	Protocol                string
	UsedBackendIP           string
	Backend                 definitions.Backend
	UsedBackendPort         int
	HTTPStatus              int
	LoginAttempts           uint
	MemoryCacheHit          bool
	DelayedResponseEligible bool
}

// ListAccountsOutcome contains the account-provider response.
type ListAccountsOutcome struct {
	ResponseHeaders         http.Header
	ResponseHeaderDeletes   []string
	FSMEventPath            []string
	Accounts                AccountList
	ResponseSettings        AuthResponseSettings
	Decision                AuthDecision
	TerminalState           string
	Session                 string
	StatusMessage           string
	StatusMessageI18NKey    string
	ResponseLanguage        string
	Error                   string
	Protocol                string
	HTTPStatus              int
	LoginAttempts           uint
	MemoryCacheHit          bool
	DelayedResponseEligible bool
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
	executor *legacyAuthApplicationExecutor
	deps     AuthDeps
}

// NewAuthApplicationService constructs the transport-neutral auth service.
func NewAuthApplicationService(deps AuthDeps) AuthApplicationService {
	return &authApplicationService{
		executor: newLegacyAuthApplicationExecutor(),
		deps:     deps,
	}
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

	if captured := capture.Outcome(); captured.Decision != CapturedAuthDecisionUnset {
		return listAccountsOutcomeFromCaptured(captured), nil
	}

	return listAccountsSuccessOutcome(auth, ginCtx, accounts), nil
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
		return &AuthInputError{Field: "password", Reason: authInputReasonRequired}
	}

	return nil
}

func validateLookupIdentityInput(input AuthInput) error {
	if requestTransportKindForService(input.Service) == requestPolicyTransportHTTP {
		return nil
	}

	return validateUsernameInput(input)
}

func validateUsernameInput(input AuthInput) error {
	if input.Credentials.Username == "" {
		return &AuthInputError{Field: authInputFieldUsername, Reason: authInputReasonRequired}
	}

	if !util.ValidateUsername(input.Credentials.Username) {
		return &AuthInputError{Field: authInputFieldUsername, Reason: "invalid"}
	}

	return nil
}

func (s *authApplicationService) effectiveDeps() (AuthDeps, error) {
	deps := s.deps
	if deps.CurrentConfig != nil {
		deps.Cfg = deps.CurrentConfig()
	}

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

func authOutcomeFromCaptured(captured CapturedAuthOutcome) *AuthOutcome {
	return &AuthOutcome{
		Attributes:              captured.Attributes,
		ResponseHeaders:         captured.ResponseHeaders.Clone(),
		ResponseHeaderDeletes:   append([]string(nil), captured.ResponseHeaderDeletes...),
		FSMEventPath:            append([]string(nil), captured.FSMEventPath...),
		ResponseSettings:        captured.ResponseSettings,
		Decision:                authDecisionFromCaptured(captured.Decision),
		TerminalState:           captured.TerminalState,
		Session:                 captured.Session,
		Account:                 captured.Account,
		AccountField:            captured.AccountField,
		TOTPSecretField:         captured.TOTPSecretField,
		TOTPRecoveryField:       captured.TOTPRecoveryField,
		UniqueUserIDField:       captured.UniqueUserIDField,
		DisplayNameField:        captured.DisplayNameField,
		StatusMessage:           captured.StatusMessage,
		StatusMessageI18NKey:    captured.StatusMessageI18NKey,
		ResponseLanguage:        captured.ResponseLanguage,
		Error:                   captured.Error,
		Groups:                  append([]string(nil), captured.Groups...),
		GroupDistinguishedNames: append([]string(nil), captured.GroupDistinguishedNames...),
		Protocol:                captured.Protocol,
		UsedBackendIP:           captured.UsedBackendIP,
		Backend:                 captured.Backend,
		UsedBackendPort:         captured.UsedBackendPort,
		HTTPStatus:              captured.HTTPStatus,
		LoginAttempts:           captured.LoginAttempts,
		MemoryCacheHit:          captured.MemoryCacheHit,
		DelayedResponseEligible: captured.DelayedResponseEligible,
	}
}

func listAccountsOutcomeFromCaptured(captured CapturedAuthOutcome) *ListAccountsOutcome {
	return &ListAccountsOutcome{
		ResponseHeaders:         captured.ResponseHeaders.Clone(),
		ResponseHeaderDeletes:   append([]string(nil), captured.ResponseHeaderDeletes...),
		FSMEventPath:            append([]string(nil), captured.FSMEventPath...),
		ResponseSettings:        captured.ResponseSettings,
		Decision:                authDecisionFromCaptured(captured.Decision),
		TerminalState:           captured.TerminalState,
		Session:                 captured.Session,
		StatusMessage:           captured.StatusMessage,
		StatusMessageI18NKey:    captured.StatusMessageI18NKey,
		ResponseLanguage:        captured.ResponseLanguage,
		Error:                   captured.Error,
		Protocol:                captured.Protocol,
		HTTPStatus:              captured.HTTPStatus,
		LoginAttempts:           captured.LoginAttempts,
		MemoryCacheHit:          captured.MemoryCacheHit,
		DelayedResponseEligible: captured.DelayedResponseEligible,
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
