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

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/model/authdto"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/util"
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

// AuthIDPRequestContext carries protocol facts while excluding browser-owned MFA state.
type AuthIDPRequestContext struct {
	RequestedScopes []string
	GrantType       string
	RedirectURI     string
}

// newAuthIDPRequestContext copies only generic protocol facts from the domain-owned request.
func newAuthIDPRequestContext(request IDPRequestContext) AuthIDPRequestContext {
	return AuthIDPRequestContext{
		RequestedScopes: append([]string(nil), request.RequestedScopes...),
		GrantType:       request.GrantType,
		RedirectURI:     request.RedirectURI,
	}
}

// clone returns a detached copy of the bounded IdP request facts.
func (c AuthIDPRequestContext) clone() AuthIDPRequestContext {
	c.RequestedScopes = append([]string(nil), c.RequestedScopes...)

	return c
}

// toIDPRequestContext reconstructs the compatibility host projection with browser MFA fields unset.
func (c AuthIDPRequestContext) toIDPRequestContext() *IDPRequestContext {
	return &IDPRequestContext{
		GrantType:       c.GrantType,
		RedirectURI:     c.RedirectURI,
		RequestedScopes: append([]string(nil), c.RequestedScopes...),
	}
}

// AuthIDPContext carries only bounded IdP values needed by authentication and identity lookup.
type AuthIDPContext struct {
	IdentityAttributeRequest *IdentityAttributeRequest
	Request                  AuthIDPRequestContext
	ExistingBackendRef       RemoteBackendRef
}

// NewAuthIDPContext constructs a detached IdP application context.
func NewAuthIDPContext(
	request IDPRequestContext,
	identityAttributeRequest *IdentityAttributeRequest,
	existingBackendRef RemoteBackendRef,
) AuthIDPContext {
	return AuthIDPContext{
		IdentityAttributeRequest: identityAttributeRequest.Clone(),
		Request:                  newAuthIDPRequestContext(request),
		ExistingBackendRef:       existingBackendRef,
	}
}

// Clone returns a detached copy of the IdP application context.
func (c AuthIDPContext) Clone() AuthIDPContext {
	return AuthIDPContext{
		IdentityAttributeRequest: c.IdentityAttributeRequest.Clone(),
		Request:                  c.Request.clone(),
		ExistingBackendRef:       c.ExistingBackendRef,
	}
}

// AuthInput contains transport-neutral authentication input.
type AuthInput struct {
	Credentials        Credentials
	Context            AuthContext
	IDP                AuthIDPContext
	CorrelationID      string
	Mode               AuthMode
	EntryPoint         AuthnEntryPoint
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

// authOutcomeProjection owns the shared terminal payload independently of its decision vocabulary.
type authOutcomeProjection[D ~string] struct {
	Attributes              bktype.AttributeMapping
	ResponseHeaders         http.Header
	MessageResolver         localization.MessageResolver
	ResponseHeaderDeletes   []string
	FSMEventPath            []string
	ResponseSettings        AuthResponseSettings
	Decision                D
	TerminalState           string
	Session                 string
	Account                 string
	AccountField            string
	DisplayName             string
	UniqueUserID            string
	TOTPSecretField         string
	TOTPRecoveryField       string
	UniqueUserIDField       string
	DisplayNameField        string
	BackendName             string
	StatusMessage           string
	StatusMessageI18NKey    string
	ResponseLanguage        string
	Error                   string
	Groups                  []string
	GroupDistinguishedNames []string
	Protocol                string
	UsedBackendIP           string
	RemoteBackendRef        RemoteBackendRef
	Backend                 definitions.Backend
	UsedBackendPort         int
	HTTPStatus              int
	LoginAttempts           uint
	MemoryCacheHit          bool
	DelayedResponseEligible bool
	PolicyTerminal          bool
}

// AuthOutcome contains the captured terminal authentication result.
type AuthOutcome = authOutcomeProjection[AuthDecision]

// convertAuthOutcomeProjection changes decision vocabulary while detaching every mutable payload.
func convertAuthOutcomeProjection[S ~string, D ~string](
	input authOutcomeProjection[S],
	decision D,
) authOutcomeProjection[D] {
	return authOutcomeProjection[D]{
		Attributes:              cloneAttributeMapping(input.Attributes),
		ResponseHeaders:         input.ResponseHeaders.Clone(),
		MessageResolver:         input.MessageResolver,
		ResponseHeaderDeletes:   append([]string(nil), input.ResponseHeaderDeletes...),
		FSMEventPath:            append([]string(nil), input.FSMEventPath...),
		ResponseSettings:        input.ResponseSettings,
		Decision:                decision,
		TerminalState:           input.TerminalState,
		Session:                 input.Session,
		Account:                 input.Account,
		AccountField:            input.AccountField,
		DisplayName:             input.DisplayName,
		UniqueUserID:            input.UniqueUserID,
		TOTPSecretField:         input.TOTPSecretField,
		TOTPRecoveryField:       input.TOTPRecoveryField,
		UniqueUserIDField:       input.UniqueUserIDField,
		DisplayNameField:        input.DisplayNameField,
		BackendName:             input.BackendName,
		StatusMessage:           input.StatusMessage,
		StatusMessageI18NKey:    input.StatusMessageI18NKey,
		ResponseLanguage:        input.ResponseLanguage,
		Error:                   input.Error,
		Groups:                  append([]string(nil), input.Groups...),
		GroupDistinguishedNames: append([]string(nil), input.GroupDistinguishedNames...),
		Protocol:                input.Protocol,
		UsedBackendIP:           input.UsedBackendIP,
		RemoteBackendRef:        input.RemoteBackendRef,
		Backend:                 input.Backend,
		UsedBackendPort:         input.UsedBackendPort,
		HTTPStatus:              input.HTTPStatus,
		LoginAttempts:           input.LoginAttempts,
		MemoryCacheHit:          input.MemoryCacheHit,
		DelayedResponseEligible: input.DelayedResponseEligible,
		PolicyTerminal:          input.PolicyTerminal,
	}
}

// ListAccountsOutcome contains the account-provider response.
type ListAccountsOutcome struct {
	ResponseHeaders         http.Header
	MessageResolver         localization.MessageResolver
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
	host *authApplicationHost
	deps AuthDeps
}

// newAuthApplicationServiceHost constructs the private admitted-execution host.
func newAuthApplicationServiceHost(deps AuthDeps) *authApplicationService {
	return &authApplicationService{
		host: newAuthApplicationHost(),
		deps: deps,
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

// normalizeAuthInput applies operation defaults and detaches mutable IdP input values.
func normalizeAuthInput(input AuthInput, defaultMode AuthMode) AuthInput {
	if input.Service == "" {
		input.Service = definitions.ServGRPC
	}

	input.Mode = defaultMode
	input.IDP = input.IDP.Clone()

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

// effectiveDeps resolves configuration only from the captured session or the immutable constructor snapshot.
func (s *authApplicationService) effectiveDeps(ctx context.Context) (AuthDeps, error) {
	deps := s.deps
	if captured, ok := decisionservice.CapturedConfigFromContext(ctx); ok {
		deps.Cfg = captured
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

// authOutcomeFromCaptured detaches the compatibility host capture into the public application result.
func authOutcomeFromCaptured(captured CapturedAuthOutcome) *AuthOutcome {
	outcome := convertAuthOutcomeProjection(captured, authDecisionFromCaptured(captured.Decision))

	return &outcome
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
