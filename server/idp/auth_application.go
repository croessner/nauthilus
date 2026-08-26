// Copyright (C) 2026 Christian Rößner
// SPDX-License-Identifier: GPL-3.0-or-later

package idp

import (
	"fmt"
	"net"
	"strings"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
)

const (
	idpAuthApplicationEntryPointField = "entry_point"
	idpAuthApplicationListener        = "http.idp"
	idpAuthApplicationUnsupported     = "unsupported"
)

// idpAuthApplicationRequest contains one host-selected authentication or identity operation.
type idpAuthApplicationRequest struct {
	attributeRequest *core.IdentityAttributeRequest
	protocolContext  core.IDPRequestContext
	backendRef       core.RemoteBackendRef
	username         string
	password         string
	oidcClientID     string
	samlEntityID     string
	protocol         string
	entryPoint       core.AuthnEntryPoint
}

// idpAuthApplicationBridge adapts IdP operations to the shared authentication application boundary.
type idpAuthApplicationBridge struct {
	application core.AuthApplicationService
	deps        *deps.Deps
}

// MFAIdentityLookupRequest contains bounded host-owned input for a specialized factor-backend lookup.
type MFAIdentityLookupRequest struct {
	ProtocolContext core.IDPRequestContext
	BackendRef      core.RemoteBackendRef
	Username        string
	Protocol        string
	OIDCClientID    string
	SAMLEntityID    string
}

// MFAIdentityLookup contains admitted identity data and its non-evaluating specialized state.
type MFAIdentityLookup struct {
	User      *backend.User
	AuthState *core.AuthState
}

// newIDPAuthApplicationBridge binds one IdP instance to its injected shared application service.
func newIDPAuthApplicationBridge(d *deps.Deps) *idpAuthApplicationBridge {
	bridge := &idpAuthApplicationBridge{deps: d}
	if d != nil {
		bridge.application = d.AuthApplication
	}

	return bridge
}

// authenticate invokes the admitted password-authentication operation exactly once.
func (b *idpAuthApplicationBridge) authenticate(
	ctx *gin.Context,
	request idpAuthApplicationRequest,
) (*core.AuthOutcome, core.AuthInput, error) {
	return b.run(ctx, core.AuthModeAuthenticate, request)
}

// lookupIdentity invokes the admitted no-password identity operation exactly once.
func (b *idpAuthApplicationBridge) lookupIdentity(
	ctx *gin.Context,
	request idpAuthApplicationRequest,
) (*core.AuthOutcome, core.AuthInput, error) {
	return b.run(ctx, core.AuthModeLookupIdentity, request)
}

// run validates and invokes exactly one shared application operation.
func (b *idpAuthApplicationBridge) run(
	ctx *gin.Context,
	mode core.AuthMode,
	request idpAuthApplicationRequest,
) (*core.AuthOutcome, core.AuthInput, error) {
	input, err := b.input(ctx, mode, request)
	if err != nil {
		return nil, core.AuthInput{}, err
	}

	switch mode {
	case core.AuthModeAuthenticate:
		outcome, callErr := b.application.Authenticate(ctx.Request.Context(), input)

		return outcome, input, callErr
	case core.AuthModeLookupIdentity:
		outcome, callErr := b.application.LookupIdentity(ctx.Request.Context(), input)

		return outcome, input, callErr
	default:
		return nil, core.AuthInput{}, &core.AuthInputError{Field: "mode", Reason: idpAuthApplicationUnsupported}
	}
}

// input builds one detached transport-neutral application request from server-observed values.
func (b *idpAuthApplicationBridge) input(
	ctx *gin.Context,
	mode core.AuthMode,
	request idpAuthApplicationRequest,
) (core.AuthInput, error) {
	if err := b.validate(ctx, mode, request); err != nil {
		return core.AuthInput{}, err
	}

	credentials := core.NewCredentials(core.WithUsername(request.username))
	method := ""

	if mode == core.AuthModeAuthenticate {
		credentials = core.NewCredentials(
			core.WithUsername(request.username),
			core.WithPassword(secret.New(request.password)),
		)
		method = definitions.AuthMethodPassword
	}

	return core.AuthInput{
		Credentials:   credentials,
		Context:       b.authContext(ctx, request, method),
		IDP:           core.NewAuthIDPContext(request.protocolContext, request.attributeRequest, request.backendRef),
		CorrelationID: ctx.GetString(definitions.CtxGUIDKey),
		Mode:          mode,
		EntryPoint:    request.entryPoint,
		Service:       definitions.ServIDP,
	}, nil
}

// validate rejects missing dependencies, ambiguous protocol bindings, and unsupported host entry selections.
func (b *idpAuthApplicationBridge) validate(
	ctx *gin.Context,
	mode core.AuthMode,
	request idpAuthApplicationRequest,
) error {
	if b == nil || b.deps == nil || b.application == nil {
		return fmt.Errorf("%w: idp auth application", core.ErrAuthApplicationDependencyMissing)
	}

	if b.deps.Cfg == nil {
		return fmt.Errorf("%w: cfg", core.ErrAuthApplicationDependencyMissing)
	}

	if ctx == nil || ctx.Request == nil {
		return fmt.Errorf("idp auth application requires an HTTP request")
	}

	if strings.TrimSpace(request.username) == "" {
		return &core.AuthInputError{Field: "username", Reason: "required"}
	}

	if request.oidcClientID != "" && request.samlEntityID != "" {
		return fmt.Errorf("idp auth application protocol binding is ambiguous")
	}

	if !idpEntrySupportsOperation(request.entryPoint, mode) {
		return &core.AuthInputError{Field: idpAuthApplicationEntryPointField, Reason: "unsupported"}
	}

	return validateIDPEntryBinding(request)
}

// authContext maps safe request and protocol facts without carrying browser state.
func (b *idpAuthApplicationBridge) authContext(
	ctx *gin.Context,
	request idpAuthApplicationRequest,
	method string,
) core.AuthContext {
	clientIP, clientPort, peer := b.clientEndpoint(ctx)
	localIP, localPort := splitIDPEndpoint(ctx.Request.Host)
	protocol := idpApplicationProtocol(request)
	passwordHeader, encodedPasswordHeader := b.credentialHeaderNames()

	return core.NewAuthContext(
		core.WithMethod(method),
		core.WithUserAgent(ctx.Request.UserAgent()),
		core.WithClientIP(clientIP),
		core.WithClientPort(clientPort),
		core.WithLocalIP(localIP),
		core.WithLocalPort(localPort),
		core.WithProtocol(protocol),
		core.WithOIDCCID(request.oidcClientID),
		core.WithSAMLEntityID(request.samlEntityID),
		core.WithAuthTransportContext(core.AuthTransportContext{
			Kind:       definitions.ServIDP,
			Listener:   idpAuthApplicationListener,
			HTTPMethod: ctx.Request.Method,
			HTTPRoute:  idpApplicationRoute(ctx),
			Peer:       peer,
			Protected:  ctx.Request.TLS != nil,
		}),
		core.WithRequestMetadata(core.SanitizeHTTPMetadata(
			ctx.Request.Header,
			passwordHeader,
			encodedPasswordHeader,
		)),
	)
}

// clientEndpoint returns trusted client facts and the immediate peer independently.
func (b *idpAuthApplicationBridge) clientEndpoint(ctx *gin.Context) (string, string, string) {
	peer, port := splitIDPEndpoint(ctx.Request.RemoteAddr)
	clientIP := util.RequestClientIPWithConfig(ctx, b.deps.Cfg, b.deps.Logger)

	if clientIP == "" {
		clientIP = peer
	}

	return clientIP, port, peer
}

// credentialHeaderNames returns configured password-bearing headers for metadata exclusion.
func (b *idpAuthApplicationBridge) credentialHeaderNames() (string, string) {
	if b == nil || b.deps == nil || b.deps.Cfg == nil {
		return "", ""
	}

	return b.deps.Cfg.GetPassword(), b.deps.Cfg.GetPasswordEncoded()
}

// splitIDPEndpoint separates one observed host and optional port without forwarded-header interpretation.
func splitIDPEndpoint(address string) (string, string) {
	trimmed := strings.TrimSpace(address)

	host, port, err := net.SplitHostPort(trimmed)
	if err == nil {
		return strings.TrimSpace(host), strings.TrimSpace(port)
	}

	return trimmed, ""
}

// idpApplicationRoute returns the matched route or its request-path fallback.
func idpApplicationRoute(ctx *gin.Context) string {
	if route := ctx.FullPath(); route != "" {
		return route
	}

	if ctx.Request.URL != nil {
		return ctx.Request.URL.Path
	}

	return ""
}

// idpApplicationProtocol derives the concrete protocol from a host binding.
func idpApplicationProtocol(request idpAuthApplicationRequest) string {
	if protocol := strings.TrimSpace(request.protocol); protocol != "" {
		return protocol
	}

	if request.oidcClientID != "" {
		return definitions.ProtoOIDC
	}

	if request.samlEntityID != "" {
		return definitions.ProtoSAML
	}

	return definitions.ProtoIDP
}

// idpEntrySupportsOperation enforces the closed host entry and operation matrix before application admission.
func idpEntrySupportsOperation(entryPoint core.AuthnEntryPoint, mode core.AuthMode) bool {
	switch entryPoint {
	case core.AuthnEntryIDPInternal,
		core.AuthnEntryIDPOIDCAuthorizationCode,
		core.AuthnEntryIDPOIDCDeviceCode,
		core.AuthnEntryIDPSAML:
		return mode == core.AuthModeAuthenticate || mode == core.AuthModeLookupIdentity
	case core.AuthnEntryIDPDelayedIdentity,
		core.AuthnEntryIDPMasterFactor,
		core.AuthnEntryIDPMFABackend:
		return mode == core.AuthModeLookupIdentity
	default:
		return false
	}
}

// validateIDPEntryBinding proves the host-selected entry agrees with the bounded protocol identity.
func validateIDPEntryBinding(request idpAuthApplicationRequest) error {
	switch request.entryPoint {
	case core.AuthnEntryIDPInternal:
		return validateInternalIDPEntryBinding(request)
	case core.AuthnEntryIDPOIDCAuthorizationCode:
		return validateOIDCIDPEntryBinding(request, definitions.OIDCFlowAuthorizationCode, "authorization-code")
	case core.AuthnEntryIDPOIDCDeviceCode:
		return validateOIDCIDPEntryBinding(request, definitions.OIDCFlowDeviceCode, "device-code")
	case core.AuthnEntryIDPSAML:
		return validateSAMLIDPEntryBinding(request)
	case core.AuthnEntryIDPDelayedIdentity, core.AuthnEntryIDPMasterFactor:
		return validateProtocolBoundIDPEntryBinding(request)
	case core.AuthnEntryIDPMFABackend:
		// MFA backend lookup may be protocol-bound or internal, but never ambiguous.
		return nil
	default:
		return &core.AuthInputError{Field: idpAuthApplicationEntryPointField, Reason: idpAuthApplicationUnsupported}
	}
}

// validateInternalIDPEntryBinding rejects external protocol identities on the internal entry.
func validateInternalIDPEntryBinding(request idpAuthApplicationRequest) error {
	if request.oidcClientID != "" || request.samlEntityID != "" {
		return fmt.Errorf("internal idp entry has an external protocol binding")
	}

	return nil
}

// validateOIDCIDPEntryBinding requires one OIDC client and its exact grant family.
func validateOIDCIDPEntryBinding(request idpAuthApplicationRequest, grantType string, label string) error {
	if request.oidcClientID == "" || request.samlEntityID != "" || request.protocolContext.GrantType != grantType {
		return fmt.Errorf("OIDC %s entry binding is incomplete", label)
	}

	return nil
}

// validateSAMLIDPEntryBinding requires one SAML service-provider identity only.
func validateSAMLIDPEntryBinding(request idpAuthApplicationRequest) error {
	if request.samlEntityID == "" || request.oidcClientID != "" {
		return fmt.Errorf("SAML entry binding is incomplete")
	}

	return nil
}

// validateProtocolBoundIDPEntryBinding requires exactly one external protocol identity.
func validateProtocolBoundIDPEntryBinding(request idpAuthApplicationRequest) error {
	if (request.oidcClientID == "") == (request.samlEntityID == "") {
		return fmt.Errorf("protocol-bound idp identity entry is incomplete")
	}

	return nil
}

// idpAuthenticationEntry selects a closed authenticate profile from host-owned protocol state.
func idpAuthenticationEntry(oidcClientID string, samlEntityID string, request core.IDPRequestContext) (core.AuthnEntryPoint, error) {
	if oidcClientID != "" {
		switch request.GrantType {
		case definitions.OIDCFlowAuthorizationCode:
			return core.AuthnEntryIDPOIDCAuthorizationCode, nil
		case definitions.OIDCFlowDeviceCode:
			return core.AuthnEntryIDPOIDCDeviceCode, nil
		default:
			return core.AuthnEntryDefault, fmt.Errorf("unsupported OIDC authentication flow %q", request.GrantType)
		}
	}

	if samlEntityID != "" {
		return core.AuthnEntryIDPSAML, nil
	}

	return core.AuthnEntryIDPInternal, nil
}

// idpOIDCLookupEntry selects a closed OIDC identity profile from host-owned flow state.
func idpOIDCLookupEntry(request core.IDPRequestContext) (core.AuthnEntryPoint, error) {
	switch request.GrantType {
	case definitions.OIDCFlowAuthorizationCode:
		return core.AuthnEntryIDPOIDCAuthorizationCode, nil
	case definitions.OIDCFlowDeviceCode:
		return core.AuthnEntryIDPOIDCDeviceCode, nil
	default:
		return core.AuthnEntryDefault, fmt.Errorf("unsupported OIDC identity flow %q", request.GrantType)
	}
}

// backendUserFromAuthOutcome maps one successful detached application outcome to IdP identity data.
func backendUserFromAuthOutcome(outcome *core.AuthOutcome) (*backend.User, error) {
	if outcome == nil || outcome.Decision != core.AuthDecisionOK || strings.TrimSpace(outcome.Account) == "" {
		return nil, fmt.Errorf("idp identity lookup did not return a successful account")
	}

	return backendUserFromOutcomeIdentity(outcome), nil
}

// backendUserFromOutcomeIdentity detaches all identity values from one application outcome.
func backendUserFromOutcomeIdentity(outcome *core.AuthOutcome) *backend.User {
	if outcome == nil || strings.TrimSpace(outcome.Account) == "" {
		return nil
	}

	user := backend.NewUser(outcome.Account, outcome.DisplayName, outcome.UniqueUserID)
	user.Attributes = outcome.Attributes.Clone()
	user.Groups = append([]string(nil), outcome.Groups...)
	user.GroupDistinguishedNames = append([]string(nil), outcome.GroupDistinguishedNames...)
	user.TOTPSecretField = outcome.TOTPSecretField
	user.TOTPRecoveryField = outcome.TOTPRecoveryField

	return user
}

// authFailureFromOutcome maps one detached terminal application outcome to the IdP response boundary.
func authFailureFromOutcome(outcome *core.AuthOutcome) error {
	if outcome == nil {
		return core.ErrAuthOutcomeMissing
	}

	if outcome.Decision == core.AuthDecisionOK {
		return nil
	}

	if outcome.Decision != core.AuthDecisionFail && outcome.Decision != core.AuthDecisionTempFail {
		return fmt.Errorf("idp authentication returned unsupported decision %q", outcome.Decision)
	}

	return NewAuthFailureError(
		fmt.Errorf("authentication failed with decision: %s", outcome.Decision),
		AuthFailureStatus{
			MessageResolver:         outcome.MessageResolver,
			StatusMessage:           outcome.StatusMessage,
			I18NKey:                 outcome.StatusMessageI18NKey,
			ResponseLanguage:        outcome.ResponseLanguage,
			PolicyTerminal:          outcome.PolicyTerminal,
			DelayedResponseEligible: outcome.DelayedResponseEligible,
		},
	)
}

// LookupMFAIdentity admits an identity lookup before materializing specialized factor-backend state.
func (n *NauthilusIDP) LookupMFAIdentity(
	ctx *gin.Context,
	request MFAIdentityLookupRequest,
) (MFAIdentityLookup, error) {
	if n == nil || n.authApplication == nil {
		return MFAIdentityLookup{}, fmt.Errorf("%w: idp auth application", core.ErrAuthApplicationDependencyMissing)
	}

	applicationRequest := idpAuthApplicationRequest{
		protocolContext: request.ProtocolContext,
		backendRef:      request.BackendRef,
		username:        request.Username,
		oidcClientID:    request.OIDCClientID,
		samlEntityID:    request.SAMLEntityID,
		protocol:        request.Protocol,
		entryPoint:      core.AuthnEntryIDPMFABackend,
	}

	outcome, input, err := n.authApplication.lookupIdentity(ctx, applicationRequest)
	if err != nil {
		return MFAIdentityLookup{}, err
	}

	user, err := backendUserFromAuthOutcome(outcome)
	if err != nil {
		return MFAIdentityLookup{}, err
	}

	authState, err := core.NewIDPSpecializedAuthState(ctx, n.deps.Auth(), input, outcome)
	if err != nil {
		return MFAIdentityLookup{}, err
	}

	return MFAIdentityLookup{User: user, AuthState: authState}, nil
}
