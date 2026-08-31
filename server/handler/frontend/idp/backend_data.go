package idp

import (
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/idp"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/model/mfa"
	"github.com/gin-gonic/gin"
)

// UserBackendData encapsulates information about a user's MFA status and backend data.
type UserBackendData struct {
	Username         string
	DisplayName      string
	UniqueUserID     string
	HaveTOTP         bool
	NumRecoveryCodes int
	HaveWebAuthn     bool
	WebAuthnUser     *backend.User
	AuthState        *core.AuthState
}

// UsesRemoteWebAuthnAuthority reports whether WebAuthn writes must stay authority-owned.
func (d *UserBackendData) UsesRemoteWebAuthnAuthority() bool {
	if d == nil || d.AuthState == nil {
		return false
	}

	return d.AuthState.Runtime.UsedPassDBBackend == definitions.BackendRemote ||
		!d.AuthState.Runtime.RemoteBackendRef.IsZero()
}

type webAuthnCredentialProvider interface {
	GetWebAuthnCredentials() ([]mfa.PersistentCredential, error)
}

type selectedBackendWebAuthnProvider struct {
	state *core.AuthState
}

// newBackendDataLookupRequest maps one bounded protocol context to the shared IdP application request.
func newBackendDataLookupRequest(
	username string,
	backendRef core.RemoteBackendRef,
	protocolContext core.IDPMFAProtocolContext,
) idp.MFAIdentityLookupRequest {
	return idp.MFAIdentityLookupRequest{
		ProtocolContext: protocolContext.Request,
		BackendRef:      backendRef,
		Username:        username,
		Protocol:        protocolContext.Protocol,
		OIDCClientID:    protocolContext.OIDCClientID,
		SAMLEntityID:    protocolContext.SAMLEntityID,
	}
}

// backendDataProtocolContext maps only protocol facts from a typed flow state.
func backendDataProtocolContext(
	state *flowdomain.State,
	fallbackProtocol string,
) core.IDPMFAProtocolContext {
	result := core.IDPMFAProtocolContext{Protocol: fallbackProtocol}
	if state == nil {
		return result
	}

	result.Protocol = string(state.Protocol)
	if state.Protocol == flowdomain.FlowProtocolInternal {
		result.Protocol = definitions.ProtoIDP
	}

	result.Request = core.IDPRequestContext{
		GrantType:       state.GrantType,
		RedirectURI:     state.Metadata[flowdomain.FlowMetadataRedirectURI],
		RequestedScopes: strings.Fields(state.Metadata[flowdomain.FlowMetadataScope]),
	}

	switch state.Protocol {
	case flowdomain.FlowProtocolOIDC:
		result.OIDCClientID = state.Metadata[flowdomain.FlowMetadataClientID]
	case flowdomain.FlowProtocolSAML:
		result.SAMLEntityID = state.Metadata[flowdomain.FlowMetadataSAMLEntityID]
	case flowdomain.FlowProtocolInternal:
	}

	return result
}

func (p selectedBackendWebAuthnProvider) GetWebAuthnCredentials() ([]mfa.PersistentCredential, error) {
	if p.state == nil {
		return nil, errors.ErrUnknownDatabaseBackend
	}

	return p.state.GetWebAuthnCredentialsFromSelectedBackend()
}

// GetUserBackendData performs backend lookups and returns encapsulated user data.
func (h *FrontendHandler) GetUserBackendData(ctx *gin.Context) (*UserBackendData, error) {
	username := h.backendDataUsername(ctx)
	if username == "" {
		return nil, nil
	}

	return h.getUserBackendDataForIdentity(
		ctx,
		newBackendDataLookupRequest(
			username,
			core.RemoteBackendRef{},
			core.IDPMFAProtocolContext{Protocol: definitions.ProtoIDP},
		),
	)
}

// getUserBackendDataForIdentity performs a no-auth lookup for one identity and
// materializes only the specialized state needed by MFA backend operations.
func (h *FrontendHandler) getUserBackendDataForIdentity(
	ctx *gin.Context,
	request idp.MFAIdentityLookupRequest,
) (*UserBackendData, error) {
	lookupCtx, restore := backendDataLookupContext(ctx)
	defer restore()

	lookup, err := idp.NewNauthilusIDP(h.deps).LookupMFAIdentity(lookupCtx, request)
	if err != nil {
		return nil, err
	}

	data := newUserBackendData(lookup.User, lookup.AuthState)

	if err = h.applyBackendMFAData(lookupCtx, data, lookup.AuthState); err != nil {
		return nil, err
	}

	return data, nil
}

// backendDataLookupContext prevents no-auth backend-data lookups from parsing
// the body of the request that triggered the lookup, such as a WebAuthn finish
// JSON payload that has already been consumed by the assertion verifier.
func backendDataLookupContext(ctx *gin.Context) (*gin.Context, func()) {
	restore := func() {}
	if ctx == nil || ctx.Request == nil {
		return ctx, restore
	}

	contentType := ctx.GetHeader("Content-Type")
	if ctx.Request.Method != http.MethodPost ||
		!strings.HasPrefix(contentType, "application/json") && !strings.HasPrefix(contentType, "application/cbor") {
		return ctx, restore
	}

	originalRequest := ctx.Request
	originalMutationDisabled := ctx.GetBool(definitions.CtxPluginResponseMutationDisabledKey)
	request := originalRequest.Clone(originalRequest.Context())
	request.Method = http.MethodGet
	request.Body = http.NoBody
	request.ContentLength = 0
	request.Header = request.Header.Clone()
	request.Header.Del("Content-Type")
	ctx.Request = request
	ctx.Set(definitions.CtxPluginResponseMutationDisabledKey, true)

	restore = func() {
		ctx.Request = originalRequest
		ctx.Set(definitions.CtxPluginResponseMutationDisabledKey, originalMutationDisabled)
	}

	return ctx, restore
}

// backendDataUsername resolves the backend-data username from canonical state or bearer token.
func (h *FrontendHandler) backendDataUsername(ctx *gin.Context) string {
	if session := cookie.GetCanonicalSession(ctx); session != nil {
		if identity, authenticated := session.Identity(); authenticated {
			return identity.Account
		}
	}

	return h.backendDataUsernameFromBearer(ctx)
}

// backendDataUsernameFromBearer resolves the subject claim from a bearer token.
func (h *FrontendHandler) backendDataUsernameFromBearer(ctx *gin.Context) string {
	tokenString, ok := strings.CutPrefix(ctx.GetHeader("Authorization"), "Bearer ")
	if !ok {
		return ""
	}

	idpInstance := idp.NewNauthilusIDP(h.deps)

	claims, err := idpInstance.ValidateToken(ctx.Request.Context(), tokenString)
	if err != nil {
		return ""
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return ""
	}

	return sub
}

// newUserBackendData creates the backend-data DTO from an admitted detached identity.
func newUserBackendData(user *backend.User, authState *core.AuthState) *UserBackendData {
	if user == nil {
		return nil
	}

	return &UserBackendData{
		Username:     user.Name,
		DisplayName:  user.DisplayName,
		UniqueUserID: user.ID,
		AuthState:    authState,
	}
}

// applyBackendMFAData fills MFA state from public backends or legacy AuthState fields.
func (h *FrontendHandler) applyBackendMFAData(
	ctx *gin.Context,
	data *UserBackendData,
	authState *core.AuthState,
) error {
	loadedPublicMFA, err := h.applyPublicMFAState(ctx, data, authState)
	if err != nil {
		return err
	}

	if loadedPublicMFA {
		return nil
	}

	h.applyLegacyBackendMFAData(ctx, data, authState)

	return nil
}

// applyLegacyBackendMFAData fills MFA state from legacy AuthState getters.
func (h *FrontendHandler) applyLegacyBackendMFAData(
	ctx *gin.Context,
	data *UserBackendData,
	authState *core.AuthState,
) {
	if secret, ok := authState.GetTOTPSecretOk(); ok && secret != "" {
		data.HaveTOTP = true
	}

	codes := authState.GetTOTPRecoveryCodes()
	data.NumRecoveryCodes = len(codes)

	h.resolveWebAuthnUser(ctx, data, selectedBackendWebAuthnProvider{state: authState})
}

func (h *FrontendHandler) applyPublicMFAState(ctx *gin.Context, data *UserBackendData, authState *core.AuthState) (bool, error) {
	if h == nil || data == nil || authState == nil {
		return false, nil
	}

	provider, ok := h.publicMFAStateProvider(authState)
	if !ok {
		return false, nil
	}

	state, err := provider.GetPublicMFAState(authState, true)
	if err != nil {
		return true, err
	}

	data.HaveTOTP = state.HasTOTP
	data.NumRecoveryCodes = state.RecoveryCodeCount
	data.HaveWebAuthn = state.HasWebAuthn && len(state.WebAuthnCredentials) > 0

	if data.HaveWebAuthn {
		user := &backend.User{
			ID:          data.UniqueUserID,
			Name:        data.Username,
			DisplayName: data.DisplayName,
			Credentials: state.WebAuthnCredentials,
		}
		data.WebAuthnUser = user

		if data.UniqueUserID != "" {
			return true, backend.SaveWebAuthnToRedis(
				ctx.Request.Context(),
				h.deps.Logger,
				h.deps.Cfg,
				h.deps.Redis,
				user,
				h.deps.Cfg.GetServer().GetRedis().GetPosCacheTTL(),
			)
		}

		return true, nil
	}

	if data.UniqueUserID != "" {
		return true, backend.DeleteWebAuthnFromRedis(ctx.Request.Context(), h.deps.Logger, h.deps.Cfg, h.deps.Redis, data.UniqueUserID)
	}

	return true, nil
}

func (h *FrontendHandler) publicMFAStateProvider(authState *core.AuthState) (core.PublicMFAStateProvider, bool) {
	if authState == nil {
		return nil, false
	}

	manager := authState.GetBackendManager(authState.Runtime.UsedPassDBBackend, authState.Runtime.BackendName)
	if manager == nil {
		return nil, false
	}

	provider, ok := manager.(core.PublicMFAStateProvider)

	return provider, ok
}

// resolveWebAuthnUser resolves WebAuthn credentials from cache or backend state.
func (h *FrontendHandler) resolveWebAuthnUser(
	ctx *gin.Context,
	data *UserBackendData,
	provider webAuthnCredentialProvider,
) {
	if data == nil || provider == nil {
		return
	}

	if h.applyCachedWebAuthnUser(ctx, data) {
		return
	}

	credentials, ok := webAuthnCredentialsFromProvider(provider)
	if !ok {
		return
	}

	user := backendDataWebAuthnUser(data, credentials)
	data.WebAuthnUser = user
	data.HaveWebAuthn = true

	if data.UniqueUserID == "" {
		return
	}

	h.cacheWebAuthnUser(ctx, user)
}

// applyCachedWebAuthnUser loads WebAuthn credentials from Redis when available.
func (h *FrontendHandler) applyCachedWebAuthnUser(ctx *gin.Context, data *UserBackendData) bool {
	if data.UniqueUserID == "" {
		return false
	}

	user, err := backend.GetWebAuthnFromRedis(ctx.Request.Context(), h.deps.Cfg, h.deps.Logger, h.deps.Redis, data.UniqueUserID)
	if err != nil || user == nil {
		return false
	}

	data.WebAuthnUser = user
	data.HaveWebAuthn = len(user.WebAuthnCredentials()) > 0

	return data.HaveWebAuthn
}

// webAuthnCredentialsFromProvider loads non-empty WebAuthn credentials from a provider.
func webAuthnCredentialsFromProvider(provider webAuthnCredentialProvider) ([]mfa.PersistentCredential, bool) {
	credentials, err := provider.GetWebAuthnCredentials()
	if err != nil || len(credentials) == 0 {
		return nil, false
	}

	return credentials, true
}

// backendDataWebAuthnUser creates a backend user for WebAuthn credential state.
func backendDataWebAuthnUser(data *UserBackendData, credentials []mfa.PersistentCredential) *backend.User {
	return &backend.User{
		ID:          data.UniqueUserID,
		Name:        data.Username,
		DisplayName: data.DisplayName,
		Credentials: credentials,
	}
}

// cacheWebAuthnUser stores resolved WebAuthn credentials in Redis best-effort.
func (h *FrontendHandler) cacheWebAuthnUser(ctx *gin.Context, user *backend.User) {
	if err := backend.SaveWebAuthnToRedis(
		ctx.Request.Context(),
		h.deps.Logger,
		h.deps.Cfg,
		h.deps.Redis,
		user,
		h.deps.Cfg.GetServer().GetRedis().GetPosCacheTTL(),
	); err != nil {
		level.Warn(h.deps.Logger).Log(
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Failed to cache WebAuthn backend user data",
			definitions.LogKeyError, err,
		)
	}
}
