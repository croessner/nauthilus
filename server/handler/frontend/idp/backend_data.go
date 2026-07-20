package idp

import (
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
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

// GetUserBackendData performs backend lookups and returns encapsulated user data.
func (h *FrontendHandler) GetUserBackendData(ctx *gin.Context) (*UserBackendData, error) {
	mgr := cookie.GetManager(ctx)

	username := h.backendDataUsername(ctx, mgr)
	if username == "" {
		return nil, nil
	}

	return h.getUserBackendDataForIdentity(ctx, mgr, username, definitions.ProtoIDP, core.RemoteBackendRef{})
}

// getUserBackendDataForIdentity performs a no-auth lookup for one identity and
// optional authority backend reference.
func (h *FrontendHandler) getUserBackendDataForIdentity(
	ctx *gin.Context,
	mgr cookie.Manager,
	username string,
	protocolName string,
	backendRef core.RemoteBackendRef,
) (*UserBackendData, error) {
	lookupCtx := backendDataLookupContext(ctx)

	authState := h.newBackendDataAuthState(lookupCtx, username)
	if authState == nil {
		return nil, nil
	}

	if protocolName != "" {
		authState.SetProtocol(config.NewProtocol(protocolName))
	}

	if !backendRef.IsZero() {
		authState.Runtime.RemoteBackendRef = backendRef
	}

	data := newUserBackendData(username, authState)
	if authState.HandlePassword(lookupCtx) != definitions.AuthResultOK {
		return data, nil
	}

	applyBackendIdentityData(data, authState)

	if err := h.applyBackendMFAData(lookupCtx, mgr, data, authState); err != nil {
		return nil, err
	}

	return data, nil
}

// backendDataLookupContext prevents no-auth backend-data lookups from parsing
// the body of the request that triggered the lookup, such as a WebAuthn finish
// JSON payload that has already been consumed by the assertion verifier.
func backendDataLookupContext(ctx *gin.Context) *gin.Context {
	if ctx == nil || ctx.Request == nil {
		return ctx
	}

	contentType := ctx.GetHeader("Content-Type")
	if ctx.Request.Method != http.MethodPost ||
		!strings.HasPrefix(contentType, "application/json") && !strings.HasPrefix(contentType, "application/cbor") {
		return ctx
	}

	lookupCtx := ctx.Copy()
	lookupCtx.Set(definitions.CtxPluginResponseMutationDisabledKey, true)

	request := ctx.Request.Clone(ctx.Request.Context())
	request.Method = http.MethodGet
	request.Body = http.NoBody
	request.ContentLength = 0
	request.Header = request.Header.Clone()
	request.Header.Del("Content-Type")
	lookupCtx.Request = request

	return lookupCtx
}

// backendDataUsername resolves the backend-data username from session or bearer token.
func (h *FrontendHandler) backendDataUsername(ctx *gin.Context, mgr cookie.Manager) string {
	if mgr != nil {
		if username := mgr.GetString(definitions.SessionKeyAccount, ""); username != "" {
			return username
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

// newBackendDataAuthState creates the no-auth IDP AuthState used for data lookups.
func (h *FrontendHandler) newBackendDataAuthState(ctx *gin.Context, username string) *core.AuthState {
	state := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
	if state == nil {
		return nil
	}

	authState := state.(*core.AuthState)
	authState.SetUsername(username)
	authState.SetProtocol(config.NewProtocol(definitions.ProtoIDP))
	authState.SetNoAuth(true)

	return authState
}

// newUserBackendData creates the backend-data DTO for an initialized AuthState.
func newUserBackendData(username string, authState *core.AuthState) *UserBackendData {
	return &UserBackendData{
		Username:  username,
		AuthState: authState,
	}
}

// applyBackendIdentityData copies display and stable user identifiers from AuthState.
func applyBackendIdentityData(data *UserBackendData, authState *core.AuthState) {
	if disp, ok := authState.GetDisplayNameOk(); ok {
		data.DisplayName = disp
	}

	if uniqueID, ok := authState.GetUniqueUserIDOk(); ok {
		data.UniqueUserID = uniqueID
	}
}

// applyBackendMFAData fills MFA state from public backends or legacy AuthState fields.
func (h *FrontendHandler) applyBackendMFAData(
	ctx *gin.Context,
	mgr cookie.Manager,
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

	h.applyLegacyBackendMFAData(ctx, mgr, data, authState)

	return nil
}

// applyLegacyBackendMFAData fills MFA state from legacy AuthState getters.
func (h *FrontendHandler) applyLegacyBackendMFAData(
	ctx *gin.Context,
	mgr cookie.Manager,
	data *UserBackendData,
	authState *core.AuthState,
) {
	if secret, ok := authState.GetTOTPSecretOk(); ok && secret != "" {
		data.HaveTOTP = true
	}

	codes := authState.GetTOTPRecoveryCodes()
	data.NumRecoveryCodes = len(codes)

	h.resolveWebAuthnUser(ctx, mgr, data, authState)
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
func (h *FrontendHandler) resolveWebAuthnUser(ctx *gin.Context, mgr cookie.Manager, data *UserBackendData, provider webAuthnCredentialProvider) {
	if data == nil || provider == nil {
		return
	}

	applyUniqueUserIDFromSession(mgr, data)

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

// applyUniqueUserIDFromSession fills missing unique user IDs from the secure session.
func applyUniqueUserIDFromSession(mgr cookie.Manager, data *UserBackendData) {
	if data.UniqueUserID != "" || mgr == nil {
		return
	}

	if uniqueUserID := mgr.GetString(definitions.SessionKeyUniqueUserID, ""); uniqueUserID != "" {
		data.UniqueUserID = uniqueUserID
	}
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
