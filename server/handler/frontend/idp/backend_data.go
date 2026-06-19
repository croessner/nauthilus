package idp

import (
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
	username := ""

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	if username == "" {
		authHeader := ctx.GetHeader("Authorization")
		if after, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
			tokenString := after
			idpInstance := idp.NewNauthilusIDP(h.deps)

			claims, err := idpInstance.ValidateToken(ctx.Request.Context(), tokenString)
			if err == nil {
				if sub, ok := claims["sub"].(string); ok {
					username = sub
				}
			}
		}
	}

	if username == "" {
		return nil, nil
	}

	authDeps := h.deps.Auth()

	state := core.NewAuthStateWithSetupWithDeps(ctx, authDeps)
	if state == nil {
		return nil, nil
	}

	authState := state.(*core.AuthState)
	authState.SetUsername(username)
	authState.SetProtocol(config.NewProtocol(definitions.ProtoIDP))
	authState.SetNoAuth(true)

	data := &UserBackendData{
		Username:  username,
		AuthState: authState,
	}

	if authResult := authState.HandlePassword(ctx); authResult == definitions.AuthResultOK {
		if disp, ok := authState.GetDisplayNameOk(); ok {
			data.DisplayName = disp
		}

		if uniqueID, ok := authState.GetUniqueUserIDOk(); ok {
			data.UniqueUserID = uniqueID
		}

		loadedPublicMFA, err := h.applyPublicMFAState(ctx, data, authState)
		if err != nil {
			return nil, err
		}

		if !loadedPublicMFA {
			if secret, ok := authState.GetTOTPSecretOk(); ok && secret != "" {
				data.HaveTOTP = true
			}

			codes := authState.GetTOTPRecoveryCodes()
			data.NumRecoveryCodes = len(codes)

			h.resolveWebAuthnUser(ctx, mgr, data, authState)
		}
	}

	return data, nil
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

	if data.UniqueUserID == "" && mgr != nil {
		uniqueUserID := mgr.GetString(definitions.SessionKeyUniqueUserID, "")
		if uniqueUserID != "" {
			data.UniqueUserID = uniqueUserID
		}
	}

	if data.UniqueUserID != "" {
		user, err := backend.GetWebAuthnFromRedis(ctx.Request.Context(), h.deps.Cfg, h.deps.Logger, h.deps.Redis, data.UniqueUserID)
		if err == nil && user != nil {
			data.WebAuthnUser = user
			data.HaveWebAuthn = len(user.WebAuthnCredentials()) > 0
		}
	}

	if data.HaveWebAuthn {
		return
	}

	credentials, err := provider.GetWebAuthnCredentials()
	if err != nil || len(credentials) == 0 {
		return
	}

	user := &backend.User{
		ID:          data.UniqueUserID,
		Name:        data.Username,
		DisplayName: data.DisplayName,
		Credentials: credentials,
	}

	data.WebAuthnUser = user
	data.HaveWebAuthn = true

	if data.UniqueUserID == "" {
		return
	}

	if err = backend.SaveWebAuthnToRedis(
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
