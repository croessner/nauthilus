package idp

import (
	"strings"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
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

// GetUserBackendData performs backend lookups and returns encapsulated user data.
func (h *FrontendHandler) GetUserBackendData(ctx *gin.Context) (*UserBackendData, error) {
	session := sessions.Default(ctx)
	username, _ := util.GetSessionValue[string](session, definitions.CookieAccount)

	if username == "" {
		authHeader := ctx.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			idpInstance := idp.NewNauthilusIdP(h.deps)

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

		if secret, ok := authState.GetTOTPSecretOk(); ok && secret != "" {
			data.HaveTOTP = true
		}

		codes := authState.GetTOTPRecoveryCodes()
		data.NumRecoveryCodes = len(codes)

		if data.UniqueUserID != "" {
			user, err := backend.GetWebAuthnFromRedis(ctx.Request.Context(), h.deps.Cfg, h.deps.Logger, h.deps.Redis, data.UniqueUserID)
			if err == nil && user != nil {
				data.WebAuthnUser = user
				data.HaveWebAuthn = len(user.WebAuthnCredentials()) > 0
			}
		}
	}

	return data, nil
}
