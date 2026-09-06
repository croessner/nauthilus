package idp

import (
	"errors"
	"net/http"

	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/gin-gonic/gin"
)

// admitMFACode reserves the factor identity's shared code budget before dispatching a verifier.
func (h *FrontendHandler) admitMFACode(ctx *gin.Context, session *mfaSessionState) bool {
	if h == nil || h.deps == nil || session == nil || session.mgr == nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)
		return false
	}

	identity, err := h.mfaCodeBudgetIdentity(ctx, session)
	if err == nil {
		err = core.ConsumeMFAAttempt(ctx.Request.Context(), h.deps.Auth(), identity)
	}

	if err == nil {
		return true
	}

	if errors.Is(err, core.ErrMFAAttemptLimit) {
		ctx.Header("Retry-After", "300")
		ctx.AbortWithStatus(http.StatusTooManyRequests)
	} else {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)
	}

	return false
}

// mfaCodeBudgetIdentity resolves older sessions without a factor ID without charging a delegated target.
func (h *FrontendHandler) mfaCodeBudgetIdentity(ctx *gin.Context, session *mfaSessionState) (string, error) {
	if identity := session.mgr.GetString(definitions.SessionKeyMFAFactorUniqueUserID, ""); identity != "" {
		return identity, nil
	}

	ref, _ := core.MFAFactorRemoteBackendRefFromSession(session.mgr)

	data, err := h.getUserBackendDataForIdentity(ctx, session.mgr, session.factorUser, definitions.ProtoIDP, ref)
	if err != nil {
		return "", err
	}

	return mfaBackendBudgetIdentity(data)
}

// mfaBackendBudgetIdentity selects a resolved factor's stable ID or canonical account.
func mfaBackendBudgetIdentity(data *UserBackendData) (string, error) {
	if data == nil || data.AuthState == nil || data.AuthState.GetAccount() == "" {
		return "", errors.New("MFA factor identity unavailable")
	}

	if data.UniqueUserID != "" {
		return data.UniqueUserID, nil
	}

	return data.AuthState.GetAccount(), nil
}
