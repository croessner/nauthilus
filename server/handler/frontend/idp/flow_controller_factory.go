// Copyright (C) 2025 Christian Rößner
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

package idp

import (
	"context"
	"net/http"
	"time"

	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	flowdomain "github.com/croessner/nauthilus/server/idp/flow"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
)

// newFlowController builds an IdP flow controller with Redis-backed state
// when available and cookie-reference fallback when Redis is unavailable.
func newFlowController(mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) *flowdomain.Controller {
	if redisClient == nil || redisClient.GetWriteHandle() == nil {
		return flowdomain.NewController(flowdomain.NewFlowReferenceAdapter(mgr))
	}

	referenceStore := flowdomain.NewFlowReferenceAdapter(mgr)
	stateStore := flowdomain.NewRedisStore(redisClient.GetWriteHandle(), redisPrefix+"idp:flow", 0)

	return flowdomain.NewController(flowdomain.NewHybridStore(referenceStore, stateStore))
}

// advanceFlow advances the current flow to the given step.
// Errors are intentionally ignored: the flow controller is an enhancement
// and failing to advance must not break the login flow.
func advanceFlow(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string, to flowdomain.FlowStep) {
	if mgr == nil {
		return
	}

	flowID := mgr.GetString(definitions.SessionKeyIdPFlowID, "")
	if flowID == "" {
		return
	}

	controller := newFlowController(mgr, redisClient, redisPrefix)

	_, _ = controller.Advance(ctx, flowID, to, time.Now())
}

// completeFlow completes the current flow: deletes the Redis state via
// the controller and then removes all IdP cookie keys.
func completeFlow(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) {
	if mgr == nil {
		return
	}

	flowID := mgr.GetString(definitions.SessionKeyIdPFlowID, "")
	if flowID != "" {
		controller := newFlowController(mgr, redisClient, redisPrefix)

		_, _ = controller.Complete(ctx, flowID)
	}

	flowdomain.CleanupIdPState(mgr)
}

// abortFlow unconditionally deletes the flow state from Redis and cleans
// up all IdP cookie keys.  Use this for denied consent or error paths
// where the policy might not allow a regular Complete.
func abortFlow(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) {
	if mgr == nil {
		return
	}

	flowID := mgr.GetString(definitions.SessionKeyIdPFlowID, "")
	if flowID != "" {
		controller := newFlowController(mgr, redisClient, redisPrefix)

		_, _ = controller.Abort(ctx, flowID)
	}

	flowdomain.CleanupIdPState(mgr)
}

// resumeFlow resolves the persisted flow state and returns the next resume
// decision, including stale-flow recovery where possible.
func resumeFlow(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) (flowdomain.Decision, error) {
	if mgr == nil {
		return flowdomain.Decision{Type: flowdomain.DecisionTypeRedirect, RedirectURI: "/"}, nil
	}

	flowID := mgr.GetString(definitions.SessionKeyIdPFlowID, "")
	if flowID == "" {
		return flowdomain.Decision{Type: flowdomain.DecisionTypeRedirect, RedirectURI: "/"}, nil
	}

	controller := newFlowController(mgr, redisClient, redisPrefix)

	decision, err := controller.Resume(ctx, flowID)
	if err == nil {
		return decision, nil
	}

	recoveryDecision, recoverErr := controller.Recover(ctx, flowID, err)
	if recoverErr != nil {
		return flowdomain.Decision{}, err
	}

	return recoveryDecision, nil
}

func getFlowAuthOutcome(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string) (flowdomain.AuthOutcome, bool) {
	if mgr == nil {
		return flowdomain.AuthOutcomeUnknown, false
	}

	flowID := mgr.GetString(definitions.SessionKeyIdPFlowID, "")
	if flowID == "" {
		return flowdomain.AuthOutcomeUnknown, false
	}

	controller := newFlowController(mgr, redisClient, redisPrefix)
	state, err := controller.State(ctx, flowID)
	if err != nil || state == nil {
		return flowdomain.AuthOutcomeUnknown, false
	}

	return state.AuthOutcome, true
}

func setFlowAuthOutcome(ctx context.Context, mgr cookie.Manager, redisClient rediscli.Client, redisPrefix string, outcome flowdomain.AuthOutcome) bool {
	if mgr == nil {
		return false
	}

	flowID := mgr.GetString(definitions.SessionKeyIdPFlowID, "")
	if flowID == "" {
		return false
	}

	controller := newFlowController(mgr, redisClient, redisPrefix)

	return controller.SetAuthOutcome(ctx, flowID, outcome, time.Now()) == nil
}

// resumeIdPFlow resumes an interrupted IdP flow and performs the redirect
// implied by the flow decision.
func (h *FrontendHandler) resumeIdPFlow(ctx *gin.Context, mgr cookie.Manager) {
	var (
		redisClient rediscli.Client
		redisPrefix string
	)

	if h != nil && h.deps != nil {
		redisClient = h.deps.Redis

		if h.deps.Cfg != nil && h.deps.Cfg.GetServer() != nil {
			redisPrefix = h.deps.Cfg.GetServer().GetRedis().GetPrefix()
		}
	}

	decision, err := resumeFlow(ctx.Request.Context(), mgr, redisClient, redisPrefix)
	if err != nil {
		ctx.Redirect(http.StatusFound, "/")

		return
	}

	if decision.RedirectURI == flowdomain.FlowMetadataResumeTargetDeviceCodeComplete {
		if h == nil || h.deps == nil {
			ctx.Redirect(http.StatusFound, "/")

			return
		}

		h.completeDeviceCodeFlow(ctx, mgr)

		return
	}

	redirectURI := decision.RedirectURI
	if redirectURI == "" {
		redirectURI = "/"
	}

	ctx.Redirect(http.StatusFound, redirectURI)
}
