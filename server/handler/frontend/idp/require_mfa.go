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
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/idp"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/idp/mfastate"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
)

type canonicalMFAPolicy struct {
	required      []string
	supported     []string
	scope         string
	requiredLevel int
}

const (
	mfaAssuranceFreshness  = 10 * time.Minute
	canonicalEnrollmentTTL = 15 * time.Minute
	canonicalStepUpTTL     = 15 * time.Minute
)

// canonicalFlowMFAPolicy resolves MFA requirements from one typed protocol flow and authoritative configuration.
//
//nolint:gocyclo // Policy projection merges protocol defaults and bounded client or service-provider requirements.
func (h *FrontendHandler) canonicalFlowMFAPolicy(
	ctx context.Context,
	state *flowdomain.State,
) (canonicalMFAPolicy, bool) {
	if h == nil || h.deps == nil || h.deps.Cfg == nil || h.deps.Cfg.GetIDP() == nil || state == nil {
		return canonicalMFAPolicy{}, false
	}

	idpInstance := idp.NewNauthilusIDP(h.deps)

	switch state.Protocol {
	case flowdomain.FlowProtocolOIDC:
		clientID := strings.TrimSpace(state.Metadata[flowdomain.FlowMetadataClientID])
		if clientID == "" {
			return canonicalMFAPolicy{}, false
		}

		client, err := idpInstance.ResolveClient(ctx, clientID)
		if err != nil || client == nil {
			return canonicalMFAPolicy{}, false
		}

		return canonicalMFAPolicy{
			required:  append([]string(nil), client.GetRequireMFA()...),
			supported: append([]string(nil), client.GetSupportedMFA()...),
			scope:     oidcMFAAssuranceScope(clientID), requiredLevel: client.GetRequiredMFALevel(),
		}, true

	case flowdomain.FlowProtocolSAML:
		entityID := strings.TrimSpace(state.Metadata[flowdomain.FlowMetadataSAMLEntityID])
		if entityID == "" {
			return canonicalMFAPolicy{}, false
		}

		sp, ok := idpInstance.FindSAMLServiceProvider(entityID)
		if !ok || sp == nil {
			return canonicalMFAPolicy{}, false
		}

		return canonicalMFAPolicy{
			required:  append([]string(nil), sp.GetRequireMFA()...),
			supported: append([]string(nil), sp.GetSupportedMFA()...),
			scope:     samlMFAAssuranceScope(entityID), requiredLevel: sp.GetRequiredMFALevel(),
		}, true
	default:
		return canonicalMFAPolicy{}, false
	}
}

// canonicalSessionSatisfiesMFAPolicy checks one live typed assurance without browser-state fallback.
func canonicalSessionSatisfiesMFAPolicy(
	session *cookie.CanonicalSession,
	policy canonicalMFAPolicy,
	now time.Time,
) bool {
	if len(policy.required) == 0 && policy.requiredLevel <= 0 {
		return true
	}

	assurance, ok := session.Assurance(now)
	if !ok {
		return false
	}

	if len(policy.required) > 0 && !slices.Contains(policy.required, assurance.Method) {
		return false
	}

	if policy.requiredLevel > 0 && assurance.Level < policy.requiredLevel {
		return false
	}

	return assurance.Scope == "" || assurance.Scope == policy.scope
}

// canonicalMissingRequiredMFA resolves enrolled factors through the canonical identity and backend capability only.
//
//nolint:gocyclo // Missing-factor computation preserves configured order across three independent methods.
func (h *FrontendHandler) canonicalMissingRequiredMFA(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
	identity cookie.SessionIdentity,
	required []string,
) ([]string, error) {
	if h == nil || h.deps == nil || ctx == nil || session == nil || state == nil {
		return nil, fmt.Errorf("canonical enrollment policy: unavailable")
	}

	boundIdentity, authenticated := session.Identity()
	if !authenticated || boundIdentity != identity {
		return nil, sessionstate.ErrBindingMismatch
	}

	data, err := h.getUserBackendDataForIdentity(
		ctx,
		newBackendDataLookupRequest(
			identity.Account,
			canonicalRemoteBackendRef(session),
			backendDataProtocolContext(state, identity.Protocol),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("canonical enrollment policy: backend state: %w", err)
	}

	if data == nil || data.Username != identity.Account || data.UniqueUserID != identity.Reference {
		return nil, sessionstate.ErrBindingMismatch
	}

	missing := make([]string, 0, len(required))
	for _, method := range required {
		switch method {
		case definitions.MFAMethodTOTP:
			if !data.HaveTOTP {
				missing = append(missing, method)
			}
		case definitions.MFAMethodWebAuthn:
			if !data.HaveWebAuthn {
				missing = append(missing, method)
			}
		case definitions.MFAMethodRecoveryCodes:
			if data.NumRecoveryCodes <= 0 {
				missing = append(missing, method)
			}
		default:
			return nil, sessionstate.ErrBindingMismatch
		}
	}

	return missing, nil
}

const (
	mfaSelfServiceActionRecoveryGenerate   = "recovery_generate"
	mfaSelfServiceActionTOTPDelete         = "totp_delete"
	mfaSelfServiceActionWebAuthnDelete     = "webauthn_delete"
	mfaSelfServiceActionWebAuthnDeviceDrop = "webauthn_device_delete"
	mfaSelfServiceActionWebAuthnDeviceName = "webauthn_device_name"
)

type mfaSelfServiceStepUpTarget struct {
	action     string
	returnPath string
}

// mfaSelfServiceStepUpMutation contains validated data needed to finish one pending mutation.
type mfaSelfServiceStepUpMutation struct {
	webAuthnCredentialID string
	webAuthnDeviceName   string
}

// oidcMFAAssuranceScope returns the session assurance scope for an OIDC client.
func oidcMFAAssuranceScope(clientID string) string {
	if clientID == "" {
		return definitions.ProtoOIDC
	}

	return definitions.ProtoOIDC + ":" + clientID
}

// samlMFAAssuranceScope returns the session assurance scope for a SAML service provider.
func samlMFAAssuranceScope(entityID string) string {
	if entityID == "" {
		return definitions.ProtoSAML
	}

	return definitions.ProtoSAML + ":" + entityID
}

// mfaSelfServiceStepUpTargetForRequest maps sensitive self-service routes to a
// fixed action label and safe return surface. Request-controlled return URLs are
// deliberately ignored.
//
//nolint:gocyclo // Route mapping is an explicit closed vocabulary for every self-service mutation.
func mfaSelfServiceStepUpTargetForRequest(ctx *gin.Context) (mfaSelfServiceStepUpTarget, bool) {
	if ctx == nil || ctx.Request == nil {
		return mfaSelfServiceStepUpTarget{}, false
	}

	method := ctx.Request.Method
	path := unlocalizedMFARootPath(ctx, ctx.Request.URL.Path)

	switch {
	case method == http.MethodPost && isRecoveryGeneratePath(path):
		return mfaSelfServiceStepUpTarget{
			action:     mfaSelfServiceActionRecoveryGenerate,
			returnPath: localizedMFARootPath(ctx, definitions.MFARoot+"/register/home"),
		}, true
	case method == http.MethodDelete && path == definitions.MFARoot+"/totp":
		return mfaSelfServiceStepUpTarget{
			action:     mfaSelfServiceActionTOTPDelete,
			returnPath: localizedMFARootPath(ctx, definitions.MFARoot+"/register/home"),
		}, true
	case method == http.MethodDelete && path == definitions.MFARoot+"/webauthn":
		return mfaSelfServiceStepUpTarget{
			action:     mfaSelfServiceActionWebAuthnDelete,
			returnPath: localizedMFARootPath(ctx, definitions.MFARoot+"/register/home"),
		}, true
	case method == http.MethodDelete && strings.HasPrefix(path, definitions.MFARoot+"/webauthn/device/"):
		return mfaSelfServiceStepUpTarget{
			action:     mfaSelfServiceActionWebAuthnDeviceDrop,
			returnPath: localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/devices"),
		}, true
	case method == http.MethodPost && isWebAuthnDeviceNamePath(path):
		return mfaSelfServiceStepUpTarget{
			action:     mfaSelfServiceActionWebAuthnDeviceName,
			returnPath: localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/devices"),
		}, true
	default:
		return mfaSelfServiceStepUpTarget{}, false
	}
}

// isRecoveryGeneratePath accepts the localized and default recovery generation routes.
func isRecoveryGeneratePath(path string) bool {
	return path == definitions.MFARoot+"/recovery/generate" ||
		strings.HasPrefix(path, definitions.MFARoot+"/recovery/generate/")
}

// isWebAuthnDeviceNamePath accepts WebAuthn credential rename routes.
func isWebAuthnDeviceNamePath(path string) bool {
	return strings.HasPrefix(path, definitions.MFARoot+"/webauthn/device/") &&
		strings.HasSuffix(path, "/name")
}

// mfaSelfServiceStepUpReturnForAction resolves the only valid retry surface for
// each pending self-service action.
func mfaSelfServiceStepUpReturnForAction(action string) (string, bool) {
	switch action {
	case mfaSelfServiceActionRecoveryGenerate, mfaSelfServiceActionTOTPDelete, mfaSelfServiceActionWebAuthnDelete:
		return definitions.MFARoot + "/register/home", true
	case mfaSelfServiceActionWebAuthnDeviceDrop, mfaSelfServiceActionWebAuthnDeviceName:
		return definitions.MFARoot + "/webauthn/devices", true
	default:
		return "", false
	}
}

// ContinueMFASelfServiceStepUp executes a one-time mutation after the completed
// MFA response has established the fresh authenticated browser session.
func (h *FrontendHandler) ContinueMFASelfServiceStepUp(ctx *gin.Context) {
	h.continueCanonicalSelfServiceStepUp(ctx)
}

func (h *FrontendHandler) getRememberMeTTL(oidcCID, samlEntityID string) time.Duration {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return 0
	}

	globalTTL := h.deps.Cfg.GetIDP().GetRememberMeTTL()
	if globalTTL > 0 {
		return globalTTL
	}

	idpInstance := idp.NewNauthilusIDP(h.deps)

	if oidcCID != "" {
		if client, ok := idpInstance.FindClient(oidcCID); ok {
			//nolint:staticcheck // Legacy client fallback is required until deprecated per-client TTL support is removed.
			return client.RememberMeTTL
		}
	}

	if samlEntityID != "" {
		if sp, ok := idpInstance.FindSAMLServiceProvider(samlEntityID); ok {
			//nolint:staticcheck // Legacy service-provider fallback is required until deprecated per-SP TTL support is removed.
			return sp.RememberMeTTL
		}
	}

	return 0
}

func (h *FrontendHandler) shouldShowRememberMe(oidcCID, samlEntityID string) bool {
	return h.getRememberMeTTL(oidcCID, samlEntityID) > 0
}

// startCanonicalRequiredMFAEnrollment commits one typed parent-bound chain before redirecting to registration.
//
//nolint:gocyclo // Enrollment start validates and publishes the complete parent-bound method request.
func (h *FrontendHandler) startCanonicalRequiredMFAEnrollment(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
	identity cookie.SessionIdentity,
	required []string,
) bool {
	if ctx == nil || session == nil || state == nil || state.FlowID == "" || len(required) == 0 {
		return false
	}

	boundIdentity, authenticated := session.Identity()
	if !authenticated || boundIdentity != identity {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	decision, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Resume(ctx.Request.Context(), state.FlowID)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	continuation := safeLocalIDPResumeTarget(decision.RedirectURI)
	target := canonicalRequiredMFARegistrationTarget(required[0])

	if continuation == "" || target == "" {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	record := &sessionstate.EnrollmentRecord{
		Record: sessionstate.Record{Handle: handle}, Session: session.Handle,
		Flow: sessionstate.Handle(state.FlowID), AccountReference: identity.Account,
		IdentityReference: identity.Reference, RequiredMethods: append([]string(nil), required...),
		CurrentStep: required[0], Continuation: continuation,
	}
	if err = mfastate.NewAggregate(session.Stores, session.Handle, canonicalEnrollmentTTL).
		BeginEnrollment(ctx.Request.Context(), record); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	ctx.Redirect(http.StatusFound, flowdomain.AppendTicket(target, string(handle)))

	return true
}

// startCanonicalMFAAssuranceStepUp commits one typed parent-bound challenge before redirecting to MFA selection.
//
//nolint:gocyclo // Assurance start validates and publishes the complete parent-bound supported-method set.
func (h *FrontendHandler) startCanonicalMFAAssuranceStepUp(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
	identity cookie.SessionIdentity,
	policy canonicalMFAPolicy,
) bool {
	if ctx == nil || session == nil || state == nil || state.FlowID == "" || policy.scope == "" ||
		len(policy.required) == 0 && policy.requiredLevel <= 0 {
		return false
	}

	boundIdentity, authenticated := session.Identity()
	if !authenticated || boundIdentity != identity {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	if _, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Resume(ctx.Request.Context(), state.FlowID); err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	record := &sessionstate.StepUpRecord{
		Record: sessionstate.Record{Handle: handle}, Session: session.Handle,
		Flow: sessionstate.Handle(state.FlowID), RequestedLevel: max(policy.requiredLevel, 1),
		SupportedMethods: append([]string(nil), policy.supported...), Scope: policy.scope,
	}
	if err = mfastate.NewAggregate(session.Stores, session.Handle, canonicalStepUpTTL).
		BeginStepUp(ctx.Request.Context(), record); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	ctx.Redirect(http.StatusFound, flowdomain.AppendTicket(h.getMFASelectPath(ctx), string(handle)))

	return true
}

func canonicalRequiredMFARegistrationTarget(method string) string {
	switch method {
	case definitions.MFAMethodTOTP:
		return definitions.MFARoot + "/totp/register"
	case definitions.MFAMethodWebAuthn:
		return definitions.MFARoot + "/webauthn/register"
	case definitions.MFAMethodRecoveryCodes:
		return definitions.MFARoot + "/recovery/register"
	default:
		return ""
	}
}

// ContinueRequiredMFARegistration is the GET handler for /mfa/register/continue.
// It is called after each individual MFA registration step in a forced-registration
// flow to decide whether another method still needs to be registered or whether the
// original IDP flow can be resumed.
func (h *FrontendHandler) ContinueRequiredMFARegistration(ctx *gin.Context) {
	state, err := h.canonicalEnrollmentContinuation(ctx, true)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	if err = mfastate.NewAggregate(state.session.Stores, state.session.Handle, 0).
		DeleteEnrollment(ctx.Request.Context(), state.enrollment.Value.Handle); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	ctx.Redirect(http.StatusSeeOther, state.target)
}

// CancelRequiredMFARegistration is the GET handler for /mfa/register/cancel.
// The user declined to register a required MFA method, so the entire session is
// invalidated:  the forced-registration state is removed, the IDP flow state is
// cleaned up, and the user is logged out before being sent to /logged_out.
func (h *FrontendHandler) CancelRequiredMFARegistration(ctx *gin.Context) {
	state, err := h.canonicalEnrollmentContinuation(ctx, false)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	parentStore := flowdomain.NewTypedStore(
		state.session.Stores, state.session.Handle, state.parent.Protocol, 0,
	)
	if err = parentStore.Delete(ctx.Request.Context(), state.parent.FlowID); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	if err = mfastate.NewAggregate(state.session.Stores, state.session.Handle, 0).
		DeleteEnrollment(ctx.Request.Context(), state.enrollment.Value.Handle); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	state.session.PurgeBrowser(ctx.Writer)
	ctx.Redirect(http.StatusSeeOther, "/logged_out")
}
