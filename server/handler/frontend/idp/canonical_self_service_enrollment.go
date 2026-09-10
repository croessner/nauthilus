// Copyright 2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/idp/mfastate"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
)

// startSelfServiceWebAuthnEnrollment creates a session-owned, single-method registration.
func (h *FrontendHandler) startSelfServiceWebAuthnEnrollment(ctx *gin.Context) {
	session := cookie.GetCanonicalSession(ctx)

	identity, authenticated := session.Identity()
	if !authenticated {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	if h.requireCanonicalSelfServiceAssurance(ctx, session, identity) {
		return
	}

	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	record := &sessionstate.EnrollmentRecord{
		Record: sessionstate.Record{Handle: handle}, Session: session.Handle, SelfService: true,
		AccountReference: identity.Account, IdentityReference: identity.Reference,
		RequiredMethods: []string{definitions.MFAMethodWebAuthn}, CurrentStep: definitions.MFAMethodWebAuthn,
		Continuation: localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/devices"),
	}
	if err = mfastate.NewAggregate(session.Stores, session.Handle, canonicalEnrollmentTTL).
		BeginEnrollment(ctx.Request.Context(), record); err != nil {
		ctx.AbortWithStatus(canonicalStateWriteStatus(err))

		return
	}

	redirectCanonicalBrowserMutation(ctx, flowdomain.AppendTicket(
		localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/register"), string(handle),
	))
}

// validSelfServiceWebAuthnEnrollment restricts optional enrollment to one factor and its device list.
func validSelfServiceWebAuthnEnrollment(record sessionstate.EnrollmentRecord) bool {
	target := safeLocalIDPResumeTarget(record.Continuation)
	root := definitions.MFARoot + "/webauthn/devices"

	return record.SelfService && record.Flow == "" && len(record.RequiredMethods) == 1 &&
		record.RequiredMethods[0] == definitions.MFAMethodWebAuthn &&
		(target == root || strings.HasPrefix(target, root+"/") && !strings.ContainsAny(strings.TrimPrefix(target, root+"/"), "/?#"))
}

// canonicalWebAuthnEnrollmentProtocol preserves protocol binding for both enrollment owners.
func canonicalWebAuthnEnrollmentProtocol(selection canonicalEnrollmentSelectionState) string {
	if selection.parent != nil {
		return string(selection.parent.Protocol)
	}

	return selection.identity.Protocol
}
