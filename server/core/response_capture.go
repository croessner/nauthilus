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
	"log/slog"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/definitions"

	"github.com/gin-gonic/gin"
)

// CapturedAuthDecision is the terminal auth decision captured from the response layer.
type CapturedAuthDecision string

const (
	// CapturedAuthDecisionUnset indicates that no terminal decision was captured yet.
	CapturedAuthDecisionUnset CapturedAuthDecision = "unset"
	// CapturedAuthDecisionOK indicates successful authentication.
	CapturedAuthDecisionOK CapturedAuthDecision = "ok"
	// CapturedAuthDecisionFail indicates a terminal authentication failure.
	CapturedAuthDecisionFail CapturedAuthDecision = "fail"
	// CapturedAuthDecisionTempFail indicates a temporary terminal failure.
	CapturedAuthDecisionTempFail CapturedAuthDecision = "tempfail"
)

// CapturedAuthOutcome stores the transport-neutral terminal auth outcome.
type CapturedAuthOutcome struct {
	Attributes           bktype.AttributeMapping
	Decision             CapturedAuthDecision
	TerminalState        string
	Session              string
	AccountField         string
	TOTPSecretField      string
	TOTPRecoveryField    string
	UniqueUserIDField    string
	DisplayNameField     string
	StatusMessage        string
	StatusMessageI18NKey string
	ResponseLanguage     string
	Error                string
	Groups               []string
	GroupDNS             []string
	Backend              definitions.Backend
	HTTPStatus           int
}

// CaptureResponseWriter captures auth terminal outcomes without rendering HTTP.
type CaptureResponseWriter struct {
	logger  *slog.Logger
	outcome CapturedAuthOutcome
}

// NewCaptureResponseWriter creates a request-scoped outcome collector.
func NewCaptureResponseWriter(logger *slog.Logger) *CaptureResponseWriter {
	return &CaptureResponseWriter{
		logger: logger,
		outcome: CapturedAuthOutcome{
			Decision: CapturedAuthDecisionUnset,
		},
	}
}

// NewDefaultCaptureResponseWriter creates a capture writer based on DI response dependencies.
func NewDefaultCaptureResponseWriter(deps ResponseDeps) *CaptureResponseWriter {
	return NewCaptureResponseWriter(deps.Logger)
}

// Outcome returns a copy of the last captured outcome.
func (w *CaptureResponseWriter) Outcome() CapturedAuthOutcome {
	if w == nil {
		return CapturedAuthOutcome{Decision: CapturedAuthDecisionUnset}
	}

	out := w.outcome
	out.Attributes = cloneAttributeMapping(out.Attributes)
	out.Groups = append([]string(nil), out.Groups...)
	out.GroupDNS = append([]string(nil), out.GroupDNS...)

	return out
}

// OK applies success side effects and captures the success outcome.
func (w *CaptureResponseWriter) OK(ctx *gin.Context, view *StateView) {
	if w == nil || view == nil || view.auth == nil {
		return
	}

	auth := view.auth
	auth.applyAuthSuccessSideEffects(ctx)
	w.captureOutcome(auth, authFSMStateAuthOK, CapturedAuthDecisionOK, "", auth.Runtime.StatusCodeOK)
}

// Fail applies failure side effects and captures the failure outcome.
func (w *CaptureResponseWriter) Fail(ctx *gin.Context, view *StateView) {
	if w == nil || view == nil || view.auth == nil {
		return
	}

	auth := view.auth
	auth.applyAuthFailureSideEffects(ctx)
	w.captureOutcome(auth, authFSMStateAuthFail, CapturedAuthDecisionFail, "", auth.Runtime.StatusCodeFail)
}

// TempFail applies temporary-failure side effects and captures the temporary failure outcome.
func (w *CaptureResponseWriter) TempFail(ctx *gin.Context, view *StateView, reason string) {
	if w == nil || view == nil || view.auth == nil {
		return
	}

	auth := view.auth
	auth.prepareAuthTempFail(reason)
	if auth.shouldLogAuthTempFail() {
		auth.logAuthTempFail(ctx, w.logger)
	}

	w.captureOutcome(auth, authFSMStateAuthTempFail, CapturedAuthDecisionTempFail, reason, auth.Runtime.StatusCodeInternalError)
}

func (w *CaptureResponseWriter) captureOutcome(
	auth *AuthState,
	terminalState authFSMState,
	decision CapturedAuthDecision,
	reason string,
	status int,
) {
	if auth == nil {
		return
	}

	w.outcome = CapturedAuthOutcome{
		Attributes:           auth.GetAttributesCopy(),
		Decision:             decision,
		TerminalState:        string(terminalState),
		Session:              auth.Runtime.GUID,
		AccountField:         auth.Runtime.AccountField,
		TOTPSecretField:      auth.Runtime.TOTPSecretField,
		TOTPRecoveryField:    auth.Runtime.TOTPRecoveryField,
		UniqueUserIDField:    auth.Runtime.UniqueUserIDField,
		DisplayNameField:     auth.Runtime.DisplayNameField,
		StatusMessage:        auth.Runtime.StatusMessage,
		StatusMessageI18NKey: auth.Runtime.StatusMessageI18NKey,
		ResponseLanguage:     auth.Runtime.ResponseLanguage,
		Error:                reason,
		Groups:               auth.GetGroups(),
		GroupDNS:             auth.GetGroupDNs(),
		Backend:              auth.Runtime.SourcePassDBBackend,
		HTTPStatus:           status,
	}
}

func cloneAttributeMapping(source bktype.AttributeMapping) bktype.AttributeMapping {
	if source == nil {
		return nil
	}

	target := make(bktype.AttributeMapping, len(source))
	for key, values := range source {
		if values == nil {
			target[key] = nil

			continue
		}

		clonedValues := make([]any, len(values))
		copy(clonedValues, values)
		target[key] = clonedValues
	}

	return target
}
