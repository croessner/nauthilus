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

package idp

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/server/definitions"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/croessner/nauthilus/server/util"
	"github.com/segmentio/ksuid"
)

type sloFanoutDispatch struct {
	Participant slodomain.SLOParticipant
	RelayState  string
	Destination string
	RedirectURL string
	PostBody    string
	PostRequest string
}

type sloFanoutFailure struct {
	EntityID string
	Err      error
}

type sloFanoutResult struct {
	Dispatches []sloFanoutDispatch
	Failures   []sloFanoutFailure
}

const (
	sloBackChannelResponseBodyLimit = 4 * 1024
	sloBackChannelRetryBaseDelay    = 150 * time.Millisecond
)

func (h *SAMLHandler) newIDPInitiatedSLOTransaction(account string, binding slodomain.SLOBinding) (*slodomain.SLOTransaction, error) {
	now := time.Now().UTC()
	rootRequestID := "id-" + ksuid.New().String()

	transaction, err := slodomain.NewTransaction(
		ksuid.New().String(),
		rootRequestID,
		slodomain.SLODirectionIDPInitiated,
		binding,
		now,
	)
	if err != nil {
		return nil, err
	}

	transaction.Account = strings.TrimSpace(account)

	if err = transaction.TransitionTo(slodomain.SLOStatusValidated, now); err != nil {
		return nil, err
	}

	return transaction, nil
}

func (h *SAMLHandler) lookupSLOParticipantSessions(ctx context.Context, account string) ([]slodomain.ParticipantSession, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return nil, nil
	}

	registry := h.sloSessionRegistry()
	if registry == nil {
		return nil, fmt.Errorf("slo session registry is not available")
	}

	sessions, err := registry.LookupParticipants(ctx, account)
	if err != nil {
		return nil, err
	}

	return sessions, nil
}

func (h *SAMLHandler) orchestrateIDPInitiatedSLOFanout(
	ctx context.Context,
	transaction *slodomain.SLOTransaction,
	account string,
) (*sloFanoutResult, error) {
	if transaction == nil {
		return nil, fmt.Errorf("slo fanout transaction is missing")
	}

	account = strings.TrimSpace(account)
	if account == "" {
		account = strings.TrimSpace(transaction.Account)
	}

	if account == "" {
		return nil, fmt.Errorf("slo fanout account is missing")
	}

	sessions, err := h.lookupSLOParticipantSessions(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("cannot load slo fanout participants: %w", err)
	}

	now := time.Now().UTC()

	if transaction.Status == slodomain.SLOStatusLocalDone {
		if err = transaction.TransitionTo(slodomain.SLOStatusFanoutRunning, now); err != nil {
			return nil, err
		}
	}

	if transaction.Status != slodomain.SLOStatusFanoutRunning {
		return nil, fmt.Errorf("slo fanout requires transaction status local_done or fanout_running, got %q", transaction.Status)
	}

	frontChannelEnabled := h.sloFrontChannelEnabled()
	backChannelEnabled := h.sloBackChannelEnabled()
	maxParticipants := h.sloMaxParticipants()

	if !frontChannelEnabled && !backChannelEnabled {
		if err = transaction.TransitionTo(slodomain.SLOStatusDone, now); err != nil {
			return nil, err
		}

		recordSLOTerminalStatus(slodomain.SLODirectionIDPInitiated, slodomain.SLOStatusDone)
		h.auditSLOEvent(
			ctx,
			"fanout_completed",
			transaction.TransactionID,
			transaction.RootRequestID,
			"",
			"status", slodomain.SLOStatusDone,
			"participants_total", len(sessions),
			"fanout_disabled", true,
		)

		return &sloFanoutResult{}, nil
	}

	if len(sessions) == 0 {
		if err = transaction.TransitionTo(slodomain.SLOStatusDone, now); err != nil {
			return nil, err
		}

		recordSLOTerminalStatus(slodomain.SLODirectionIDPInitiated, slodomain.SLOStatusDone)
		h.auditSLOEvent(
			ctx,
			"fanout_completed",
			transaction.TransactionID,
			transaction.RootRequestID,
			"",
			"status", slodomain.SLOStatusDone,
			"participants_total", 0,
		)

		return &sloFanoutResult{}, nil
	}

	sessions = slices.Clone(sessions)
	slices.SortFunc(sessions, compareSLOParticipantSessions)

	idpObj, err := h.getSAMLIdP()
	if err != nil {
		return nil, err
	}

	signingSP, err := h.newSLOSigningServiceProvider(idpObj)
	if err != nil {
		return nil, err
	}

	result := &sloFanoutResult{
		Dispatches: make([]sloFanoutDispatch, 0, len(sessions)),
		Failures:   make([]sloFanoutFailure, 0),
	}

	if maxParticipants > 0 && len(sessions) > maxParticipants {
		for _, session := range sessions[maxParticipants:] {
			result.Failures = append(result.Failures, sloFanoutFailure{
				EntityID: strings.TrimSpace(session.SPEntityID),
				Err:      fmt.Errorf("slo max participants limit reached (%d)", maxParticipants),
			})
		}

		sessions = sessions[:maxParticipants]
	}

	for _, session := range sessions {
		if backChannelEnabled {
			backChannelDispatch, delivered, backChannelErr := h.tryBackChannelSLODispatch(ctx, transaction, session, idpObj, signingSP)
			if backChannelErr != nil {
				if !frontChannelEnabled {
					result.Failures = append(result.Failures, sloFanoutFailure{
						EntityID: strings.TrimSpace(session.SPEntityID),
						Err:      fmt.Errorf("slo back-channel dispatch failed and front-channel fallback is disabled: %w", backChannelErr),
					})

					continue
				}

				util.DebugModuleWithCfg(
					ctx,
					h.deps.Cfg,
					h.deps.Logger,
					definitions.DbgIdp,
					definitions.LogKeyMsg, "SAML SLO back-channel dispatch failed, falling back to front-channel",
					"transaction_id", util.WithNotAvailable(transaction.TransactionID),
					"sp_entity_id", util.WithNotAvailable(strings.TrimSpace(session.SPEntityID)),
					"error", backChannelErr.Error(),
				)
			} else if delivered {
				transaction.Participants = append(transaction.Participants, backChannelDispatch.Participant)

				util.DebugModuleWithCfg(
					ctx,
					h.deps.Cfg,
					h.deps.Logger,
					definitions.DbgIdp,
					definitions.LogKeyMsg, "SAML SLO back-channel dispatch completed",
					"transaction_id", util.WithNotAvailable(transaction.TransactionID),
					"sp_entity_id", util.WithNotAvailable(backChannelDispatch.Participant.EntityID),
					"request_id", util.WithNotAvailable(backChannelDispatch.Participant.RequestID),
					"destination", util.WithNotAvailable(backChannelDispatch.Destination),
				)

				continue
			}
		}

		if !frontChannelEnabled {
			result.Failures = append(result.Failures, sloFanoutFailure{
				EntityID: strings.TrimSpace(session.SPEntityID),
				Err:      fmt.Errorf("slo front-channel fanout is disabled"),
			})

			continue
		}

		dispatch, err := h.buildSLOFanoutDispatch(transaction, session, idpObj, signingSP)
		if err != nil {
			result.Failures = append(result.Failures, sloFanoutFailure{
				EntityID: strings.TrimSpace(session.SPEntityID),
				Err:      err,
			})

			continue
		}

		transaction.Participants = append(transaction.Participants, dispatch.Participant)
		result.Dispatches = append(result.Dispatches, dispatch)
	}

	if err = transaction.Validate(); err != nil {
		return nil, err
	}

	if len(result.Dispatches) == 0 {
		nextStatus := slodomain.SLOStatusDone
		if len(result.Failures) > 0 {
			nextStatus = slodomain.SLOStatusFailed
		}

		if err = transaction.TransitionTo(nextStatus, time.Now().UTC()); err != nil {
			return nil, err
		}

		recordSLOTerminalStatus(slodomain.SLODirectionIDPInitiated, nextStatus)
		h.auditSLOEvent(
			ctx,
			"fanout_completed",
			transaction.TransactionID,
			transaction.RootRequestID,
			"",
			"status", nextStatus,
			"participants_total", len(result.Failures),
			"participants_failed", len(result.Failures),
		)
	}

	return result, nil
}

func compareSLOParticipantSessions(left, right slodomain.ParticipantSession) int {
	if cmp := strings.Compare(left.SPEntityID, right.SPEntityID); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(left.SessionIndex, right.SessionIndex); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(left.NameID, right.NameID); cmp != 0 {
		return cmp
	}

	return strings.Compare(left.AuthnInstant.UTC().Format(time.RFC3339Nano), right.AuthnInstant.UTC().Format(time.RFC3339Nano))
}

func (h *SAMLHandler) sloBackChannelEnabled() bool {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return false
	}

	return h.sloEnabled() && h.deps.Cfg.GetIdP().SAML2.GetSLOBackChannelEnabled()
}

func (h *SAMLHandler) sloFrontChannelEnabled() bool {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return true
	}

	return h.sloEnabled() && h.deps.Cfg.GetIdP().SAML2.GetSLOFrontChannelEnabled()
}

func (h *SAMLHandler) sloMaxParticipants() int {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return 64
	}

	return h.deps.Cfg.GetIdP().SAML2.GetSLOMaxParticipants()
}

func (h *SAMLHandler) tryBackChannelSLODispatch(
	ctx context.Context,
	transaction *slodomain.SLOTransaction,
	session slodomain.ParticipantSession,
	idpObj *saml.IdentityProvider,
	signingSP *saml.ServiceProvider,
) (sloFanoutDispatch, bool, error) {
	destination, hasEndpoint, err := h.resolveLogoutRequestBackChannelDestination(session.SPEntityID)
	if err != nil {
		return sloFanoutDispatch{}, false, err
	}

	if !hasEndpoint {
		return sloFanoutDispatch{}, false, nil
	}

	dispatch, err := h.buildSLOFanoutDispatchWithBinding(
		transaction,
		session,
		idpObj,
		signingSP,
		slodomain.SLOBindingPost,
		destination,
	)
	if err != nil {
		return sloFanoutDispatch{}, false, err
	}

	if err = h.deliverBackChannelSLODispatch(ctx, dispatch); err != nil {
		return sloFanoutDispatch{}, false, err
	}

	return dispatch, true, nil
}

func (h *SAMLHandler) resolveLogoutRequestBackChannelDestination(spEntityID string) (string, bool, error) {
	spEntityID = strings.TrimSpace(spEntityID)
	if spEntityID == "" {
		return "", false, fmt.Errorf("logout request participant issuer is missing")
	}

	sp, ok := h.findConfiguredSAMLServiceProvider(spEntityID)
	if !ok {
		return "", false, nil
	}

	backChannelURL := strings.TrimSpace(sp.GetSLOBackChannelURL())
	if backChannelURL == "" {
		return "", false, nil
	}

	parsedURL, err := parseAbsoluteURL(backChannelURL)
	if err != nil {
		return "", false, fmt.Errorf("invalid SAML SLO back-channel URL for issuer %q: %w", spEntityID, err)
	}

	return parsedURL.String(), true, nil
}

func (h *SAMLHandler) deliverBackChannelSLODispatch(ctx context.Context, dispatch sloFanoutDispatch) error {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return fmt.Errorf("SAML handler configuration is not available")
	}

	destination := strings.TrimSpace(dispatch.Destination)
	if destination == "" {
		return fmt.Errorf("back-channel destination is missing")
	}

	encodedRequest := strings.TrimSpace(dispatch.PostRequest)
	if encodedRequest == "" {
		return fmt.Errorf("back-channel SAMLRequest payload is missing")
	}

	form := url.Values{}
	form.Set("SAMLRequest", encodedRequest)
	if relayState := strings.TrimSpace(dispatch.RelayState); relayState != "" {
		form.Set("RelayState", relayState)
	}

	samlCfg := h.deps.Cfg.GetIdP().SAML2
	requestTimeout := samlCfg.GetSLORequestTimeout()
	maxRetries := samlCfg.GetSLOBackChannelMaxRetries()
	attempts := maxRetries + 1
	client := h.newBackChannelSLOHTTPClient(requestTimeout)

	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			retryDelay := time.Duration(attempt-1) * sloBackChannelRetryBaseDelay
			if waitErr := sleepWithContext(ctx, retryDelay); waitErr != nil {
				return waitErr
			}
		}

		requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)

		req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, destination, strings.NewReader(form.Encode()))
		if err != nil {
			cancel()

			return fmt.Errorf("cannot create back-channel logout request: %w", err)
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("back-channel request attempt %d/%d failed: %w", attempt, attempts, err)

			continue
		}

		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, sloBackChannelResponseBodyLimit))
		_ = resp.Body.Close()
		cancel()

		if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
			return nil
		}

		lastErr = fmt.Errorf(
			"back-channel request attempt %d/%d returned HTTP %d",
			attempt,
			attempts,
			resp.StatusCode,
		)

		if !isRetryableBackChannelStatus(resp.StatusCode) {
			return lastErr
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("back-channel request failed")
	}

	return lastErr
}

func (h *SAMLHandler) newBackChannelSLOHTTPClient(requestTimeout time.Duration) *http.Client {
	if requestTimeout <= 0 {
		requestTimeout = 3 * time.Second
	}

	tlsHandshakeTimeout := max(requestTimeout/2, time.Second)

	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: requestTimeout,
			ExpectContinueTimeout: time.Second,
			IdleConnTimeout:       30 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: requestTimeout,
	}
}

func isRetryableBackChannelStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	}

	return statusCode >= http.StatusInternalServerError
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (h *SAMLHandler) buildSLOFanoutDispatch(
	transaction *slodomain.SLOTransaction,
	session slodomain.ParticipantSession,
	idpObj *saml.IdentityProvider,
	signingSP *saml.ServiceProvider,
) (sloFanoutDispatch, error) {
	binding := slodomain.SLOBindingRedirect
	if transaction != nil {
		binding = resolveLogoutResponseBinding(transaction.Binding)
	}

	return h.buildSLOFanoutDispatchWithBinding(transaction, session, idpObj, signingSP, binding, "")
}

func (h *SAMLHandler) buildSLOFanoutDispatchWithBinding(
	transaction *slodomain.SLOTransaction,
	session slodomain.ParticipantSession,
	idpObj *saml.IdentityProvider,
	signingSP *saml.ServiceProvider,
	binding slodomain.SLOBinding,
	destination string,
) (sloFanoutDispatch, error) {
	entityID := strings.TrimSpace(session.SPEntityID)
	if entityID == "" {
		return sloFanoutDispatch{}, fmt.Errorf("slo participant entity id is missing")
	}

	destination = strings.TrimSpace(destination)
	if destination == "" {
		var err error

		destination, err = h.resolveLogoutRequestDestination(entityID)
		if err != nil {
			return sloFanoutDispatch{}, err
		}
	} else {
		parsedDestination, err := parseAbsoluteURL(destination)
		if err != nil {
			return sloFanoutDispatch{}, fmt.Errorf("invalid SAML SLO destination for issuer %q: %w", entityID, err)
		}

		destination = parsedDestination.String()
	}

	nameID := strings.TrimSpace(session.NameID)
	if nameID == "" {
		nameID = strings.TrimSpace(session.Account)
	}
	if nameID == "" && transaction != nil {
		nameID = strings.TrimSpace(transaction.Account)
	}
	if nameID == "" {
		return sloFanoutDispatch{}, fmt.Errorf("slo participant NameID is missing for %q", entityID)
	}

	binding = resolveLogoutResponseBinding(binding)
	requestID := "id-" + ksuid.New().String()
	relayState := ""

	if transaction != nil {
		relayState = transaction.TransactionID
	}

	logoutRequest := &saml.LogoutRequest{
		ID:           requestID,
		Version:      "2.0",
		IssueInstant: saml.TimeNow().UTC(),
		Destination:  destination,
		Issuer: &saml.Issuer{
			Format: samlEntityIssuerFormat,
			Value:  idpObj.MetadataURL.String(),
		},
		NameID: &saml.NameID{
			Format:          h.deps.Cfg.GetIdP().SAML2.GetNameIDFormat(),
			Value:           nameID,
			NameQualifier:   idpObj.MetadataURL.String(),
			SPNameQualifier: entityID,
		},
	}

	if sessionIndex := strings.TrimSpace(session.SessionIndex); sessionIndex != "" {
		logoutRequest.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
	}

	dispatch := sloFanoutDispatch{
		Participant: slodomain.SLOParticipant{
			EntityID:     entityID,
			NameID:       nameID,
			SessionIndex: strings.TrimSpace(session.SessionIndex),
			RequestID:    requestID,
			Binding:      binding,
		},
		RelayState:  relayState,
		Destination: destination,
	}

	var err error

	switch binding {
	case slodomain.SLOBindingPost:
		if err = signingSP.SignLogoutRequest(logoutRequest); err != nil {
			return sloFanoutDispatch{}, fmt.Errorf("cannot sign SLO fanout logout request for %q: %w", entityID, err)
		}

		document := etree.NewDocument()
		document.SetRoot(logoutRequest.Element())

		rawRequestXML, encodeErr := document.WriteToBytes()
		if encodeErr != nil {
			return sloFanoutDispatch{}, fmt.Errorf("cannot encode POST SLO fanout request for %q: %w", entityID, encodeErr)
		}

		dispatch.PostRequest = base64.StdEncoding.EncodeToString(rawRequestXML)
		dispatch.PostBody = string(logoutRequest.Post(dispatch.RelayState))
	case slodomain.SLOBindingRedirect:
		redirectURL, redirectErr := buildSignedRedirectLogoutRequestURL(logoutRequest, dispatch.RelayState, signingSP)
		if redirectErr != nil {
			return sloFanoutDispatch{}, fmt.Errorf("cannot sign redirect SLO fanout request for %q: %w", entityID, redirectErr)
		}

		dispatch.RedirectURL = redirectURL
	default:
		return sloFanoutDispatch{}, fmt.Errorf("unsupported SLO fanout binding %q", binding)
	}

	return dispatch, nil
}

func (h *SAMLHandler) resolveLogoutRequestDestination(spEntityID string) (string, error) {
	spEntityID = strings.TrimSpace(spEntityID)
	if spEntityID == "" {
		return "", fmt.Errorf("logout request participant issuer is missing")
	}

	if sp, ok := h.findConfiguredSAMLServiceProvider(spEntityID); ok {
		sloURL := strings.TrimSpace(sp.SLOURL)
		if sloURL != "" {
			parsedSLOURL, err := parseAbsoluteURL(sloURL)
			if err != nil {
				return "", fmt.Errorf("invalid SAML SLOURL for issuer %q: %w", spEntityID, err)
			}

			return parsedSLOURL.String(), nil
		}
	}

	parsedEntityID, err := parseAbsoluteURL(spEntityID)
	if err != nil {
		return "", fmt.Errorf("logout request destination for issuer %q is not configured", spEntityID)
	}

	return parsedEntityID.String(), nil
}

func (h *SAMLHandler) newSLOSigningServiceProvider(idpObj *saml.IdentityProvider) (*saml.ServiceProvider, error) {
	if idpObj == nil {
		return nil, fmt.Errorf("idp context is missing")
	}

	signer, ok := idpObj.Key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("idp key type %T does not support signing", idpObj.Key)
	}

	signatureMethod := strings.TrimSpace(idpObj.SignatureMethod)
	if signatureMethod == "" {
		if h == nil || h.deps == nil || h.deps.Cfg == nil {
			return nil, fmt.Errorf("saml signature method is not configured")
		}

		signatureMethod = h.deps.Cfg.GetIdP().SAML2.GetSignatureMethod()
	}

	if signatureMethod == "" {
		return nil, fmt.Errorf("saml signature method is not configured")
	}

	if isWeakSHA1SignatureMethodSLO(signatureMethod) {
		return nil, fmt.Errorf("unsupported SAML logout request signature algorithm %q", signatureMethod)
	}

	return &saml.ServiceProvider{
		Key:             signer,
		Certificate:     idpObj.Certificate,
		SignatureMethod: signatureMethod,
	}, nil
}

func buildSignedRedirectLogoutRequestURL(
	logoutRequest *saml.LogoutRequest,
	relayState string,
	signingSP *saml.ServiceProvider,
) (string, error) {
	if logoutRequest == nil {
		return "", fmt.Errorf("logout request payload is missing")
	}

	if signingSP == nil {
		return "", fmt.Errorf("logout request signer is missing")
	}

	deflated, err := logoutRequest.Deflate()
	if err != nil {
		return "", err
	}

	rawSAMLRequest := url.QueryEscape(base64.StdEncoding.EncodeToString(deflated))
	rawSigAlg := url.QueryEscape(signingSP.SignatureMethod)

	signedContent := "SAMLRequest=" + rawSAMLRequest
	if relayState != "" {
		signedContent += "&RelayState=" + url.QueryEscape(relayState)
	}

	signedContent += "&SigAlg=" + rawSigAlg

	signingContext, err := saml.GetSigningContext(signingSP)
	if err != nil {
		return "", err
	}

	signature, err := signingContext.SignString(signedContent)
	if err != nil {
		return "", err
	}

	query := signedContent + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))

	target, err := parseAbsoluteURL(logoutRequest.Destination)
	if err != nil {
		return "", err
	}

	if target.RawQuery != "" {
		target.RawQuery += "&" + query
	} else {
		target.RawQuery = query
	}

	return target.String(), nil
}
