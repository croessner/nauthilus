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
	"github.com/croessner/nauthilus/v3/server/definitions"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/segmentio/ksuid"
)

type sloFanoutDispatch struct {
	Participant slodomain.Participant
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

type backChannelSLODelivery struct {
	Client         *http.Client
	FormBody       string
	Destination    string
	RequestTimeout time.Duration
	Attempts       int
}

const (
	sloBackChannelResponseBodyLimit = 4 * 1024
	sloBackChannelRetryBaseDelay    = 150 * time.Millisecond
)

func (h *SAMLHandler) newIDPInitiatedSLOTransaction(account string, binding slodomain.Binding) (*slodomain.Transaction, error) {
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
	transaction *slodomain.Transaction,
	account string,
) (*sloFanoutResult, error) {
	if transaction == nil {
		return nil, fmt.Errorf("slo fanout transaction is missing")
	}

	account, err := sloFanoutAccount(transaction, account)
	if err != nil {
		return nil, err
	}

	sessions, err := h.lookupSLOParticipantSessions(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("cannot load slo fanout participants: %w", err)
	}

	if err = ensureSLOFanoutRunning(transaction, time.Now().UTC()); err != nil {
		return nil, err
	}

	frontChannelEnabled := h.sloFrontChannelEnabled()
	backChannelEnabled := h.sloBackChannelEnabled()
	maxParticipants := h.sloMaxParticipants()

	if result, done, err := h.completeSLOFanoutEarly(ctx, transaction, sessions, frontChannelEnabled, backChannelEnabled); done || err != nil {
		return result, err
	}

	sessions = slices.Clone(sessions)
	slices.SortFunc(sessions, compareSLOParticipantSessions)

	idpObj, signingSP, err := h.sloFanoutSigningContext()
	if err != nil {
		return nil, err
	}

	result := &sloFanoutResult{
		Dispatches: make([]sloFanoutDispatch, 0, len(sessions)),
		Failures:   make([]sloFanoutFailure, 0),
	}

	sessions = trimSLOFanoutSessionsToLimit(sessions, maxParticipants, result)

	for _, session := range sessions {
		h.dispatchSLOFanoutSession(ctx, transaction, session, idpObj, signingSP, frontChannelEnabled, backChannelEnabled, result)
	}

	if err = transaction.Validate(); err != nil {
		return nil, err
	}

	if len(result.Dispatches) == 0 {
		return h.completeSLOFanoutWithoutOpenDispatch(ctx, transaction, result)
	}

	return result, nil
}

// sloFanoutSigningContext returns the SAML IdP and signing SP used for fanout requests.
func (h *SAMLHandler) sloFanoutSigningContext() (*saml.IdentityProvider, *saml.ServiceProvider, error) {
	idpObj, err := h.getSAMLIDP()
	if err != nil {
		return nil, nil, err
	}

	signingSP, err := h.newSLOSigningServiceProvider(idpObj)
	if err != nil {
		return nil, nil, err
	}

	return idpObj, signingSP, nil
}

// sloFanoutAccount returns the explicit account or the transaction account.
func sloFanoutAccount(transaction *slodomain.Transaction, account string) (string, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		account = strings.TrimSpace(transaction.Account)
	}

	if account == "" {
		return "", fmt.Errorf("slo fanout account is missing")
	}

	return account, nil
}

// ensureSLOFanoutRunning moves a local-done transaction into fanout-running state.
func ensureSLOFanoutRunning(transaction *slodomain.Transaction, now time.Time) error {
	if transaction.Status == slodomain.SLOStatusLocalDone {
		if err := transaction.TransitionTo(slodomain.SLOStatusFanoutRunning, now); err != nil {
			return err
		}
	}

	if transaction.Status != slodomain.SLOStatusFanoutRunning {
		return fmt.Errorf("slo fanout requires transaction status local_done or fanout_running, got %q", transaction.Status)
	}

	return nil
}

// completeSLOFanoutEarly handles disabled fanout or empty participant sets.
func (h *SAMLHandler) completeSLOFanoutEarly(
	ctx context.Context,
	transaction *slodomain.Transaction,
	sessions []slodomain.ParticipantSession,
	frontChannelEnabled bool,
	backChannelEnabled bool,
) (*sloFanoutResult, bool, error) {
	if !frontChannelEnabled && !backChannelEnabled {
		result, err := h.completeSLOFanoutAsDone(ctx, transaction, len(sessions), "fanout_disabled", true)

		return result, true, err
	}

	if len(sessions) == 0 {
		result, err := h.completeSLOFanoutAsDone(ctx, transaction, 0)

		return result, true, err
	}

	return nil, false, nil
}

// completeSLOFanoutAsDone marks a fanout with no dispatch work as completed.
func (h *SAMLHandler) completeSLOFanoutAsDone(
	ctx context.Context,
	transaction *slodomain.Transaction,
	participantsTotal int,
	extraKeyvals ...any,
) (*sloFanoutResult, error) {
	if err := transaction.TransitionTo(slodomain.SLOStatusDone, time.Now().UTC()); err != nil {
		return nil, err
	}

	keyvals := []any{
		samlMetricLabelStatus, slodomain.SLOStatusDone,
		"participants_total", participantsTotal,
	}
	keyvals = append(keyvals, extraKeyvals...)

	recordSLOTerminalStatus(slodomain.SLODirectionIDPInitiated, slodomain.SLOStatusDone)
	h.auditSLOEvent(ctx, "fanout_completed", transaction.TransactionID, transaction.RootRequestID, "", keyvals...)

	return &sloFanoutResult{}, nil
}

// trimSLOFanoutSessionsToLimit moves over-limit participants into result failures.
func trimSLOFanoutSessionsToLimit(
	sessions []slodomain.ParticipantSession,
	maxParticipants int,
	result *sloFanoutResult,
) []slodomain.ParticipantSession {
	if maxParticipants <= 0 || len(sessions) <= maxParticipants {
		return sessions
	}

	for _, session := range sessions[maxParticipants:] {
		result.Failures = append(result.Failures, sloFanoutFailure{
			EntityID: strings.TrimSpace(session.SPEntityID),
			Err:      fmt.Errorf("slo max participants limit reached (%d)", maxParticipants),
		})
	}

	return sessions[:maxParticipants]
}

// dispatchSLOFanoutSession dispatches one participant through back-channel or front-channel SLO.
func (h *SAMLHandler) dispatchSLOFanoutSession(
	ctx context.Context,
	transaction *slodomain.Transaction,
	session slodomain.ParticipantSession,
	idpObj *saml.IdentityProvider,
	signingSP *saml.ServiceProvider,
	frontChannelEnabled bool,
	backChannelEnabled bool,
	result *sloFanoutResult,
) {
	if backChannelEnabled && h.dispatchBackChannelSLOFanoutSession(ctx, transaction, session, idpObj, signingSP, frontChannelEnabled, result) {
		return
	}

	if !frontChannelEnabled {
		result.Failures = append(result.Failures, sloFanoutFailure{
			EntityID: strings.TrimSpace(session.SPEntityID),
			Err:      fmt.Errorf("slo front-channel fanout is disabled"),
		})

		return
	}

	dispatch, err := h.buildSLOFanoutDispatch(transaction, session, idpObj, signingSP)
	if err != nil {
		result.Failures = append(result.Failures, sloFanoutFailure{
			EntityID: strings.TrimSpace(session.SPEntityID),
			Err:      err,
		})

		return
	}

	transaction.Participants = append(transaction.Participants, dispatch.Participant)
	result.Dispatches = append(result.Dispatches, dispatch)
}

// dispatchBackChannelSLOFanoutSession attempts back-channel dispatch and reports whether processing is complete.
func (h *SAMLHandler) dispatchBackChannelSLOFanoutSession(
	ctx context.Context,
	transaction *slodomain.Transaction,
	session slodomain.ParticipantSession,
	idpObj *saml.IdentityProvider,
	signingSP *saml.ServiceProvider,
	frontChannelEnabled bool,
	result *sloFanoutResult,
) bool {
	backChannelDispatch, delivered, backChannelErr := h.tryBackChannelSLODispatch(ctx, transaction, session, idpObj, signingSP)
	if backChannelErr != nil {
		if !frontChannelEnabled {
			result.Failures = append(result.Failures, sloFanoutFailure{
				EntityID: strings.TrimSpace(session.SPEntityID),
				Err:      fmt.Errorf("slo back-channel dispatch failed and front-channel fallback is disabled: %w", backChannelErr),
			})

			return true
		}

		h.logBackChannelSLOFallback(ctx, transaction, session, backChannelErr)

		return false
	}

	if !delivered {
		return false
	}

	transaction.Participants = append(transaction.Participants, backChannelDispatch.Participant)
	h.logBackChannelSLODelivered(ctx, transaction, backChannelDispatch)

	return true
}

// logBackChannelSLOFallback records a fallback from back-channel to front-channel dispatch.
func (h *SAMLHandler) logBackChannelSLOFallback(
	ctx context.Context,
	transaction *slodomain.Transaction,
	session slodomain.ParticipantSession,
	err error,
) {
	util.DebugModuleWithCfg(
		ctx,
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyMsg, "SAML SLO back-channel dispatch failed, falling back to front-channel",
		"transaction_id", util.WithNotAvailable(transaction.TransactionID),
		"sp_entity_id", util.WithNotAvailable(strings.TrimSpace(session.SPEntityID)),
		"error", err.Error(),
	)
}

// logBackChannelSLODelivered records a successful back-channel dispatch.
func (h *SAMLHandler) logBackChannelSLODelivered(
	ctx context.Context,
	transaction *slodomain.Transaction,
	dispatch sloFanoutDispatch,
) {
	util.DebugModuleWithCfg(
		ctx,
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyMsg, "SAML SLO back-channel dispatch completed",
		"transaction_id", util.WithNotAvailable(transaction.TransactionID),
		"sp_entity_id", util.WithNotAvailable(dispatch.Participant.EntityID),
		"request_id", util.WithNotAvailable(dispatch.Participant.RequestID),
		"destination", util.WithNotAvailable(dispatch.Destination),
	)
}

// completeSLOFanoutWithoutOpenDispatch finalizes fanout when no front-channel requests remain pending.
func (h *SAMLHandler) completeSLOFanoutWithoutOpenDispatch(
	ctx context.Context,
	transaction *slodomain.Transaction,
	result *sloFanoutResult,
) (*sloFanoutResult, error) {
	nextStatus := slodomain.SLOStatusDone
	if len(result.Failures) > 0 {
		nextStatus = slodomain.SLOStatusFailed
	}

	if err := transaction.TransitionTo(nextStatus, time.Now().UTC()); err != nil {
		return nil, err
	}

	recordSLOTerminalStatus(slodomain.SLODirectionIDPInitiated, nextStatus)
	h.auditSLOEvent(
		ctx,
		"fanout_completed",
		transaction.TransactionID,
		transaction.RootRequestID,
		"",
		samlMetricLabelStatus, nextStatus,
		"participants_total", len(result.Failures),
		"participants_failed", len(result.Failures),
	)

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

	return h.sloEnabled() && h.deps.Cfg.GetIDP().SAML2.GetSLOBackChannelEnabled()
}

func (h *SAMLHandler) sloFrontChannelEnabled() bool {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return true
	}

	return h.sloEnabled() && h.deps.Cfg.GetIDP().SAML2.GetSLOFrontChannelEnabled()
}

func (h *SAMLHandler) sloMaxParticipants() int {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return 64
	}

	return h.deps.Cfg.GetIDP().SAML2.GetSLOMaxParticipants()
}

func (h *SAMLHandler) tryBackChannelSLODispatch(
	ctx context.Context,
	transaction *slodomain.Transaction,
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
	delivery, err := h.newBackChannelSLODelivery(dispatch)
	if err != nil {
		return err
	}

	return delivery.run(ctx)
}

// newBackChannelSLODelivery validates dispatch data and prepares an HTTP delivery.
func (h *SAMLHandler) newBackChannelSLODelivery(dispatch sloFanoutDispatch) (backChannelSLODelivery, error) {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return backChannelSLODelivery{}, fmt.Errorf("SAML handler configuration is not available")
	}

	destination := strings.TrimSpace(dispatch.Destination)
	if destination == "" {
		return backChannelSLODelivery{}, fmt.Errorf("back-channel destination is missing")
	}

	encodedRequest := strings.TrimSpace(dispatch.PostRequest)
	if encodedRequest == "" {
		return backChannelSLODelivery{}, fmt.Errorf("back-channel SAMLRequest payload is missing")
	}

	form := url.Values{}
	form.Set("SAMLRequest", encodedRequest)

	if relayState := strings.TrimSpace(dispatch.RelayState); relayState != "" {
		form.Set("RelayState", relayState)
	}

	samlCfg := h.deps.Cfg.GetIDP().SAML2
	requestTimeout := samlCfg.GetSLORequestTimeout()
	maxRetries := samlCfg.GetSLOBackChannelMaxRetries()
	attempts := maxRetries + 1

	return backChannelSLODelivery{
		Client:         h.newBackChannelSLOHTTPClient(requestTimeout),
		FormBody:       form.Encode(),
		Destination:    destination,
		RequestTimeout: requestTimeout,
		Attempts:       attempts,
	}, nil
}

// run executes the prepared back-channel delivery with configured retries.
func (d backChannelSLODelivery) run(ctx context.Context) error {
	var lastErr error

	for attempt := 1; attempt <= d.Attempts; attempt++ {
		if attempt > 1 {
			retryDelay := time.Duration(attempt-1) * sloBackChannelRetryBaseDelay
			if waitErr := sleepWithContext(ctx, retryDelay); waitErr != nil {
				return waitErr
			}
		}

		done, retry, err := d.doAttempt(ctx, attempt)
		if err != nil {
			lastErr = err
		}

		if done {
			return nil
		}

		if !retry {
			return lastErr
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("back-channel request failed")
	}

	return lastErr
}

// doAttempt performs one back-channel HTTP request attempt.
func (d backChannelSLODelivery) doAttempt(ctx context.Context, attempt int) (done bool, retry bool, err error) {
	requestCtx, cancel := context.WithTimeout(ctx, d.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, d.Destination, strings.NewReader(d.FormBody))
	if err != nil {
		return false, false, fmt.Errorf("cannot create back-channel logout request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.Client.Do(req)
	if err != nil {
		return false, true, fmt.Errorf("back-channel request attempt %d/%d failed: %w", attempt, d.Attempts, err)
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, sloBackChannelResponseBodyLimit))
	_ = resp.Body.Close()

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return true, false, nil
	}

	err = fmt.Errorf("back-channel request attempt %d/%d returned HTTP %d", attempt, d.Attempts, resp.StatusCode)

	return false, isRetryableBackChannelStatus(resp.StatusCode), err
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
	transaction *slodomain.Transaction,
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
	transaction *slodomain.Transaction,
	session slodomain.ParticipantSession,
	idpObj *saml.IdentityProvider,
	signingSP *saml.ServiceProvider,
	binding slodomain.Binding,
	destination string,
) (sloFanoutDispatch, error) {
	entityID, destination, err := h.resolveSLOFanoutDispatchTarget(session, destination)
	if err != nil {
		return sloFanoutDispatch{}, err
	}

	nameID, err := sloFanoutDispatchNameID(session, transaction, entityID)
	if err != nil {
		return sloFanoutDispatch{}, err
	}

	binding = resolveLogoutResponseBinding(binding)
	requestID := "id-" + ksuid.New().String()
	relayState := sloFanoutRelayState(transaction)
	logoutRequest := h.newSLOFanoutLogoutRequest(requestID, destination, entityID, nameID, session, idpObj)
	dispatch := newSLOFanoutDispatch(entityID, nameID, requestID, binding, destination, relayState, session)

	if err = encodeSLOFanoutDispatchBinding(&dispatch, logoutRequest, signingSP); err != nil {
		return sloFanoutDispatch{}, err
	}

	return dispatch, nil
}

// resolveSLOFanoutDispatchTarget resolves the participant entity and destination URL.
func (h *SAMLHandler) resolveSLOFanoutDispatchTarget(
	session slodomain.ParticipantSession,
	destination string,
) (string, string, error) {
	entityID := strings.TrimSpace(session.SPEntityID)
	if entityID == "" {
		return "", "", fmt.Errorf("slo participant entity id is missing")
	}

	destination = strings.TrimSpace(destination)
	if destination == "" {
		resolvedDestination, err := h.resolveLogoutRequestDestination(entityID)

		return entityID, resolvedDestination, err
	}

	parsedDestination, err := parseAbsoluteURL(destination)
	if err != nil {
		return "", "", fmt.Errorf("invalid SAML SLO destination for issuer %q: %w", entityID, err)
	}

	return entityID, parsedDestination.String(), nil
}

// sloFanoutDispatchNameID resolves the NameID for a participant logout request.
func sloFanoutDispatchNameID(
	session slodomain.ParticipantSession,
	transaction *slodomain.Transaction,
	entityID string,
) (string, error) {
	nameID := strings.TrimSpace(session.NameID)
	if nameID == "" {
		nameID = strings.TrimSpace(session.Account)
	}

	if nameID == "" && transaction != nil {
		nameID = strings.TrimSpace(transaction.Account)
	}

	if nameID == "" {
		return "", fmt.Errorf("slo participant NameID is missing for %q", entityID)
	}

	return nameID, nil
}

// sloFanoutRelayState returns the transaction identifier used as RelayState.
func sloFanoutRelayState(transaction *slodomain.Transaction) string {
	if transaction == nil {
		return ""
	}

	return transaction.TransactionID
}

// newSLOFanoutLogoutRequest builds the SAML LogoutRequest for one participant.
func (h *SAMLHandler) newSLOFanoutLogoutRequest(
	requestID string,
	destination string,
	entityID string,
	nameID string,
	session slodomain.ParticipantSession,
	idpObj *saml.IdentityProvider,
) *saml.LogoutRequest {
	logoutRequest := &saml.LogoutRequest{
		ID:           requestID,
		Version:      samlProtocolVersion,
		IssueInstant: saml.TimeNow().UTC(),
		Destination:  destination,
		Issuer: &saml.Issuer{
			Format: samlEntityIssuerFormat,
			Value:  idpObj.MetadataURL.String(),
		},
		NameID: &saml.NameID{
			Format:          h.deps.Cfg.GetIDP().SAML2.GetNameIDFormat(),
			Value:           nameID,
			NameQualifier:   idpObj.MetadataURL.String(),
			SPNameQualifier: entityID,
		},
	}

	if sessionIndex := strings.TrimSpace(session.SessionIndex); sessionIndex != "" {
		logoutRequest.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
	}

	return logoutRequest
}

// newSLOFanoutDispatch creates the dispatch envelope tracked by fanout state.
func newSLOFanoutDispatch(
	entityID string,
	nameID string,
	requestID string,
	binding slodomain.Binding,
	destination string,
	relayState string,
	session slodomain.ParticipantSession,
) sloFanoutDispatch {
	return sloFanoutDispatch{
		Participant: slodomain.Participant{
			EntityID:     entityID,
			NameID:       nameID,
			SessionIndex: strings.TrimSpace(session.SessionIndex),
			RequestID:    requestID,
			Binding:      binding,
		},
		RelayState:  relayState,
		Destination: destination,
	}
}

// encodeSLOFanoutDispatchBinding signs and encodes the dispatch for its binding.
func encodeSLOFanoutDispatchBinding(
	dispatch *sloFanoutDispatch,
	logoutRequest *saml.LogoutRequest,
	signingSP *saml.ServiceProvider,
) error {
	switch dispatch.Participant.Binding {
	case slodomain.SLOBindingPost:
		return encodePostSLOFanoutDispatch(dispatch, logoutRequest, signingSP)
	case slodomain.SLOBindingRedirect:
		return encodeRedirectSLOFanoutDispatch(dispatch, logoutRequest, signingSP)
	default:
		return fmt.Errorf("unsupported SLO fanout binding %q", dispatch.Participant.Binding)
	}
}

// encodePostSLOFanoutDispatch signs and serializes a POST-binding fanout request.
func encodePostSLOFanoutDispatch(
	dispatch *sloFanoutDispatch,
	logoutRequest *saml.LogoutRequest,
	signingSP *saml.ServiceProvider,
) error {
	if err := signingSP.SignLogoutRequest(logoutRequest); err != nil {
		return fmt.Errorf("cannot sign SLO fanout logout request for %q: %w", dispatch.Participant.EntityID, err)
	}

	document := etree.NewDocument()
	document.SetRoot(logoutRequest.Element())

	rawRequestXML, err := document.WriteToBytes()
	if err != nil {
		return fmt.Errorf("cannot encode POST SLO fanout request for %q: %w", dispatch.Participant.EntityID, err)
	}

	dispatch.PostRequest = base64.StdEncoding.EncodeToString(rawRequestXML)
	dispatch.PostBody = string(logoutRequest.Post(dispatch.RelayState))

	return nil
}

// encodeRedirectSLOFanoutDispatch signs and serializes a Redirect-binding fanout request.
func encodeRedirectSLOFanoutDispatch(
	dispatch *sloFanoutDispatch,
	logoutRequest *saml.LogoutRequest,
	signingSP *saml.ServiceProvider,
) error {
	redirectURL, err := buildSignedRedirectLogoutRequestURL(logoutRequest, dispatch.RelayState, signingSP)
	if err != nil {
		return fmt.Errorf("cannot sign redirect SLO fanout request for %q: %w", dispatch.Participant.EntityID, err)
	}

	dispatch.RedirectURL = redirectURL

	return nil
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

		signatureMethod = h.deps.Cfg.GetIDP().SAML2.GetSignatureMethod()
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
