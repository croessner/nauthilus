// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
)

const (
	loginCompletionTombstoneTTL   = time.Minute
	loginCompletionSuccessOutcome = "ok"
)

// LoginCompletionInput is the complete durable state transition for one successful primary login.
type LoginCompletionInput struct {
	Identity    IdentityUpdate
	Flow        sessionstate.Handle
	Protocol    string
	NextStep    string
	RememberTTL time.Duration
}

type loginCompletionRecords struct {
	oidc         []sessionstate.Versioned[sessionstate.OIDCFlow]
	saml         []sessionstate.Versioned[sessionstate.SAMLFlow]
	selfService  []sessionstate.Versioned[sessionstate.SelfServiceFlow]
	enrollment   []sessionstate.Versioned[sessionstate.EnrollmentRecord]
	stepUp       []sessionstate.Versioned[sessionstate.StepUpRecord]
	ceremony     []sessionstate.Versioned[sessionstate.CeremonyRecord]
	totpRecovery []sessionstate.Versioned[sessionstate.TOTPRecoveryRecord]
}

type preparedLoginCompletion struct {
	newHandle   sessionstate.Handle
	anchor      sessionstate.SessionAnchor
	transaction sessionstate.TransactionRequest
	children    []sessionstate.OwnedReference
	cookie      *http.Cookie
}

// CompleteLogin rotates the canonical handle and publishes identity, protocol, and child state before the envelope.
func (s *CanonicalSession) CompleteLogin(
	ctx context.Context,
	writer http.ResponseWriter,
	input LoginCompletionInput,
) (*CanonicalSession, error) {
	if s == nil || s.runtime == nil || s.Stores == nil || s.clock == nil || writer == nil {
		return nil, fmt.Errorf("canonical login completion: unavailable session")
	}

	prepared, err := s.prepareLoginCompletion(ctx, input)
	if err != nil {
		return nil, err
	}

	receipt, err := s.Stores.Commit(ctx, prepared.transaction)
	if err != nil {
		return nil, err
	}

	prepared.anchor.Revision = receipt.Revision
	if err = s.revokeLoginCompletionSession(
		ctx, s.Handle, s.Anchor.Revision, oldLoginCompletionChildren(s.Anchor.Value), true,
	); err != nil {
		rollbackErr := s.revokeLoginCompletionSession(
			ctx, prepared.newHandle, receipt.Revision, prepared.children, false,
		)

		return nil, errors.Join(err, rollbackErr)
	}

	http.SetCookie(writer, prepared.cookie)

	return &CanonicalSession{
		Handle:  prepared.newHandle,
		Anchor:  sessionstate.Versioned[sessionstate.SessionAnchor]{Value: prepared.anchor, Revision: receipt.Revision},
		Stores:  s.Stores,
		clock:   s.clock,
		runtime: s.runtime,
	}, nil
}

func (s *CanonicalSession) prepareLoginCompletion(
	ctx context.Context,
	input LoginCompletionInput,
) (preparedLoginCompletion, error) {
	var prepared preparedLoginCompletion

	identity, err := validateLoginCompletionInput(input)
	if err != nil {
		return prepared, err
	}

	records, err := s.loadLoginCompletionRecords(ctx)
	if err != nil {
		return prepared, err
	}

	prepared.newHandle, err = s.runtime.generator.NewHandle()
	if err != nil {
		return prepared, err
	}

	now := s.clock.Now().UTC()
	absoluteTTL, cookieMaxAge := normalizedRememberTTL(input.RememberTTL)
	anchorTTL := min(canonicalIdleTTL, absoluteTTL)
	prepared.anchor = s.loginCompletionAnchor(prepared.newHandle, now, anchorTTL, absoluteTTL, identity)

	prepared.transaction, prepared.children, err = loginCompletionTransaction(
		prepared.newHandle, prepared.anchor, records, input, now, anchorTTL,
	)
	if err != nil {
		return prepared, err
	}

	encoded, err := s.runtime.codec.Encode(definitions.SecureDataCookieName, Envelope{
		Version: CurrentEnvelopeVersion, Session: prepared.newHandle, KeyEpoch: s.runtime.codec.keyEpoch,
	})
	if err != nil {
		return prepared, err
	}

	prepared.cookie = canonicalHTTPCookie(definitions.SecureDataCookieName, encoded, cookieMaxAge, s.runtime.secure)
	if len(prepared.cookie.String()) >= EnvelopeHardLimitBytes {
		return preparedLoginCompletion{}, fmt.Errorf(
			"%w: cookie header size %d", ErrEnvelopeRejected, len(prepared.cookie.String()),
		)
	}

	return prepared, nil
}

func validateLoginCompletionInput(
	input LoginCompletionInput,
) (validatedIdentityUpdate, error) {
	if input.Flow == "" || strings.TrimSpace(input.Protocol) == "" || strings.TrimSpace(input.NextStep) == "" {
		return validatedIdentityUpdate{}, sessionstate.ErrBindingMismatch
	}

	return validateIdentityUpdate(input.Identity)
}

func normalizedRememberTTL(requested time.Duration) (time.Duration, int) {
	if requested <= 0 {
		return canonicalAbsoluteTTL, 0
	}

	requested = min(requested, canonicalRememberAbsoluteTTL)

	return requested, int(requested.Seconds())
}

func (s *CanonicalSession) loginCompletionAnchor(
	handle sessionstate.Handle,
	now time.Time,
	idleTTL time.Duration,
	absoluteTTL time.Duration,
	identity validatedIdentityUpdate,
) sessionstate.SessionAnchor {
	anchor := s.Anchor.Value
	anchor.Record = sessionstate.Record{Handle: handle, ExpiresAt: now.Add(idleTTL)}
	anchor.CreatedAt = now
	anchor.LastTouchedAt = now
	anchor.IdleExpiresAt = now.Add(idleTTL)
	anchor.AbsoluteExpiresAt = now.Add(absoluteTTL)
	anchor.Authenticated = true
	anchor.IdentityReference = identity.identity.Subject
	anchor.Identity = identity.identity
	anchor.BackendAffinity = identity.affinity
	anchor.MFAIdentityReference = identity.mfaIdentity.Subject
	anchor.MFAIdentity = identity.mfaIdentity
	anchor.MFABackendAffinity = identity.mfaAffinity
	anchor.RotatedFrom = s.Handle
	anchor.Revoked = false
	anchor.Tombstone = false

	return anchor
}

func (s *CanonicalSession) loadLoginCompletionRecords(ctx context.Context) (loginCompletionRecords, error) {
	var records loginCompletionRecords

	var err error

	records.oidc, err = loadLoginCompletionFamily(ctx, s.Stores.OIDC, s.Handle, s.Anchor.Value.OIDCFlows)
	if err != nil {
		return records, err
	}

	records.saml, err = loadLoginCompletionFamily(ctx, s.Stores.SAML, s.Handle, s.Anchor.Value.SAMLFlows)
	if err != nil {
		return records, err
	}

	records.selfService, err = loadLoginCompletionFamily(
		ctx,
		s.Stores.SelfService,
		s.Handle,
		s.Anchor.Value.SelfServiceFlows,
	)
	if err != nil {
		return records, err
	}

	records.enrollment, err = loadLoginCompletionFamily(ctx, s.Stores.Enrollment, s.Handle, s.Anchor.Value.Enrollments)
	if err != nil {
		return records, err
	}

	records.stepUp, err = loadLoginCompletionFamily(ctx, s.Stores.StepUp, s.Handle, s.Anchor.Value.StepUps)
	if err != nil {
		return records, err
	}

	records.ceremony, err = loadLoginCompletionFamily(ctx, s.Stores.Ceremony, s.Handle, s.Anchor.Value.Ceremonies)
	if err != nil {
		return records, err
	}

	records.totpRecovery, err = loadLoginCompletionFamily(
		ctx, s.Stores.TOTPRecovery, s.Handle, s.Anchor.Value.TOTPRecovery,
	)

	return records, err
}

func loadLoginCompletionFamily[T any](
	ctx context.Context,
	repository sessionstate.Repository[T],
	session sessionstate.Handle,
	handles []sessionstate.Handle,
) ([]sessionstate.Versioned[T], error) {
	records := make([]sessionstate.Versioned[T], 0, len(handles))
	for _, handle := range handles {
		record, err := repository.Load(ctx, sessionstate.Reference{Session: session, Record: handle})
		if err != nil {
			return nil, err
		}

		records = append(records, record)
	}

	return records, nil
}

func loginCompletionTransaction(
	newHandle sessionstate.Handle,
	anchor sessionstate.SessionAnchor,
	records loginCompletionRecords,
	input LoginCompletionInput,
	now time.Time,
	anchorTTL time.Duration,
) (sessionstate.TransactionRequest, []sessionstate.OwnedReference, error) {
	transaction := sessionstate.TransactionRequest{Session: &sessionstate.CommitRequest[sessionstate.SessionAnchor]{
		Reference: sessionstate.Reference{Session: newHandle, Record: newHandle}, Value: anchor, TTL: anchorTTL,
	}}

	oidc, children, selected, err := appendLoginCompletionProtocol(
		records.oidc, newHandle, now, anchorTTL, input, false, "oidc", sessionstate.OwnerOIDCFlow,
		rebindLoginCompletionOIDC, advanceLoginCompletionOIDC,
	)
	if err != nil {
		return transaction, nil, err
	}

	transaction.OIDC = oidc

	saml, samlChildren, selected, err := appendLoginCompletionProtocol(
		records.saml, newHandle, now, anchorTTL, input, selected, "saml", sessionstate.OwnerSAMLFlow,
		rebindLoginCompletionSAML, advanceLoginCompletionSAML,
	)
	if err != nil {
		return transaction, nil, err
	}

	transaction.SAML = saml

	children = append(children, samlChildren...)

	selfService, selfServiceChildren, selected, err := appendLoginCompletionProtocol(
		records.selfService, newHandle, now, anchorTTL, input, selected, "internal",
		sessionstate.OwnerSelfServiceFlow, rebindLoginCompletionSelfService, advanceLoginCompletionSelfService,
	)
	if err != nil {
		return transaction, nil, err
	}

	transaction.SelfService = selfService

	children = append(children, selfServiceChildren...)

	if !selected {
		return transaction, nil, sessionstate.ErrBindingMismatch
	}

	appendLoginCompletionAuxiliaryFamilies(&transaction, &children, records, newHandle, now, anchorTTL)

	return transaction, children, nil
}

func appendLoginCompletionProtocol[T any](
	records []sessionstate.Versioned[T],
	session sessionstate.Handle,
	now time.Time,
	anchorTTL time.Duration,
	input LoginCompletionInput,
	selected bool,
	protocol string,
	owner sessionstate.Owner,
	rebind func(*T, sessionstate.Handle) (sessionstate.Handle, time.Time),
	advance func(*T, string),
) ([]sessionstate.CommitRequest[T], []sessionstate.OwnedReference, bool, error) {
	mutations := make([]sessionstate.CommitRequest[T], 0, len(records))

	children := make([]sessionstate.OwnedReference, 0, len(records))
	for _, record := range records {
		value := record.Value

		handle, expiresAt := rebind(&value, session)
		if handle == input.Flow {
			if input.Protocol != protocol || selected {
				return nil, nil, selected, sessionstate.ErrBindingMismatch
			}

			advance(&value, input.NextStep)

			selected = true
		}

		mutations = append(mutations, sessionstate.CommitRequest[T]{
			Reference: sessionstate.Reference{Session: session, Record: handle}, Value: value,
			TTL: remainingLoginCompletionTTL(expiresAt, now, anchorTTL),
		})
		children = append(children, sessionstate.OwnedReference{
			Owner: owner, Reference: sessionstate.Reference{Session: session, Record: handle},
		})
	}

	return mutations, children, selected, nil
}

func appendLoginCompletionAuxiliaryFamilies(
	transaction *sessionstate.TransactionRequest,
	children *[]sessionstate.OwnedReference,
	records loginCompletionRecords,
	session sessionstate.Handle,
	now time.Time,
	anchorTTL time.Duration,
) {
	var owned []sessionstate.OwnedReference

	transaction.Enrollment, owned = appendLoginCompletionFamily(
		records.enrollment, session, now, anchorTTL, sessionstate.OwnerEnrollment, rebindLoginCompletionEnrollment,
	)
	*children = append(*children, owned...)
	transaction.StepUp, owned = appendLoginCompletionFamily(
		records.stepUp, session, now, anchorTTL, sessionstate.OwnerStepUp, rebindLoginCompletionStepUp,
	)
	*children = append(*children, owned...)
	transaction.Ceremony, owned = appendLoginCompletionFamily(
		records.ceremony, session, now, anchorTTL,
		sessionstate.OwnerWebAuthnCeremony, rebindLoginCompletionCeremony,
	)
	*children = append(*children, owned...)
	transaction.TOTPRecovery, owned = appendLoginCompletionFamily(
		records.totpRecovery, session, now, anchorTTL,
		sessionstate.OwnerTOTPRecovery, rebindLoginCompletionTOTPRecovery,
	)
	*children = append(*children, owned...)
}

func appendLoginCompletionFamily[T any](
	records []sessionstate.Versioned[T],
	session sessionstate.Handle,
	now time.Time,
	anchorTTL time.Duration,
	owner sessionstate.Owner,
	rebind func(*T, sessionstate.Handle) (sessionstate.Handle, time.Time),
) ([]sessionstate.CommitRequest[T], []sessionstate.OwnedReference) {
	mutations := make([]sessionstate.CommitRequest[T], 0, len(records))

	children := make([]sessionstate.OwnedReference, 0, len(records))
	for _, record := range records {
		value := record.Value

		handle, expiresAt := rebind(&value, session)
		mutations = append(mutations, sessionstate.CommitRequest[T]{
			Reference: sessionstate.Reference{Session: session, Record: handle}, Value: value,
			TTL: remainingLoginCompletionTTL(expiresAt, now, anchorTTL),
		})
		children = append(children, sessionstate.OwnedReference{
			Owner: owner, Reference: sessionstate.Reference{Session: session, Record: handle},
		})
	}

	return mutations, children
}

func rebindLoginCompletionOIDC(
	value *sessionstate.OIDCFlow,
	session sessionstate.Handle,
) (sessionstate.Handle, time.Time) {
	value.Session = session

	return value.Handle, value.ExpiresAt
}

func advanceLoginCompletionOIDC(value *sessionstate.OIDCFlow, nextStep string) {
	value.AuthOutcome = loginCompletionSuccessOutcome
	value.CurrentStep = nextStep
}

func rebindLoginCompletionSAML(
	value *sessionstate.SAMLFlow,
	session sessionstate.Handle,
) (sessionstate.Handle, time.Time) {
	value.Session = session

	return value.Handle, value.ExpiresAt
}

func advanceLoginCompletionSAML(value *sessionstate.SAMLFlow, nextStep string) {
	value.AuthOutcome = loginCompletionSuccessOutcome
	value.CurrentStep = nextStep
}

// rebindLoginCompletionSelfService moves one internal-login record to the rotated session.
func rebindLoginCompletionSelfService(
	value *sessionstate.SelfServiceFlow,
	session sessionstate.Handle,
) (sessionstate.Handle, time.Time) {
	value.Session = session

	return value.Handle, value.ExpiresAt
}

// advanceLoginCompletionSelfService publishes successful primary authentication on the selected flow.
func advanceLoginCompletionSelfService(value *sessionstate.SelfServiceFlow, nextStep string) {
	value.AuthOutcome = loginCompletionSuccessOutcome
	value.CurrentStep = nextStep
}

func rebindLoginCompletionEnrollment(
	value *sessionstate.EnrollmentRecord,
	session sessionstate.Handle,
) (sessionstate.Handle, time.Time) {
	value.Session = session

	return value.Handle, value.ExpiresAt
}

func rebindLoginCompletionStepUp(
	value *sessionstate.StepUpRecord,
	session sessionstate.Handle,
) (sessionstate.Handle, time.Time) {
	value.Session = session

	return value.Handle, value.ExpiresAt
}

func rebindLoginCompletionCeremony(
	value *sessionstate.CeremonyRecord,
	session sessionstate.Handle,
) (sessionstate.Handle, time.Time) {
	value.Session = session

	return value.Handle, value.ExpiresAt
}

func rebindLoginCompletionTOTPRecovery(
	value *sessionstate.TOTPRecoveryRecord,
	session sessionstate.Handle,
) (sessionstate.Handle, time.Time) {
	value.Session = session

	return value.Handle, value.ExpiresAt
}

func remainingLoginCompletionTTL(expiresAt time.Time, now time.Time, anchorTTL time.Duration) time.Duration {
	remaining := expiresAt.Sub(now)
	if remaining <= 0 || remaining > anchorTTL {
		return anchorTTL
	}

	return remaining
}

func oldLoginCompletionChildren(anchor sessionstate.SessionAnchor) []sessionstate.OwnedReference {
	children := make([]sessionstate.OwnedReference, 0,
		len(anchor.OIDCFlows)+len(anchor.SAMLFlows)+len(anchor.SelfServiceFlows)+len(anchor.Enrollments)+len(anchor.StepUps)+
			len(anchor.Ceremonies)+len(anchor.TOTPRecovery))
	appendOwner := func(owner sessionstate.Owner, handles []sessionstate.Handle) {
		for _, handle := range handles {
			children = append(children, sessionstate.OwnedReference{
				Owner:     owner,
				Reference: sessionstate.Reference{Session: anchor.Handle, Record: handle},
			})
		}
	}
	appendOwner(sessionstate.OwnerOIDCFlow, anchor.OIDCFlows)
	appendOwner(sessionstate.OwnerSAMLFlow, anchor.SAMLFlows)
	appendOwner(sessionstate.OwnerSelfServiceFlow, anchor.SelfServiceFlows)
	appendOwner(sessionstate.OwnerEnrollment, anchor.Enrollments)
	appendOwner(sessionstate.OwnerStepUp, anchor.StepUps)
	appendOwner(sessionstate.OwnerWebAuthnCeremony, anchor.Ceremonies)
	appendOwner(sessionstate.OwnerTOTPRecovery, anchor.TOTPRecovery)

	return children
}

func (s *CanonicalSession) revokeLoginCompletionSession(
	ctx context.Context,
	handle sessionstate.Handle,
	revision sessionstate.Revision,
	children []sessionstate.OwnedReference,
	rejectRevoked bool,
) error {
	return s.Stores.RevokeSession(ctx, sessionstate.RevocationRequest{
		Reference:        sessionstate.Reference{Session: handle, Record: handle},
		ExpectedRevision: revision,
		TombstoneTTL:     loginCompletionTombstoneTTL,
		Children:         children,
		RejectRevoked:    rejectRevoked,
	})
}
