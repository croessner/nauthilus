// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/sessionstate"
)

// SessionIdentity is the stable identity binding exposed to browser-flow callers.
type SessionIdentity struct {
	Reference   string
	Account     string
	Subject     string
	DisplayName string
	Protocol    string
}

// SessionBackendAffinity is the server-side authority capability for follow-up identity operations.
type SessionBackendAffinity struct {
	Type        string
	Name        string
	Protocol    string
	Authority   string
	OpaqueToken string
}

// IdentityUpdate is the complete successful-authentication projection committed to the anchor.
type IdentityUpdate struct {
	Reference          string
	Account            string
	Subject            string
	DisplayName        string
	Protocol           string
	BackendAffinity    *SessionBackendAffinity
	MFAIdentity        *SessionIdentity
	MFABackendAffinity *SessionBackendAffinity
}

// SessionAssurance is the bounded, non-secret MFA proof shared across protocol flows.
type SessionAssurance struct {
	Level     int
	Method    string
	Scope     string
	ProvenAt  time.Time
	ExpiresAt time.Time
}

// OIDCLogoutContext is the bounded typed identity/client projection used by logout.
type OIDCLogoutContext struct {
	Identity  SessionIdentity
	ClientIDs []string
}

// RecordOIDCClient records one successfully issued OIDC client session without tokens.
//
//nolint:gocyclo,funlen // Bounded CAS retry keeps identity validation and index publication in one transaction boundary.
func (s *CanonicalSession) RecordOIDCClient(
	ctx context.Context,
	identity SessionIdentity,
	clientID string,
) error {
	currentIdentity, ok := s.Identity()

	clientID = strings.TrimSpace(clientID)
	if !ok || identity != currentIdentity || clientID == "" || len(clientID) > 512 ||
		s.Stores == nil || s.Stores.Logout == nil {
		return sessionstate.ErrBindingMismatch
	}

	reference := sessionstate.Reference{Session: s.Handle, Record: s.Handle}
	for range 4 {
		index := sessionstate.LogoutIndex{
			Record: sessionstate.Record{Handle: s.Handle}, Session: s.Handle,
			IdentityReference: identity.Reference, Account: identity.Account,
		}
		expected := sessionstate.Revision(0)

		loaded, err := s.Stores.Logout.Load(ctx, reference)
		switch {
		case err == nil:
			if loaded.Value.IdentityReference != identity.Reference || loaded.Value.Account != identity.Account {
				return sessionstate.ErrBindingMismatch
			}

			index = loaded.Value
			expected = loaded.Revision
		case errors.Is(err, sessionstate.ErrNotFound):
		default:
			return err
		}

		if slices.Contains(index.OIDCClientIDs, clientID) {
			return nil
		}

		if len(index.OIDCClientIDs) >= 16 {
			return sessionstate.ErrActiveFlowLimit
		}

		index.OIDCClientIDs = append(index.OIDCClientIDs, clientID)
		sort.Strings(index.OIDCClientIDs)

		ttl := s.Anchor.Value.ExpiresAt.Sub(s.EvaluationTime())
		if ttl <= 0 {
			return sessionstate.ErrExpired
		}

		_, err = s.Stores.CommitLogoutIndex(ctx, sessionstate.CommitRequest[sessionstate.LogoutIndex]{
			Reference: reference, ExpectedRevision: expected, Value: index, TTL: ttl,
		})
		if errors.Is(err, sessionstate.ErrRevisionConflict) {
			continue
		}

		if err != nil {
			return err
		}

		s.Anchor, err = s.Stores.Session.Load(ctx, sessionstate.Reference{Session: s.Handle, Record: s.Handle})

		return err
	}

	return sessionstate.ErrRevisionConflict
}

// OIDCLogoutContext loads only the current session's typed logout index.
func (s *CanonicalSession) OIDCLogoutContext(ctx context.Context) (OIDCLogoutContext, error) {
	var result OIDCLogoutContext
	if s == nil || s.Stores == nil || s.Stores.Logout == nil || s.Handle == "" {
		return result, sessionstate.ErrBindingMismatch
	}

	identity, authenticated := s.Identity()
	reference := sessionstate.Reference{Session: s.Handle, Record: s.Handle}

	index, err := s.Stores.Logout.Load(ctx, reference)
	if errors.Is(err, sessionstate.ErrNotFound) {
		if authenticated {
			result.Identity = identity
		}

		return result, nil
	}

	if err != nil {
		return result, err
	}

	if !authenticated || index.Value.IdentityReference != identity.Reference ||
		index.Value.Account != identity.Account {
		return result, sessionstate.ErrBindingMismatch
	}

	result.Identity = identity

	result.ClientIDs = append([]string(nil), index.Value.OIDCClientIDs...)

	return result, nil
}

// EvaluationTime returns the session runtime clock used for TTL and assurance decisions.
func (s *CanonicalSession) EvaluationTime() time.Time {
	if s == nil || s.clock == nil {
		return time.Time{}
	}

	return s.clock.Now().UTC()
}

// RefreshAnchor reloads the current typed anchor after an indexed child mutation.
func (s *CanonicalSession) RefreshAnchor(ctx context.Context) error {
	if s == nil || s.Stores == nil || s.Handle == "" {
		return sessionstate.ErrBindingMismatch
	}

	anchor, err := s.Stores.Session.Load(
		ctx,
		sessionstate.Reference{Session: s.Handle, Record: s.Handle},
	)
	if err != nil {
		return err
	}

	s.Anchor = anchor

	return nil
}

// Identity returns a consistent authenticated identity binding from the session anchor.
func (s *CanonicalSession) Identity() (SessionIdentity, bool) {
	if s == nil || !s.Anchor.Value.Authenticated {
		return SessionIdentity{}, false
	}

	reference := strings.TrimSpace(s.Anchor.Value.IdentityReference)

	identity := s.Anchor.Value.Identity
	if reference == "" || strings.TrimSpace(identity.Account) == "" || strings.TrimSpace(identity.Subject) != reference {
		return SessionIdentity{}, false
	}

	return SessionIdentity{
		Reference: reference, Account: identity.Account, Subject: identity.Subject,
		DisplayName: identity.DisplayName, Protocol: identity.Protocol,
	}, true
}

// BackendAffinity returns only a complete authority capability held in the server-side anchor.
func (s *CanonicalSession) BackendAffinity() (SessionBackendAffinity, bool) {
	if s == nil {
		return SessionBackendAffinity{}, false
	}

	return sessionBackendAffinity(s.Anchor.Value.BackendAffinity)
}

// MFAIdentity returns the account whose factor proves assurance for this session.
func (s *CanonicalSession) MFAIdentity() (SessionIdentity, bool) {
	if s == nil || !s.Anchor.Value.Authenticated {
		return SessionIdentity{}, false
	}

	reference := strings.TrimSpace(s.Anchor.Value.MFAIdentityReference)

	identity := s.Anchor.Value.MFAIdentity
	if reference == "" || strings.TrimSpace(identity.Account) == "" ||
		strings.TrimSpace(identity.Subject) != reference || strings.TrimSpace(identity.Protocol) == "" {
		return SessionIdentity{}, false
	}

	return SessionIdentity{
		Reference: reference, Account: identity.Account, Subject: identity.Subject,
		DisplayName: identity.DisplayName, Protocol: identity.Protocol,
	}, true
}

// MFABackendAffinity returns the capability bound to the assurance identity.
func (s *CanonicalSession) MFABackendAffinity() (SessionBackendAffinity, bool) {
	if s == nil {
		return SessionBackendAffinity{}, false
	}

	return sessionBackendAffinity(s.Anchor.Value.MFABackendAffinity)
}

func sessionBackendAffinity(affinity sessionstate.BackendAffinitySummary) (SessionBackendAffinity, bool) {
	if strings.TrimSpace(affinity.OpaqueToken) == "" || strings.TrimSpace(affinity.Type) == "" ||
		strings.TrimSpace(affinity.Name) == "" || strings.TrimSpace(affinity.Protocol) == "" ||
		strings.TrimSpace(affinity.Authority) == "" {
		return SessionBackendAffinity{}, false
	}

	return SessionBackendAffinity{
		Type: affinity.Type, Name: affinity.Name, Protocol: affinity.Protocol,
		Authority: affinity.Authority, OpaqueToken: affinity.OpaqueToken,
	}, true
}

// Assurance returns only a complete, currently live assurance summary.
func (s *CanonicalSession) Assurance(now time.Time) (SessionAssurance, bool) {
	if s == nil {
		return SessionAssurance{}, false
	}

	summary := s.Anchor.Value.Assurance
	if summary.Level <= 0 || strings.TrimSpace(summary.Method) == "" || summary.ProvenAt.IsZero() ||
		summary.ExpiresAt.IsZero() || summary.ProvenAt.After(now) || !summary.ExpiresAt.After(now) {
		return SessionAssurance{}, false
	}

	return SessionAssurance{
		Level: summary.Level, Method: summary.Method, Scope: summary.Scope,
		ProvenAt: summary.ProvenAt, ExpiresAt: summary.ExpiresAt,
	}, true
}

// CommitAssurance atomically publishes one live MFA proof through the authenticated anchor revision.
func (s *CanonicalSession) CommitAssurance(ctx context.Context, proof SessionAssurance) error {
	if err := validateAssuranceSession(s); err != nil {
		return err
	}

	now := s.clock.Now().UTC()

	proof, err := validateAssuranceProof(proof, now, s.Anchor.Value.AbsoluteExpiresAt)
	if err != nil {
		return err
	}

	anchor := s.Anchor.Value

	ttl := anchor.ExpiresAt.Sub(now)
	if ttl <= 0 {
		return sessionstate.ErrExpired
	}

	anchor.Assurance = sessionstate.AssuranceSummary{
		Level: proof.Level, Method: proof.Method, Scope: proof.Scope,
		ProvenAt: proof.ProvenAt.UTC(), ExpiresAt: proof.ExpiresAt.UTC(),
	}

	revision, err := s.Stores.Session.Commit(ctx, sessionstate.CommitRequest[sessionstate.SessionAnchor]{
		Reference:        sessionstate.Reference{Session: s.Handle, Record: s.Handle},
		ExpectedRevision: s.Anchor.Revision, Value: anchor, TTL: ttl,
	})
	if err != nil {
		return err
	}

	anchor.Revision = revision
	s.Anchor = sessionstate.Versioned[sessionstate.SessionAnchor]{Value: anchor, Revision: revision}

	return nil
}

func validateAssuranceSession(s *CanonicalSession) error {
	if s == nil || s.Stores == nil || s.clock == nil || s.Handle == "" ||
		!s.Anchor.Value.Authenticated || strings.TrimSpace(s.Anchor.Value.IdentityReference) == "" {
		return fmt.Errorf("canonical assurance commit: unavailable authenticated session")
	}

	return nil
}

func validateAssuranceProof(
	proof SessionAssurance,
	now time.Time,
	absoluteExpiry time.Time,
) (SessionAssurance, error) {
	proof.Method = strings.TrimSpace(proof.Method)
	proof.Scope = strings.TrimSpace(proof.Scope)

	if proof.Level <= 0 || proof.Method == "" || len(proof.Method) > 64 || len(proof.Scope) > 256 ||
		proof.ProvenAt.IsZero() || proof.ProvenAt.After(now) || !proof.ExpiresAt.After(now) ||
		proof.ExpiresAt.After(absoluteExpiry) {
		return SessionAssurance{}, sessionstate.ErrBindingMismatch
	}

	return proof, nil
}

// CommitIdentity atomically publishes one successful identity binding through the anchor revision.
func (s *CanonicalSession) CommitIdentity(ctx context.Context, update IdentityUpdate) error {
	if s == nil || s.Stores == nil || s.clock == nil || s.Handle == "" {
		return fmt.Errorf("canonical identity commit: unavailable session")
	}

	validated, err := validateIdentityUpdate(update)
	if err != nil {
		return err
	}

	anchor := s.Anchor.Value

	ttl := anchor.ExpiresAt.Sub(s.clock.Now())
	if ttl <= 0 {
		return sessionstate.ErrExpired
	}

	anchor.Authenticated = true
	anchor.IdentityReference = validated.identity.Subject
	anchor.Identity = validated.identity
	anchor.BackendAffinity = validated.affinity
	anchor.MFAIdentityReference = validated.mfaIdentity.Subject
	anchor.MFAIdentity = validated.mfaIdentity
	anchor.MFABackendAffinity = validated.mfaAffinity

	revision, err := s.Stores.Session.Commit(ctx, sessionstate.CommitRequest[sessionstate.SessionAnchor]{
		Reference:        sessionstate.Reference{Session: s.Handle, Record: s.Handle},
		ExpectedRevision: s.Anchor.Revision, Value: anchor, TTL: ttl,
	})
	if err != nil {
		return err
	}

	anchor.Revision = revision
	s.Anchor = sessionstate.Versioned[sessionstate.SessionAnchor]{Value: anchor, Revision: revision}

	return nil
}

type validatedIdentityUpdate struct {
	identity    sessionstate.IdentitySummary
	mfaIdentity sessionstate.IdentitySummary
	affinity    sessionstate.BackendAffinitySummary
	mfaAffinity sessionstate.BackendAffinitySummary
}

func validateIdentityUpdate(update IdentityUpdate) (validatedIdentityUpdate, error) {
	var validated validatedIdentityUpdate

	identity, err := normalizedSessionIdentity(SessionIdentity{
		Reference: update.Reference, Account: update.Account, Subject: update.Subject,
		DisplayName: update.DisplayName, Protocol: update.Protocol,
	})
	if err != nil {
		return validated, err
	}

	validated.identity = sessionstate.IdentitySummary{
		Account: identity.Account, Subject: identity.Subject,
		DisplayName: identity.DisplayName, Protocol: identity.Protocol,
	}

	validated.affinity, err = backendAffinitySummary(update.BackendAffinity)
	if err != nil {
		return validatedIdentityUpdate{}, err
	}

	if update.MFAIdentity == nil {
		if update.MFABackendAffinity != nil {
			return validatedIdentityUpdate{}, sessionstate.ErrBindingMismatch
		}

		validated.mfaIdentity = validated.identity
		validated.mfaAffinity = validated.affinity

		return validated, nil
	}

	mfaIdentity, err := normalizedSessionIdentity(*update.MFAIdentity)
	if err != nil {
		return validatedIdentityUpdate{}, err
	}

	validated.mfaIdentity = sessionstate.IdentitySummary{
		Account: mfaIdentity.Account, Subject: mfaIdentity.Subject,
		DisplayName: mfaIdentity.DisplayName, Protocol: mfaIdentity.Protocol,
	}

	validated.mfaAffinity, err = backendAffinitySummary(update.MFABackendAffinity)
	if err != nil {
		return validatedIdentityUpdate{}, err
	}

	return validated, nil
}

func normalizedSessionIdentity(identity SessionIdentity) (SessionIdentity, error) {
	identity.Reference = strings.TrimSpace(identity.Reference)
	identity.Account = strings.TrimSpace(identity.Account)
	identity.Subject = strings.TrimSpace(identity.Subject)

	identity.Protocol = strings.TrimSpace(identity.Protocol)
	if identity.Reference == "" || identity.Account == "" || identity.Subject != identity.Reference ||
		identity.Protocol == "" || len(identity.Reference) > 512 || len(identity.Account) > 512 ||
		len(identity.Subject) > 512 || len(identity.DisplayName) > 512 || len(identity.Protocol) > 64 {
		return SessionIdentity{}, sessionstate.ErrBindingMismatch
	}

	return identity, nil
}

func backendAffinitySummary(affinity *SessionBackendAffinity) (sessionstate.BackendAffinitySummary, error) {
	if affinity == nil {
		return sessionstate.BackendAffinitySummary{}, nil
	}

	if strings.TrimSpace(affinity.Type) == "" || strings.TrimSpace(affinity.Name) == "" ||
		strings.TrimSpace(affinity.Protocol) == "" || strings.TrimSpace(affinity.Authority) == "" ||
		strings.TrimSpace(affinity.OpaqueToken) == "" {
		return sessionstate.BackendAffinitySummary{}, sessionstate.ErrBindingMismatch
	}

	return sessionstate.BackendAffinitySummary{
		Type: affinity.Type, Name: affinity.Name, Protocol: affinity.Protocol,
		Authority: affinity.Authority, OpaqueToken: affinity.OpaqueToken,
	}, nil
}
