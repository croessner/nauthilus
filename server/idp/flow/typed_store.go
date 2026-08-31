// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package flow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/sessionstate"
)

// TypedStore persists exactly one protocol family below one canonical browser session.
type TypedStore struct {
	stores   *sessionstate.RedisStores
	session  sessionstate.Handle
	protocol Protocol
	ttl      time.Duration
}

// NewTypedStore binds protocol flow persistence to one canonical session anchor.
func NewTypedStore(
	stores *sessionstate.RedisStores,
	session sessionstate.Handle,
	protocol Protocol,
	ttl time.Duration,
) *TypedStore {
	return &TypedStore{stores: stores, session: session, protocol: protocol, ttl: ttl}
}

// Load fetches one protocol-specific flow and rejects cross-session references.
func (s *TypedStore) Load(ctx context.Context, flowID string) (*State, error) {
	reference, err := s.reference(flowID)
	if err != nil {
		return nil, err
	}

	switch s.protocol {
	case FlowProtocolOIDC:
		versioned, loadErr := s.stores.OIDC.Load(ctx, reference)
		if loadErr != nil {
			return nil, loadErr
		}

		return stateFromOIDC(versioned), nil
	case FlowProtocolSAML:
		versioned, loadErr := s.stores.SAML.Load(ctx, reference)
		if loadErr != nil {
			return nil, loadErr
		}

		return stateFromSAML(versioned), nil
	case FlowProtocolInternal:
		versioned, loadErr := s.stores.SelfService.Load(ctx, reference)
		if loadErr != nil {
			return nil, loadErr
		}

		return stateFromSelfService(versioned), nil
	default:
		return nil, fmt.Errorf("typed flow store: unsupported protocol %q", s.protocol)
	}
}

// Save creates or revision-checks one protocol-specific flow record.
func (s *TypedStore) Save(ctx context.Context, state *State) error {
	return s.saveWithTTL(ctx, state, s.ttl)
}

func (s *TypedStore) saveWithTTL(ctx context.Context, state *State, ttl time.Duration) error {
	if state == nil || state.Protocol != s.protocol {
		return sessionstate.ErrBindingMismatch
	}

	reference, err := s.reference(state.FlowID)
	if err != nil {
		return err
	}

	switch s.protocol {
	case FlowProtocolOIDC:
		revision, commitErr := s.stores.CommitOIDCFlow(ctx, sessionstate.CommitRequest[sessionstate.OIDCFlow]{
			Reference:        reference,
			ExpectedRevision: sessionstate.Revision(state.Revision),
			Value:            oidcFromState(s.session, state),
			TTL:              ttl,
		})
		state.Revision = uint64(revision)

		return commitErr
	case FlowProtocolSAML:
		revision, commitErr := s.stores.CommitSAMLFlow(ctx, sessionstate.CommitRequest[sessionstate.SAMLFlow]{
			Reference:        reference,
			ExpectedRevision: sessionstate.Revision(state.Revision),
			Value:            samlFromState(s.session, state),
			TTL:              ttl,
		})
		state.Revision = uint64(revision)

		return commitErr
	case FlowProtocolInternal:
		revision, commitErr := s.stores.CommitSelfServiceFlow(
			ctx,
			sessionstate.CommitRequest[sessionstate.SelfServiceFlow]{
				Reference:        reference,
				ExpectedRevision: sessionstate.Revision(state.Revision),
				Value:            selfServiceFromState(s.session, state),
				TTL:              ttl,
			},
		)
		state.Revision = uint64(revision)

		return commitErr
	default:
		return fmt.Errorf("typed flow store: unsupported protocol %q", s.protocol)
	}
}

// Delete removes one flow only at its current revision.
func (s *TypedStore) Delete(ctx context.Context, flowID string) error {
	state, err := s.Load(ctx, flowID)
	if errors.Is(err, sessionstate.ErrNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	reference, err := s.reference(flowID)
	if err != nil {
		return err
	}

	request := sessionstate.DeleteRequest{
		Reference: reference, ExpectedRevision: sessionstate.Revision(state.Revision),
	}

	switch s.protocol {
	case FlowProtocolOIDC:
		return s.stores.DeleteOIDCFlow(ctx, request)
	case FlowProtocolSAML:
		return s.stores.DeleteSAMLFlow(ctx, request)
	case FlowProtocolInternal:
		return s.stores.DeleteSelfServiceFlow(ctx, request)
	default:
		return fmt.Errorf("typed flow store: unsupported protocol %q", s.protocol)
	}
}

// ConsumeOIDC atomically removes one revision-bound OIDC flow and its anchor index before returning it.
func (s *TypedStore) ConsumeOIDC(ctx context.Context, flowID string, expectedRevision uint64) (*State, error) {
	if s == nil {
		return nil, sessionstate.ErrBindingMismatch
	}

	return consumeTypedFlow(
		ctx, s, flowID, expectedRevision, FlowProtocolOIDC,
		s.stores.ConsumeOIDCFlow, stateFromOIDC,
	)
}

// ConsumeSAML atomically removes one revision-bound SAML flow and its anchor index before returning it.
func (s *TypedStore) ConsumeSAML(ctx context.Context, flowID string, expectedRevision uint64) (*State, error) {
	if s == nil {
		return nil, sessionstate.ErrBindingMismatch
	}

	return consumeTypedFlow(
		ctx, s, flowID, expectedRevision, FlowProtocolSAML,
		s.stores.ConsumeSAMLFlow, stateFromSAML,
	)
}

// ConsumeInternal atomically removes one revision-bound internal browser flow.
func (s *TypedStore) ConsumeInternal(ctx context.Context, flowID string, expectedRevision uint64) (*State, error) {
	if s == nil {
		return nil, sessionstate.ErrBindingMismatch
	}

	return consumeTypedFlow(
		ctx, s, flowID, expectedRevision, FlowProtocolInternal,
		s.stores.ConsumeSelfServiceFlow, stateFromSelfService,
	)
}

// consumeTypedFlow applies the shared revision-bound consume contract to one typed repository family.
func consumeTypedFlow[T any](
	ctx context.Context,
	store *TypedStore,
	flowID string,
	expectedRevision uint64,
	protocol Protocol,
	consume func(context.Context, sessionstate.DeleteRequest) (sessionstate.Versioned[T], error),
	restore func(sessionstate.Versioned[T]) *State,
) (*State, error) {
	if store.protocol != protocol {
		return nil, sessionstate.ErrBindingMismatch
	}

	reference, err := store.reference(flowID)
	if err != nil {
		return nil, err
	}

	versioned, err := consume(ctx, sessionstate.DeleteRequest{
		Reference: reference, ExpectedRevision: sessionstate.Revision(expectedRevision),
	})
	if err != nil {
		return nil, err
	}

	return restore(versioned), nil
}

// TouchTTL extends a live flow with the same revision and bounded parent lifetime.
func (s *TypedStore) TouchTTL(ctx context.Context, flowID string, ttl time.Duration) error {
	state, err := s.Load(ctx, flowID)
	if err != nil {
		return err
	}

	return s.saveWithTTL(ctx, state, ttl)
}

func (s *TypedStore) reference(flowID string) (sessionstate.Reference, error) {
	if s == nil || s.stores == nil {
		return sessionstate.Reference{}, fmt.Errorf("typed flow store: unavailable")
	}

	record := sessionstate.Handle(strings.TrimSpace(flowID))
	if record == "" || s.session == "" {
		return sessionstate.Reference{}, ErrEmptyFlowID
	}

	return sessionstate.Reference{Session: s.session, Record: record}, nil
}

func oidcFromState(session sessionstate.Handle, state *State) sessionstate.OIDCFlow {
	return sessionstate.OIDCFlow{
		Record: sessionstate.Record{Handle: sessionstate.Handle(state.FlowID)}, Session: session,
		FlowType: string(state.Type), CurrentStep: string(state.CurrentStep), AuthOutcome: string(state.AuthOutcome),
		CancelTarget: state.CancelTarget, ReturnTarget: state.ReturnTarget, CreatedAt: state.CreatedAt,
		ResumeTarget: state.metadataValue(FlowMetadataResumeTarget),
		UpdatedAt:    state.UpdatedAt, PendingMFA: state.PendingMFA, GrantType: state.GrantType,
		DeviceCode:           state.metadataValue(FlowMetadataDeviceCode),
		DeviceUserCodeDigest: state.metadataValue(FlowMetadataDeviceUserCodeDigest),
		ClientID:             state.metadataValue(FlowMetadataClientID), RedirectURI: state.metadataValue(FlowMetadataRedirectURI),
		Scopes: strings.Fields(state.metadataValue(FlowMetadataScope)), State: state.metadataValue(FlowMetadataState),
		Nonce: state.metadataValue(FlowMetadataNonce), ResponseType: state.metadataValue(FlowMetadataResponseType),
		Prompt: state.metadataValue(FlowMetadataPrompt), CodeChallenge: state.metadataValue(FlowMetadataCodeChallenge),
		CodeChallengeMethod: state.metadataValue(FlowMetadataCodeChallengeMethod),
		ConsentChallenge:    state.metadataValue(FlowMetadataConsentChallenge),
	}
}

func samlFromState(session sessionstate.Handle, state *State) sessionstate.SAMLFlow {
	return sessionstate.SAMLFlow{
		Record: sessionstate.Record{Handle: sessionstate.Handle(state.FlowID)}, Session: session,
		FlowType: string(state.Type), CurrentStep: string(state.CurrentStep), AuthOutcome: string(state.AuthOutcome),
		CancelTarget: state.CancelTarget, ReturnTarget: state.ReturnTarget, CreatedAt: state.CreatedAt,
		UpdatedAt: state.UpdatedAt, PendingMFA: state.PendingMFA,
		EntityID:      state.metadataValue(FlowMetadataSAMLEntityID),
		RequestID:     state.metadataValue(FlowMetadataSAMLRequestID),
		RequestDigest: state.metadataValue(FlowMetadataSAMLRequestDigest),
		RelayState:    state.metadataValue(FlowMetadataSAMLRelayState),
		Destination:   state.metadataValue(FlowMetadataSAMLDestination),
		OriginalURL:   state.metadataValue(FlowMetadataOriginalURL),
		ResumeTarget:  state.metadataValue(FlowMetadataResumeTarget),
	}
}

// selfServiceFromState maps one internal login flow into its dedicated durable record.
func selfServiceFromState(session sessionstate.Handle, state *State) sessionstate.SelfServiceFlow {
	return sessionstate.SelfServiceFlow{
		FlowType: string(state.Type), CurrentStep: string(state.CurrentStep),
		AuthOutcome: string(state.AuthOutcome), LoginTarget: state.ReturnTarget,
		ResumeTarget: state.metadataValue(FlowMetadataResumeTarget),
		Record:       sessionstate.Record{Handle: sessionstate.Handle(state.FlowID)}, Session: session,
		CreatedAt: state.CreatedAt, UpdatedAt: state.UpdatedAt,
	}
}

func stateFromOIDC(versioned sessionstate.Versioned[sessionstate.OIDCFlow]) *State {
	value := versioned.Value

	return &State{
		FlowID: string(value.Handle), Revision: uint64(versioned.Revision), GrantType: value.GrantType,
		CancelTarget: value.CancelTarget, ReturnTarget: value.ReturnTarget, Type: Type(value.FlowType),
		Protocol: FlowProtocolOIDC, CurrentStep: Step(value.CurrentStep), AuthOutcome: AuthOutcome(value.AuthOutcome),
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, PendingMFA: value.PendingMFA,
		Metadata: map[string]string{
			FlowMetadataResumeTarget: value.ResumeTarget,
			FlowMetadataClientID:     value.ClientID, FlowMetadataRedirectURI: value.RedirectURI,
			FlowMetadataScope: strings.Join(value.Scopes, " "), FlowMetadataState: value.State,
			FlowMetadataNonce: value.Nonce, FlowMetadataResponseType: value.ResponseType,
			FlowMetadataPrompt: value.Prompt, FlowMetadataCodeChallenge: value.CodeChallenge,
			FlowMetadataCodeChallengeMethod:  value.CodeChallengeMethod,
			FlowMetadataConsentChallenge:     value.ConsentChallenge,
			FlowMetadataDeviceCode:           value.DeviceCode,
			FlowMetadataDeviceUserCodeDigest: value.DeviceUserCodeDigest,
		},
	}
}

func stateFromSAML(versioned sessionstate.Versioned[sessionstate.SAMLFlow]) *State {
	value := versioned.Value

	return &State{
		FlowID: string(value.Handle), Revision: uint64(versioned.Revision), CancelTarget: value.CancelTarget,
		ReturnTarget: value.ReturnTarget, Type: Type(value.FlowType), Protocol: FlowProtocolSAML,
		CurrentStep: Step(value.CurrentStep), AuthOutcome: AuthOutcome(value.AuthOutcome),
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, PendingMFA: value.PendingMFA,
		Metadata: map[string]string{
			FlowMetadataSAMLEntityID:      value.EntityID,
			FlowMetadataSAMLRequestID:     value.RequestID,
			FlowMetadataSAMLRequestDigest: value.RequestDigest,
			FlowMetadataSAMLRelayState:    value.RelayState,
			FlowMetadataSAMLDestination:   value.Destination,
			FlowMetadataOriginalURL:       value.OriginalURL,
			FlowMetadataResumeTarget:      value.ResumeTarget,
		},
	}
}

// stateFromSelfService restores one internal login flow from its durable record.
func stateFromSelfService(versioned sessionstate.Versioned[sessionstate.SelfServiceFlow]) *State {
	value := versioned.Value

	return &State{
		FlowID: string(value.Handle), Revision: uint64(versioned.Revision), ReturnTarget: value.LoginTarget,
		Type: Type(value.FlowType), Protocol: FlowProtocolInternal, CurrentStep: Step(value.CurrentStep),
		AuthOutcome: AuthOutcome(value.AuthOutcome), CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		Metadata: map[string]string{FlowMetadataResumeTarget: value.ResumeTarget},
	}
}
