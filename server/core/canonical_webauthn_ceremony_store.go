// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	webAuthnCeremonyTTL      = 5 * time.Minute
	webAuthnCeremonyLogin    = "login"
	webAuthnCeremonyRegister = "register"
)

type canonicalWebAuthnCeremonyStore struct {
	stores    *sessionstate.RedisStores
	generator sessionstate.HandleGenerator
	session   sessionstate.Handle
}

func newCanonicalWebAuthnCeremonyStore(
	stores *sessionstate.RedisStores,
	generator sessionstate.HandleGenerator,
	session sessionstate.Handle,
) *canonicalWebAuthnCeremonyStore {
	return &canonicalWebAuthnCeremonyStore{stores: stores, generator: generator, session: session}
}

func (s *canonicalWebAuthnCeremonyStore) Store(
	ctx context.Context,
	flow sessionstate.Handle,
	identity string,
	protocol string,
	kind string,
	data *webauthn.SessionData,
) (sessionstate.Handle, error) {
	if s == nil || s.stores == nil || s.generator == nil || data == nil {
		return "", fmt.Errorf("canonical webauthn ceremony: unavailable")
	}

	handle, err := s.generator.NewHandle()
	if err != nil {
		return "", err
	}

	payload, err := jsonIter.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("canonical webauthn ceremony: encode: %w", err)
	}

	reference := sessionstate.Reference{Session: s.session, Record: handle}

	record := sessionstate.CeremonyRecord{
		Record: sessionstate.Record{Handle: handle}, Session: s.session, Flow: flow,
		IdentityReference: identity, Protocol: protocol, Kind: kind, Attempt: 1, Payload: payload,
	}
	if _, err = s.stores.CommitCeremony(ctx, sessionstate.CommitRequest[sessionstate.CeremonyRecord]{
		Reference: reference, Value: record, TTL: webAuthnCeremonyTTL,
	}); err != nil {
		return "", err
	}

	return handle, nil
}

func (s *canonicalWebAuthnCeremonyStore) Take(
	ctx context.Context,
	handle sessionstate.Handle,
	flow sessionstate.Handle,
	identity string,
	protocol string,
	kind string,
) (*webauthn.SessionData, error) {
	if s == nil || s.stores == nil {
		return nil, fmt.Errorf("canonical webauthn ceremony: unavailable")
	}

	reference := sessionstate.Reference{Session: s.session, Record: handle}

	loaded, err := s.stores.Ceremony.Load(ctx, reference)
	if err != nil {
		return nil, err
	}

	consumed, err := s.stores.ConsumeCeremony(ctx, sessionstate.DeleteRequest{
		Reference: reference, ExpectedRevision: loaded.Revision,
	})
	if err != nil {
		return nil, err
	}

	record := consumed.Value
	if record.Flow != flow || record.IdentityReference != identity || record.Protocol != protocol || record.Kind != kind {
		return nil, sessionstate.ErrBindingMismatch
	}

	data := &webauthn.SessionData{}
	if err = jsonIter.Unmarshal(record.Payload, data); err != nil {
		return nil, errors.Join(sessionstate.ErrBindingMismatch, err)
	}

	return data, nil
}

// BeginCanonicalWebAuthnLogin creates one typed, parent-bound login ceremony.
func BeginCanonicalWebAuthnLogin(
	ctx context.Context,
	session *cookie.CanonicalSession,
	flow sessionstate.Handle,
	identity string,
	protocolName string,
	user *backend.User,
) (*protocol.CredentialAssertion, sessionstate.Handle, error) {
	if session == nil || session.Stores == nil || session.Handle == "" || flow == "" ||
		identity == "" || user == nil {
		return nil, "", sessionstate.ErrBindingMismatch
	}

	options, data, err := beginWebAuthnLoginOptions(user)
	if err != nil {
		return nil, "", err
	}

	store := newCanonicalWebAuthnCeremonyStore(
		session.Stores,
		sessionstate.NewRandomHandleGenerator(nil),
		session.Handle,
	)

	handle, err := store.Store(ctx, flow, identity, protocolName, webAuthnCeremonyLogin, data)
	if err != nil {
		return nil, "", err
	}

	return options, handle, nil
}

// CompleteCanonicalWebAuthnLogin consumes and verifies one typed login ceremony.
func CompleteCanonicalWebAuthnLogin(
	ctx *gin.Context,
	deps AuthDeps,
	session *cookie.CanonicalSession,
	ceremony sessionstate.Handle,
	flow sessionstate.Handle,
	identity string,
	protocolName string,
	protocolContext IDPMFAProtocolContext,
	user *backend.User,
	authState *AuthState,
) (*backend.User, bool) {
	if ctx == nil || session == nil || session.Stores == nil || ceremony == "" || flow == "" ||
		identity == "" || user == nil || authState == nil {
		return nil, false
	}

	store := newCanonicalWebAuthnCeremonyStore(session.Stores, nil, session.Handle)

	data, err := store.Take(
		ctx.Request.Context(),
		ceremony,
		flow,
		identity,
		protocolName,
		webAuthnCeremonyLogin,
	)
	if err != nil {
		LogIDPMFAuthResult(
			ctx,
			deps,
			protocolContext,
			user.Name,
			"webauthn",
			"WebAuthn session data is missing",
			false,
		)

		return nil, false
	}

	_, span := monittrace.New("nauthilus/core/webauthn").Start(
		ctx.Request.Context(),
		"webauthn.canonical_login_finish",
	)
	defer span.End()

	assertion, ok := finishWebAuthnLoginAssertion(
		ctx, deps, protocolContext, authState, user, data, span,
	)
	if !ok || !persistWebAuthnLoginCredentialUpdate(
		ctx, deps, protocolContext, authState, user, assertion,
	) {
		return nil, false
	}

	return user, true
}

// BeginCanonicalWebAuthnRegistration creates one typed, enrollment-bound registration ceremony.
func BeginCanonicalWebAuthnRegistration(
	ctx context.Context,
	deps AuthDeps,
	session *cookie.CanonicalSession,
	flow sessionstate.Handle,
	identity string,
	protocolName string,
	user *backend.User,
) (*protocol.CredentialCreation, sessionstate.Handle, error) {
	if session == nil || session.Stores == nil || session.Handle == "" || flow == "" ||
		identity == "" || user == nil {
		return nil, "", sessionstate.ErrBindingMismatch
	}

	options, data, err := beginRegistrationOptions(deps, user)
	if err != nil {
		return nil, "", err
	}

	store := newCanonicalWebAuthnCeremonyStore(
		session.Stores, sessionstate.NewRandomHandleGenerator(nil), session.Handle,
	)

	handle, err := store.Store(ctx, flow, identity, protocolName, webAuthnCeremonyRegister, data)
	if err != nil {
		return nil, "", err
	}

	return options, handle, nil
}

// CompleteCanonicalWebAuthnRegistration consumes and persists one typed registration ceremony.
//
//nolint:gocyclo // Registration completion is one revision-bound verification and publication boundary.
func CompleteCanonicalWebAuthnRegistration(
	ctx *gin.Context,
	deps AuthDeps,
	session *cookie.CanonicalSession,
	ceremony sessionstate.Handle,
	flow sessionstate.Handle,
	identity string,
	protocolName string,
	user *backend.User,
	authState *AuthState,
) error {
	if ctx == nil || session == nil || session.Stores == nil || ceremony == "" || flow == "" ||
		identity == "" || user == nil || authState == nil {
		return sessionstate.ErrBindingMismatch
	}

	store := newCanonicalWebAuthnCeremonyStore(session.Stores, nil, session.Handle)

	data, err := store.Take(
		ctx.Request.Context(), ceremony, flow, identity, protocolName, webAuthnCeremonyRegister,
	)
	if err != nil {
		return err
	}

	deviceName, response, ok := parseRegistrationFinishResponse(ctx)
	if !ok {
		return fmt.Errorf("canonical webauthn registration: invalid response")
	}

	credential, err := webAuthn.CreateCredential(user, *data, response)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, fmt.Sprintf("%+v", util.ProtoErrToFields(err)))

		return err
	}

	user.AddCredential(*credential, deviceName)

	if !persistRegistrationCredential(ctx, deps, authState, credential, deviceName) {
		return fmt.Errorf("canonical webauthn registration: persist credential")
	}

	if !updateRegistrationUserCache(ctx, deps, authState, user) {
		return fmt.Errorf("canonical webauthn registration: update cache")
	}

	authState.PurgeCacheFor(user.Name)

	return nil
}
