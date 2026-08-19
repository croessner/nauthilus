// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/redis/go-redis/v9"
)

const (
	canonicalAnchorSchemaVersion    uint8 = 1
	canonicalIdleTTL                      = 30 * time.Minute
	canonicalAbsoluteTTL                  = 7 * 24 * time.Hour
	canonicalRememberAbsoluteTTL          = 30 * 24 * time.Hour
	canonicalRevocationTombstoneTTL       = 5 * time.Minute
)

// CanonicalSession is one loaded anchor and its exclusively typed repositories.
type CanonicalSession struct {
	Handle  sessionstate.Handle
	Anchor  sessionstate.Versioned[sessionstate.SessionAnchor]
	Stores  *sessionstate.RedisStores
	clock   sessionstate.Clock
	runtime *CanonicalRuntime
}

// PurgeBrowser removes the canonical browser envelope after an explicit session-ending action.
func (s *CanonicalSession) PurgeBrowser(writer http.ResponseWriter) {
	if s == nil || s.runtime == nil {
		return
	}

	s.runtime.PurgeBrowser(writer)
}

// Revoke tombstones the canonical anchor before deleting its indexed current-v1 children.
// Browser representations are purged even when Redis revocation fails.
func (s *CanonicalSession) Revoke(ctx context.Context, writer http.ResponseWriter) error {
	if s == nil || s.Stores == nil || s.Handle == "" || writer == nil {
		return ErrEnvelopeConfiguration
	}

	defer s.PurgeBrowser(writer)

	return s.Stores.RevokeSession(ctx, sessionstate.RevocationRequest{
		Reference:        sessionstate.Reference{Session: s.Handle, Record: s.Handle},
		ExpectedRevision: s.Anchor.Revision,
		TombstoneTTL:     canonicalRevocationTombstoneTTL,
		Children:         canonicalOwnedChildren(s.Handle, s.Anchor.Value),
	})
}

func canonicalOwnedChildren(
	session sessionstate.Handle,
	anchor sessionstate.SessionAnchor,
) []sessionstate.OwnedReference {
	children := make([]sessionstate.OwnedReference, 0,
		len(anchor.OIDCFlows)+len(anchor.SAMLFlows)+len(anchor.SelfServiceFlows)+len(anchor.Enrollments)+
			len(anchor.StepUps)+len(anchor.Ceremonies)+len(anchor.TOTPRecovery)+len(anchor.LogoutIndexes),
	)
	children = appendCanonicalOwnedChildren(children, sessionstate.OwnerOIDCFlow, session, anchor.OIDCFlows)
	children = appendCanonicalOwnedChildren(children, sessionstate.OwnerSAMLFlow, session, anchor.SAMLFlows)
	children = appendCanonicalOwnedChildren(
		children,
		sessionstate.OwnerSelfServiceFlow,
		session,
		anchor.SelfServiceFlows,
	)
	children = appendCanonicalOwnedChildren(children, sessionstate.OwnerEnrollment, session, anchor.Enrollments)
	children = appendCanonicalOwnedChildren(children, sessionstate.OwnerStepUp, session, anchor.StepUps)
	children = appendCanonicalOwnedChildren(children, sessionstate.OwnerWebAuthnCeremony, session, anchor.Ceremonies)
	children = appendCanonicalOwnedChildren(children, sessionstate.OwnerTOTPRecovery, session, anchor.TOTPRecovery)
	children = appendCanonicalOwnedChildren(children, sessionstate.OwnerConsent, session, anchor.LogoutIndexes)

	return children
}

func appendCanonicalOwnedChildren(
	children []sessionstate.OwnedReference,
	owner sessionstate.Owner,
	session sessionstate.Handle,
	handles []sessionstate.Handle,
) []sessionstate.OwnedReference {
	for _, handle := range handles {
		children = append(children, sessionstate.OwnedReference{
			Owner:     owner,
			Reference: sessionstate.Reference{Session: session, Record: handle},
		})
	}

	return children
}

// CanonicalRuntime owns the sole browser envelope and server-side anchor lifecycle.
type CanonicalRuntime struct {
	codec     *EnvelopeCodec
	stores    *sessionstate.RedisStores
	clock     sessionstate.Clock
	generator sessionstate.HandleGenerator
	secure    bool
}

// NewCanonicalRuntime validates the envelope and typed Redis store configuration.
func NewCanonicalRuntime(
	secret []byte,
	keyEpoch uint16,
	client redis.UniversalClient,
	prefix string,
	clock sessionstate.Clock,
	generator sessionstate.HandleGenerator,
	secure bool,
) (*CanonicalRuntime, error) {
	codec, err := NewEnvelopeCodec(secret, keyEpoch)
	if err != nil {
		return nil, err
	}

	if clock == nil || generator == nil || client == nil {
		return nil, ErrEnvelopeConfiguration
	}

	digestInput := append(append([]byte(nil), secret...), []byte("/browser-session-keyspace/v1")...)
	digestSecret := sha256.Sum256(digestInput)
	clear(digestInput)

	stores, err := sessionstate.NewRedisStores(client, digestSecret[:], clock, sessionstate.RedisStoreConfig{
		Prefix: prefix + ":browser-session",
	})
	if err != nil {
		return nil, err
	}

	return &CanonicalRuntime{codec: codec, stores: stores, clock: clock, generator: generator, secure: secure}, nil
}

// Create commits a fresh anchor before emitting its canonical envelope.
func (r *CanonicalRuntime) Create(
	ctx context.Context,
	writer http.ResponseWriter,
	remember bool,
) (*CanonicalSession, error) {
	if r == nil || r.stores == nil || writer == nil {
		return nil, ErrEnvelopeConfiguration
	}

	handle, err := r.generator.NewHandle()
	if err != nil {
		return nil, err
	}

	now := r.clock.Now().UTC()

	absoluteTTL := canonicalAbsoluteTTL
	if remember {
		absoluteTTL = canonicalRememberAbsoluteTTL
	}

	anchor := sessionstate.SessionAnchor{
		Record: sessionstate.Record{Handle: handle, ExpiresAt: now.Add(canonicalIdleTTL)}, SchemaVersion: canonicalAnchorSchemaVersion,
		CreatedAt: now, LastTouchedAt: now, IdleExpiresAt: now.Add(canonicalIdleTTL),
		AbsoluteExpiresAt: now.Add(absoluteTTL),
	}
	reference := sessionstate.Reference{Session: handle, Record: handle}

	revision, err := r.stores.Session.Commit(ctx, sessionstate.CommitRequest[sessionstate.SessionAnchor]{
		Reference: reference, Value: anchor, TTL: canonicalIdleTTL,
	})
	if err != nil {
		return nil, err
	}

	anchor.Revision = revision

	envelope := Envelope{Version: CurrentEnvelopeVersion, Session: handle, KeyEpoch: r.codec.keyEpoch}

	encoded, err := r.codec.Encode(definitions.SecureDataCookieName, envelope)
	if err != nil {
		_ = r.stores.Session.Delete(ctx, sessionstate.DeleteRequest{Reference: reference, ExpectedRevision: revision})

		return nil, err
	}

	responseCookie := canonicalHTTPCookie(definitions.SecureDataCookieName, encoded, 0, r.secure)
	if len(responseCookie.String()) >= EnvelopeHardLimitBytes {
		_ = r.stores.Session.Delete(ctx, sessionstate.DeleteRequest{Reference: reference, ExpectedRevision: revision})

		return nil, fmt.Errorf("%w: cookie header size %d", ErrEnvelopeRejected, len(responseCookie.String()))
	}

	http.SetCookie(writer, responseCookie)

	return &CanonicalSession{
		Handle: handle, Anchor: sessionstate.Versioned[sessionstate.SessionAnchor]{Value: anchor, Revision: revision},
		Stores: r.stores, clock: r.clock, runtime: r,
	}, nil
}

// Open validates exactly one canonical envelope and loads its live anchor.
func (r *CanonicalRuntime) Open(ctx context.Context, request *http.Request) (*CanonicalSession, error) {
	if r == nil || r.stores == nil || request == nil {
		return nil, ErrEnvelopeConfiguration
	}

	if len(request.CookiesNamed(definitions.WebAuthnCeremonyCookieName)) != 0 {
		return nil, ErrEnvelopeRejected
	}

	cookies := request.CookiesNamed(definitions.SecureDataCookieName)
	if len(cookies) != 1 {
		return nil, ErrEnvelopeRejected
	}

	envelope, err := r.codec.Decode(definitions.SecureDataCookieName, cookies[0].Value)
	if err != nil {
		return nil, err
	}

	reference := sessionstate.Reference{Session: envelope.Session, Record: envelope.Session}

	anchor, err := r.stores.Session.Load(ctx, reference)
	if err != nil {
		return nil, errors.Join(ErrEnvelopeRejected, err)
	}

	if anchor.Value.SchemaVersion != canonicalAnchorSchemaVersion || anchor.Value.Handle != envelope.Session {
		return nil, errors.Join(ErrEnvelopeRejected, sessionstate.ErrBindingMismatch)
	}

	return &CanonicalSession{
		Handle: envelope.Session, Anchor: anchor, Stores: r.stores, clock: r.clock, runtime: r,
	}, nil
}

// PurgeBrowser deletes every pre-cutover and canonical browser representation.
func (r *CanonicalRuntime) PurgeBrowser(writer http.ResponseWriter) {
	if writer == nil {
		return
	}

	http.SetCookie(writer, canonicalHTTPCookie(definitions.SecureDataCookieName, "", -1, r.secure))
	http.SetCookie(writer, canonicalHTTPCookie(definitions.WebAuthnCeremonyCookieName, "", -1, r.secure))
}

func canonicalHTTPCookie(name string, value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}
