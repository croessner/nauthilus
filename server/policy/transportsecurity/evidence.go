// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package transportsecurity classifies trusted Policy transport evidence.
package transportsecurity

import (
	"crypto/tls"
	"strings"

	"google.golang.org/grpc/credentials"
)

const forwardedProtoHTTPS = "https"

// Evidence is immutable trusted transport evidence produced at a protocol boundary.
type Evidence struct {
	mtlsIdentity string
	protected    bool
	mtlsVerified bool
}

// NewHTTP classifies direct HTTP TLS or explicitly trusted immediate-proxy evidence.
func NewHTTP(
	tlsState *tls.ConnectionState,
	rawImmediatePeerTrusted bool,
	forwardedProtoValues []string,
	normalizedMTLSIdentity string,
) Evidence {
	protected := completedTLS(tlsState) || trustedForwardedHTTPS(rawImmediatePeerTrusted, forwardedProtoValues)

	return newEvidence(protected, tlsState, normalizedMTLSIdentity)
}

// NewGRPC classifies concrete gRPC TLS authentication evidence.
func NewGRPC(authInfo credentials.AuthInfo, normalizedMTLSIdentity string) Evidence {
	tlsState, securityLevel, ok := grpcTLSState(authInfo)
	protected := ok && completedTLS(tlsState) && securityLevel == credentials.PrivacyAndIntegrity

	return newEvidence(protected, tlsState, normalizedMTLSIdentity)
}

// Protected reports whether the transport provides confidentiality and integrity.
func (e Evidence) Protected() bool {
	return e.protected
}

// MTLSIdentity returns the exact boundary-normalized identity only for a verified client chain.
func (e Evidence) MTLSIdentity() (string, bool) {
	return e.mtlsIdentity, e.mtlsVerified
}

// newEvidence gates mTLS identity export independently from transport protection.
func newEvidence(protected bool, tlsState *tls.ConnectionState, normalizedMTLSIdentity string) Evidence {
	evidence := Evidence{protected: protected}

	if !protected || normalizedMTLSIdentity == "" || !hasVerifiedClientChain(tlsState) {
		return evidence
	}

	evidence.mtlsIdentity = normalizedMTLSIdentity
	evidence.mtlsVerified = true

	return evidence
}

// completedTLS reports whether the supplied connection state completed its handshake.
func completedTLS(tlsState *tls.ConnectionState) bool {
	return tlsState != nil && tlsState.HandshakeComplete
}

// trustedForwardedHTTPS accepts one HTTPS value only from an explicitly trusted raw peer.
func trustedForwardedHTTPS(rawImmediatePeerTrusted bool, forwardedProtoValues []string) bool {
	if !rawImmediatePeerTrusted || len(forwardedProtoValues) != 1 {
		return false
	}

	return strings.EqualFold(strings.TrimSpace(forwardedProtoValues[0]), forwardedProtoHTTPS)
}

// grpcTLSState extracts state only from the concrete gRPC TLS authentication type.
func grpcTLSState(authInfo credentials.AuthInfo) (*tls.ConnectionState, credentials.SecurityLevel, bool) {
	switch tlsInfo := authInfo.(type) {
	case credentials.TLSInfo:
		return &tlsInfo.State, tlsInfo.SecurityLevel, true
	case *credentials.TLSInfo:
		if tlsInfo == nil {
			return nil, credentials.NoSecurity, false
		}

		return &tlsInfo.State, tlsInfo.SecurityLevel, true
	default:
		return nil, credentials.NoSecurity, false
	}
}

// hasVerifiedClientChain reports whether TLS verified a non-empty peer certificate chain.
func hasVerifiedClientChain(tlsState *tls.ConnectionState) bool {
	if !completedTLS(tlsState) || len(tlsState.PeerCertificates) == 0 {
		return false
	}

	presentedLeaf := tlsState.PeerCertificates[0]
	if presentedLeaf == nil {
		return false
	}

	for _, chain := range tlsState.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && chain[0].Equal(presentedLeaf) {
			return true
		}
	}

	return false
}
