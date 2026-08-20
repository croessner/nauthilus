// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package transportsecurity

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"google.golang.org/grpc/credentials"
)

type policyFakeTLSAuthInfo struct{}

// AuthType impersonates only the textual gRPC authentication type.
func (policyFakeTLSAuthInfo) AuthType() string {
	return "tls"
}

type policyHTTPProtectionTest struct {
	tlsState       *tls.ConnectionState
	forwardedProto []string
	name           string
	trustedProxy   bool
	wantProtected  bool
}

type policyGRPCProtectionTest struct {
	authInfo      credentials.AuthInfo
	name          string
	wantProtected bool
}

type policyMTLSIdentityTest struct {
	tlsState     *tls.ConnectionState
	name         string
	identity     string
	wantIdentity string
	wantVerified bool
}

// runPolicyHTTPProtectionTests checks HTTP protection cases through one assertion path.
func runPolicyHTTPProtectionTests(t *testing.T, tests []policyHTTPProtectionTest) {
	t.Helper()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			evidence := NewHTTP(test.tlsState, test.trustedProxy, test.forwardedProto, "")

			if evidence.Protected() != test.wantProtected {
				t.Fatalf("Protected() = %t, want %t", evidence.Protected(), test.wantProtected)
			}
		})
	}
}

// runPolicyGRPCProtectionTests checks gRPC protection cases through one assertion path.
func runPolicyGRPCProtectionTests(t *testing.T, tests []policyGRPCProtectionTest) {
	t.Helper()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			evidence := NewGRPC(test.authInfo, "")

			if evidence.Protected() != test.wantProtected {
				t.Fatalf("Protected() = %t, want %t", evidence.Protected(), test.wantProtected)
			}
		})
	}
}

// runPolicyMTLSIdentityTests checks verified identity cases through one assertion path.
func runPolicyMTLSIdentityTests(t *testing.T, tests []policyMTLSIdentityTest) {
	t.Helper()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			evidence := NewHTTP(test.tlsState, false, nil, test.identity)
			identity, verified := evidence.MTLSIdentity()

			if identity != test.wantIdentity {
				t.Fatalf("MTLSIdentity() identity = %q, want %q", identity, test.wantIdentity)
			}

			if verified != test.wantVerified {
				t.Fatalf("MTLSIdentity() verified = %t, want %t", verified, test.wantVerified)
			}
		})
	}
}

func TestPolicyBasicTransportRejectsPlaintextAndLoopback(t *testing.T) {
	t.Parallel()

	tests := []policyHTTPProtectionTest{
		{
			name:          "plaintext remote peer",
			wantProtected: false,
		},
		{
			name:          "plaintext loopback has no exception",
			wantProtected: false,
		},
		{
			name:          "incomplete direct TLS",
			tlsState:      &tls.ConnectionState{},
			wantProtected: false,
		},
		{
			name:          "completed direct TLS",
			tlsState:      &tls.ConnectionState{HandshakeComplete: true},
			wantProtected: true,
		},
	}

	runPolicyHTTPProtectionTests(t, tests)
}

func TestPolicyTrustedProxyRequiresExactForwardedHTTPS(t *testing.T) {
	t.Parallel()

	tests := []policyHTTPProtectionTest{
		{
			name:           "trusted proxy exact https",
			trustedProxy:   true,
			forwardedProto: []string{"https"},
			wantProtected:  true,
		},
		{
			name:           "trusted proxy normalized https",
			trustedProxy:   true,
			forwardedProto: []string{" HTTPS "},
			wantProtected:  true,
		},
		{
			name:           "untrusted proxy",
			forwardedProto: []string{"https"},
		},
		{
			name:         "missing forwarded proto",
			trustedProxy: true,
		},
		{
			name:           "plaintext forwarded proto",
			trustedProxy:   true,
			forwardedProto: []string{"http"},
		},
		{
			name:           "multiple header values",
			trustedProxy:   true,
			forwardedProto: []string{"https", "https"},
		},
		{
			name:           "comma separated duplicate",
			trustedProxy:   true,
			forwardedProto: []string{"https, https"},
		},
		{
			name:           "comma separated conflict",
			trustedProxy:   true,
			forwardedProto: []string{"https,http"},
		},
		{
			name:           "empty value",
			trustedProxy:   true,
			forwardedProto: []string{" "},
		},
	}

	runPolicyHTTPProtectionTests(t, tests)
}

func TestPolicyGRPCMTLSRequiresConcreteProtectedTLS(t *testing.T) {
	t.Parallel()

	tests := []policyGRPCProtectionTest{
		{
			name: "missing authentication info",
		},
		{
			name:     "fabricated TLS authentication type",
			authInfo: policyFakeTLSAuthInfo{},
		},
		{
			name:     "zero TLS info",
			authInfo: credentials.TLSInfo{},
		},
		{
			name: "incomplete TLS handshake",
			authInfo: credentials.TLSInfo{
				CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
			},
		},
		{
			name: "integrity only",
			authInfo: credentials.TLSInfo{
				State:          tls.ConnectionState{HandshakeComplete: true},
				CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.IntegrityOnly},
			},
		},
		{
			name: "privacy and integrity",
			authInfo: credentials.TLSInfo{
				State:          tls.ConnectionState{HandshakeComplete: true},
				CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
			},
			wantProtected: true,
		},
	}

	runPolicyGRPCProtectionTests(t, tests)
}

func TestPolicyMTLSIdentityRequiresVerifiedClientChain(t *testing.T) {
	t.Parallel()

	presentedCertificate := &x509.Certificate{Raw: []byte("presented")}
	verifiedState := &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{presentedCertificate},
		VerifiedChains:    [][]*x509.Certificate{{presentedCertificate}},
	}

	tests := []policyMTLSIdentityTest{
		{
			name:     "identity without TLS",
			identity: "spiffe://example.test/policy-client",
		},
		{
			name:     "identity without verified chain",
			tlsState: &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{{}}},
			identity: "spiffe://example.test/policy-client",
		},
		{
			name: "verified chain for another certificate",
			tlsState: &tls.ConnectionState{
				HandshakeComplete: true,
				PeerCertificates:  []*x509.Certificate{{Raw: []byte("presented")}},
				VerifiedChains:    [][]*x509.Certificate{{{Raw: []byte("different")}}},
			},
			identity: "spiffe://example.test/policy-client",
		},
		{
			name:     "verified chain without identity",
			tlsState: verifiedState,
		},
		{
			name:         "verified chain exports exact boundary identity",
			tlsState:     verifiedState,
			identity:     "spiffe://example.test/policy-client",
			wantIdentity: "spiffe://example.test/policy-client",
			wantVerified: true,
		},
	}

	runPolicyMTLSIdentityTests(t, tests)
}

func TestPolicyGRPCMTLSIdentityUsesVerifiedTLSState(t *testing.T) {
	t.Parallel()

	authInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{{}},
			VerifiedChains:    [][]*x509.Certificate{{{}}},
		},
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	}

	evidence := NewGRPC(authInfo, "policy-client.example.test")
	identity, verified := evidence.MTLSIdentity()

	if !evidence.Protected() {
		t.Fatal("Protected() = false, want true")
	}

	if identity != "policy-client.example.test" || !verified {
		t.Fatalf("MTLSIdentity() = (%q, %t), want exact verified identity", identity, verified)
	}
}
