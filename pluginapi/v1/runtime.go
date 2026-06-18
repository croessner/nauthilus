// Copyright (C) 2026 Christian Roessner
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

package pluginapi

import "context"

// IDPInfo contains safe identity-provider policy inputs for a request.
type IDPInfo struct {
	RequestedScopes         []string
	UserGroups              []string
	AllowedClientScopes     []string
	AllowedClientGrantTypes []string
	GrantType               string
	ClientID                string
	ClientName              string
	RedirectURI             string
	MFAMethod               string
	MFACompleted            bool
}

// RequestDiagnostics contains bounded request outcome and diagnostic metadata.
type RequestDiagnostics struct {
	StatusMessage     string
	BruteForceName    string
	EnvironmentName   string
	LatencyMillis     int64
	BruteForceCounter uint
	HTTPStatus        int
}

// RequestSnapshot contains immutable, redacted request metadata visible to plugins.
type RequestSnapshot struct {
	Headers           map[string][]string
	IDP               IDPInfo
	Session           string
	ExternalSessionID string
	Service           string
	Protocol          string
	Method            string
	Username          string
	Account           string
	AccountField      string
	UniqueUserID      string
	DisplayName       string
	ClientIP          string
	ClientPort        string
	ClientNet         string
	ClientHost        string
	ClientID          string
	UserAgent         string
	LocalIP           string
	LocalPort         string
	OIDCCID           string
	SAMLEntityID      string
	AuthLoginAttempt  uint
	TLS               TLSInfo
	Diagnostics       RequestDiagnostics
	Runtime           RuntimeFlags
	HealthCheck       bool
}

// TLSLegacyInfo preserves safe legacy ssl_* request metadata without exposing server internals.
type TLSLegacyInfo struct {
	State            string
	SessionID        string
	ClientVerify     string
	ClientDN         string
	ClientCommonName string
	Issuer           string
	ClientNotBefore  string
	ClientNotAfter   string
	SubjectDN        string
	IssuerDN         string
	ClientSubjectDN  string
	ClientIssuerDN   string
	Protocol         string
	CipherSuite      string
	Serial           string
	Fingerprint      string
}

// TLSInfo describes the accepted TLS state for a request.
type TLSInfo struct {
	Legacy         TLSLegacyInfo
	ServerName     string
	CipherSuite    string
	PeerCommonName string
	PeerIssuer     string
	Version        string
	VerifiedChains int
	Enabled        bool
	Mutual         bool
}

// RuntimeFlags describes host-derived runtime conditions for a request snapshot.
type RuntimeFlags struct {
	Debug                    bool
	LocalRequest             bool
	NoAuth                   bool
	UserFound                bool
	Authenticated            bool
	Authorized               bool
	Repeating                bool
	RWP                      bool
	EnvironmentRejected      bool
	EnvironmentStageExpected bool
	SubjectStageExpected     bool
}

// RuntimeContext exposes an isolated read-only runtime context view.
type RuntimeContext interface {
	Get(string) (any, bool)
	Snapshot() map[string]any
}

// RuntimeDelta describes runtime context mutations returned by a plugin call.
type RuntimeDelta struct {
	Set    map[string]any
	Delete []string
}

// CredentialProvider gives request-scoped access to credential material.
type CredentialProvider interface {
	Password(context.Context) (Secret, bool)
}

// Secret exposes sensitive bytes only inside a caller-provided closure.
type Secret interface {
	WithBytes(func([]byte) error) error
	IsZero() bool
}
