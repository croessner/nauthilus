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

// RequestSnapshot contains immutable, redacted request metadata visible to plugins.
type RequestSnapshot struct {
	Headers           map[string][]string
	Session           string
	ExternalSessionID string
	Service           string
	Protocol          string
	Method            string
	Username          string
	Account           string
	ClientIP          string
	ClientPort        string
	ClientHost        string
	UserAgent         string
	OIDCCID           string
	SAMLEntityID      string
	TLS               TLSInfo
	Runtime           RuntimeFlags
	HealthCheck       bool
}

// TLSInfo describes the accepted TLS state for a request.
type TLSInfo struct {
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
	Debug         bool
	LocalRequest  bool
	Authenticated bool
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
