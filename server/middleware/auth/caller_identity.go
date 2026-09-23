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

package auth

import (
	"context"
	"encoding/base64"
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	presentedIdentityNone   = "none"
	presentedIdentityOther  = "other"
	presentedIdentityBearer = "bearer"
	presentedIdentityBasic  = "basic:"
)

// PresentedCredentialIdentity derives the identity that exempt callers are counted by from the first
// authorization value: the Basic username, or the scheme for Bearer tokens. A Bearer token itself is never
// used, because a guesser would present a new token each time; the password is never retained.
func PresentedCredentialIdentity(authorization []string) string {
	for _, value := range authorization {
		scheme, payload, ok := strings.Cut(strings.TrimSpace(value), " ")
		if !ok || strings.TrimSpace(payload) == "" {
			continue
		}

		switch strings.ToLower(scheme) {
		case "bearer":
			return presentedIdentityBearer
		case "basic":
			return presentedBasicIdentity(strings.TrimSpace(payload))
		default:
			return presentedIdentityOther
		}
	}

	return presentedIdentityNone
}

// presentedBasicIdentity extracts the Basic username and clears the decoded credential.
func presentedBasicIdentity(payload string) string {
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return presentedIdentityBasic
	}

	defer clear(decoded)

	username, _, _ := strings.Cut(string(decoded), ":")

	return presentedIdentityBasic + username
}

// transportPeerContextKey stores the TCP upstream address of the request's connection.
type transportPeerContextKey struct{}

// ContextWithTransportPeer records the TCP upstream address of a connection. The HTTP server sets it per
// connection, because http.Request.RemoteAddr carries the PROXY protocol source when PROXY is enabled.
func ContextWithTransportPeer(ctx context.Context, address string) context.Context {
	return context.WithValue(ctx, transportPeerContextKey{}, address)
}

// directPeerIP returns the address of the direct HTTP transport peer, ignoring every forwarding header and
// every PROXY protocol header. Without a recorded connection upstream it falls back to RemoteAddr.
func directPeerIP(ctx *gin.Context) string {
	if ctx == nil || ctx.Request == nil {
		return ""
	}

	if address, ok := ctx.Request.Context().Value(transportPeerContextKey{}).(string); ok && address != "" {
		return address
	}

	remoteAddr := strings.TrimSpace(ctx.Request.RemoteAddr)

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}

	return host
}
