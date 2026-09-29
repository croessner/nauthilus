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

package core

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/peer"
)

// TestRequestClientIPFactsUseGRPCPeerFallback pins the host-normalized client address of gRPC requests
// that carry no client_ip: the observed peer is the fallback in every path and keeps its grpc_peer label.
func TestRequestClientIPFactsUseGRPCPeerFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	podPeer := &net.TCPAddr{IP: net.ParseIP("172.20.3.17"), Port: 41000}

	testCases := []struct {
		name          string
		clientIP      string
		transportPeer string
		contextPeer   net.Addr
		want          requestClientIPFacts
	}{
		{
			name: "context peer only", contextPeer: podPeer,
			want: grpcPeerClientIPFacts("172.20.3.17", requestPolicyClientIPSourceGRPCPeer, true),
		},
		{
			name: "boundary peer only", transportPeer: "172.20.3.17",
			want: grpcPeerClientIPFacts("172.20.3.17", requestPolicyClientIPSourceGRPCPeer, true),
		},
		{
			name: "boundary and context peer", transportPeer: "127.0.0.1",
			contextPeer: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000},
			want:        grpcPeerClientIPFacts("127.0.0.1", requestPolicyClientIPSourceGRPCPeer, true),
		},
		{
			name: "caller asserted address stays untrusted", clientIP: "198.51.100.7",
			transportPeer: "172.20.3.17", contextPeer: podPeer,
			want: grpcPeerClientIPFacts("198.51.100.7", requestPolicyClientIPSourceMetadata, false),
		},
		{
			name: "unix socket peer has no address", transportPeer: "/run/nauthilus/grpc.sock",
			contextPeer: &net.UnixAddr{Name: "/run/nauthilus/grpc.sock", Net: "unix"},
			want:        requestClientIPFacts{requestIPFacts: requestIPFacts{source: requestPolicyClientIPSourceGRPCPeer}},
		},
		{
			name: "no peer at all",
			want: requestClientIPFacts{requestIPFacts: requestIPFacts{source: requestPolicyClientIPSourceGRPCPeer}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			auth := &AuthState{}
			auth.Request.Service = definitions.ServGRPC
			auth.Request.ClientIP = testCase.clientIP
			auth.Request.Transport = AuthTransportContext{Kind: requestPolicyTransportGRPC, Peer: testCase.transportPeer}

			got := auth.requestClientIPFacts(grpcPeerGinContext(testCase.contextPeer))
			if got != testCase.want {
				t.Fatalf("requestClientIPFacts() = %#v, want %#v", got, testCase.want)
			}
		})
	}
}

// grpcPeerClientIPFacts builds one expected present client-IP fact set.
func grpcPeerClientIPFacts(address string, source string, trusted bool) requestClientIPFacts {
	return requestClientIPFacts{
		requestIPFacts: requestIPFacts{source: source, addr: netip.MustParseAddr(address), present: true},
		trusted:        trusted,
	}
}

// grpcPeerGinContext builds the private application request whose context optionally carries one gRPC peer.
func grpcPeerGinContext(address net.Addr) *gin.Context {
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	requestContext := context.Background()

	if address != nil {
		requestContext = peer.NewContext(requestContext, &peer.Peer{Addr: address})
	}

	ctx.Request = httptest.NewRequestWithContext(requestContext, http.MethodPost, "/grpc/auth/v1/LookupIdentity", http.NoBody)
	ctx.Request.RemoteAddr = ""

	return ctx
}
