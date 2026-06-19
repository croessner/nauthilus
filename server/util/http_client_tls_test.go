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

package util

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
)

func TestNewHTTPClient_PreservesDefaultTransportBehavior(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{},
	}

	client := NewHTTPClient(cfg)
	transport := requireHTTPTransport(t, client)

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport type = %T, want *http.Transport", http.DefaultTransport)
	}

	if transport.DialContext == nil {
		t.Fatal("Transport.DialContext = nil, want default dialer")
	}

	if transport.ForceAttemptHTTP2 != defaultTransport.ForceAttemptHTTP2 {
		t.Fatalf("Transport.ForceAttemptHTTP2 = %v, want %v", transport.ForceAttemptHTTP2, defaultTransport.ForceAttemptHTTP2)
	}

	if transport.MaxIdleConns != defaultTransport.MaxIdleConns {
		t.Fatalf("Transport.MaxIdleConns = %d, want %d", transport.MaxIdleConns, defaultTransport.MaxIdleConns)
	}

	if transport.IdleConnTimeout != defaultTransport.IdleConnTimeout {
		t.Fatalf("Transport.IdleConnTimeout = %s, want %s", transport.IdleConnTimeout, defaultTransport.IdleConnTimeout)
	}

	if transport.TLSHandshakeTimeout != defaultTransport.TLSHandshakeTimeout {
		t.Fatalf("Transport.TLSHandshakeTimeout = %s, want %s", transport.TLSHandshakeTimeout, defaultTransport.TLSHandshakeTimeout)
	}

	if transport.ExpectContinueTimeout != defaultTransport.ExpectContinueTimeout {
		t.Fatalf("Transport.ExpectContinueTimeout = %s, want %s", transport.ExpectContinueTimeout, defaultTransport.ExpectContinueTimeout)
	}
}

func TestNewHTTPClient_UsesDedicatedHTTPClientTLSSettings(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			HTTPClient: config.HTTPClient{
				TLS: config.HTTPClientTLS{
					SkipVerify:    true,
					MinTLSVersion: "TLS1.2",
					CipherSuites: []string{
						"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					},
				},
			},
		},
	}

	client := NewHTTPClient(cfg)
	transport := requireHTTPTransport(t, client)

	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		t.Fatal("TLSClientConfig = nil, want configured TLS client config")
	}

	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("TLSClientConfig.InsecureSkipVerify = false, want true")
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLSClientConfig.MinVersion = %v, want %v", tlsConfig.MinVersion, tls.VersionTLS12)
	}

	wantCipherSuites := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}

	if len(tlsConfig.CipherSuites) != len(wantCipherSuites) {
		t.Fatalf("TLSClientConfig.CipherSuites length = %d, want %d", len(tlsConfig.CipherSuites), len(wantCipherSuites))
	}

	for index, want := range wantCipherSuites {
		if tlsConfig.CipherSuites[index] != want {
			t.Fatalf("TLSClientConfig.CipherSuites[%d] = %v, want %v", index, tlsConfig.CipherSuites[index], want)
		}
	}
}

func requireHTTPTransport(t *testing.T, client *http.Client) *http.Transport {
	t.Helper()

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport type = %T, want *http.Transport", client.Transport)
	}

	return transport
}
