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

	"github.com/croessner/nauthilus/server/config"
)

func TestNewHTTPClient_UsesDedicatedHTTPClientTLSSettings(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			HTTPClient: config.HTTPClient{
				TLS: config.HTTPClientTLS{
					SkipVerify:    true,
					MinTLSVersion: "TLS1.3",
					CipherSuites: []string{
						"TLS_AES_256_GCM_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					},
				},
			},
		},
	}

	client := NewHTTPClient(cfg)

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport type = %T, want *http.Transport", client.Transport)
	}

	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		t.Fatal("TLSClientConfig = nil, want configured TLS client config")
	}

	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("TLSClientConfig.InsecureSkipVerify = false, want true")
	}

	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLSClientConfig.MinVersion = %v, want %v", tlsConfig.MinVersion, tls.VersionTLS13)
	}

	wantCipherSuites := []uint16{
		tls.TLS_AES_256_GCM_SHA384,
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
