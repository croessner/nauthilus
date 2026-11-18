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

package windowsource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/secret"
)

const oneSample = `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"instance":"a"},"value":[1,"2"]}]}}`

// newTestClient builds a client against handler with fixed credentials and bounds.
func newTestClient(t *testing.T, handler http.Handler, adjust func(*ClientConfig)) *Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	endpoint, _ := url.Parse(server.URL + "/base")
	cfg := ClientConfig{HTTP: server.Client(), Endpoint: endpoint, QueryPath: "/q", TimeParam: func(at time.Time) string { return at.UTC().Format(time.RFC3339) },
		MaxResponseBytes: 1 << 10, MaxSeries: 4}

	if adjust != nil {
		adjust(&cfg)
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() = %v", err)
	}

	return client
}

// TestClientNeverFollowsRedirects pins that a redirect is a rejection, so a configured endpoint cannot bounce the
// credentials to another host.
func TestClientNeverFollowsRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the redirect target must never be reached")
	}))
	t.Cleanup(target.Close)

	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}), nil)

	if _, _, err := client.Instant(context.Background(), "up", time.Now()); !errors.Is(err, ErrRejected) {
		t.Fatalf("Instant() error = %v, want a rejection", err)
	}
}

// TestClientSendsFixedHeadersAndCredentials pins the fixed headers, the bearer token over basic auth, and the path.
func TestClientSendsFixedHeadersAndCredentials(t *testing.T) {
	var seen *http.Request

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen = request.Clone(context.Background())
		_, _ = writer.Write([]byte(oneSample))
	})

	client := newTestClient(t, handler, func(cfg *ClientConfig) {
		cfg.Headers = map[string]string{TenantHeader: "t1"}
		cfg.BearerToken = secret.New("token")
		cfg.Username, cfg.Password = "user", secret.New("pass")
	})

	samples, truncated, err := client.Instant(context.Background(), "up", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil || truncated || len(samples) != 1 || samples[0].Value != 2 {
		t.Fatalf("Instant() = %v, %v, %v", samples, truncated, err)
	}

	if seen.URL.Path != "/base/q" || seen.Header.Get(TenantHeader) != "t1" || seen.Header.Get("Authorization") != "Bearer token" ||
		seen.URL.Query().Get("time") != "2026-01-02T03:04:05Z" {
		t.Fatalf("request = %s headers %v", seen.URL, seen.Header)
	}
}

// TestClientRejectsNegativeAndMalformedSamples pins that an implausible value is a rejection, never a count.
func TestClientRejectsNegativeAndMalformedSamples(t *testing.T) {
	for name, body := range map[string]string{
		"negative":  `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"-1"]}]}}`,
		"not a num": `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"x"]}]}}`,
		"matrix":    `{"status":"success","data":{"resultType":"matrix","result":[]}}`,
		"error":     `{"status":"error","data":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(body))
			}), nil)

			if _, _, err := client.Instant(context.Background(), "up", time.Now()); !errors.Is(err, ErrRejected) {
				t.Fatalf("Instant() error = %v, want a rejection", err)
			}
		})
	}
}

// TestNewClientRejectsIncompleteConfig pins the constructor boundary.
func TestNewClientRejectsIncompleteConfig(t *testing.T) {
	if _, err := NewClient(ClientConfig{}); err == nil {
		t.Fatal("an empty config must be rejected")
	}
}
