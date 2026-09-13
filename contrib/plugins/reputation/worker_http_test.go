//go:build reputation_worker

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	serverconfig "github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// TestWorkerRoutesExcludeIdentityAndRequireMetricsCredentials proves the consumer exposes no authentication server.
func TestWorkerRoutesExcludeIdentityAndRequireMetricsCredentials(t *testing.T) {
	state := &stateOwner{}
	state.ready.Store(true)

	basic := &serverconfig.BasicAuth{Enabled: true, Username: "metrics", Password: secret.New("isolated-test-password")}
	handler := workerHandler(state, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), basic)

	for _, test := range []struct {
		path          string
		authenticated bool
		expected      int
	}{
		{"/healthz", false, http.StatusOK}, {"/metrics", false, http.StatusUnauthorized},
		{"/metrics", true, http.StatusOK}, {"/login", true, http.StatusNotFound},
		{"/.well-known/openid-configuration", true, http.StatusNotFound},
		{"/api/v1/auth/json", true, http.StatusNotFound},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		if test.authenticated {
			request.SetBasicAuth("metrics", "isolated-test-password")
		}

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)

		if test.path == "/healthz" {
			var body map[string]string
			requireNoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))

			if body["status"] != "up" {
				t.Fatal("worker health response broke the deployed healthcheck contract")
			}
		}

		if recorder.Code != test.expected {
			t.Fatalf("worker route %s returned %d, want %d", test.path, recorder.Code, test.expected)
		}
	}
}
