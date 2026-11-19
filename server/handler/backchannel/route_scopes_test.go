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

package backchannel

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	mdauth "github.com/croessner/nauthilus/v4/server/middleware/auth"
	"github.com/croessner/nauthilus/v4/server/secret"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const (
	routeScopeUnrestrictedUser = "management"
	routeScopeSupportUser      = "support-console"
	routeScopeAuthUser         = "mail-frontend"
	routeScopeSecurityUser     = "abuse-desk"
	routeScopeReadUser         = "abuse-dashboard"
	routeScopeWriteUser        = "abuse-automation"
	routeScopePassword         = "route-scope-secret-1234"

	routeScopeOpenAPIPath = "/api/v1/openapi.yaml"
	routeScopeSupportPath = "/api/v1/support/authentication-attempts/search"
	routeScopeCachePath   = "/api/v1/cache/flush"
	routeScopeListPath    = "/api/v1/bruteforce/list"
	routeScopeFlushPath   = "/api/v1/bruteforce/flush"
	routeScopeJobPath     = "/api/v1/async/jobs/job-1"
)

// routeScopeConfig configures the unrestricted Basic credential and one scoped credential per route family.
func routeScopeConfig() *config.FileSettings {
	password := secret.New(routeScopePassword)

	return &config.FileSettings{Server: &config.ServerSection{BasicAuth: config.BackchannelBasicAuth{
		Enabled:  true,
		Username: routeScopeUnrestrictedUser,
		Password: password,
		Users: []config.BackchannelBasicAuthUser{
			{Username: routeScopeSupportUser, Password: password, Scopes: []string{definitions.ScopeHistoryRead}},
			{Username: routeScopeAuthUser, Password: password, Scopes: []string{definitions.ScopeAuthenticate}},
			{Username: routeScopeSecurityUser, Password: password, Scopes: []string{definitions.ScopeSecurity}},
			{Username: routeScopeReadUser, Password: password, Scopes: []string{definitions.ScopeSecurityRead}},
			{Username: routeScopeWriteUser, Password: password, Scopes: []string{definitions.ScopeSecurityWrite}},
		},
	}}}
}

// newRouteScopeRouter builds the real backchannel route tree over the scoped Basic configuration.
func newRouteScopeRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Cleanup(mdauth.SetCallerRejectionDelayForTest(time.Millisecond))

	router := gin.New()
	router.Use(gin.Recovery())

	err := Setup(router, &handlerdeps.Deps{
		Cfg:    routeScopeConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("backchannel setup failed: %v", err)
	}

	return router
}

// serveRouteScopeRequest sends one request with the Basic credential of username.
func serveRouteScopeRequest(router *gin.Engine, method string, path string, username string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(username, routeScopePassword)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	return response
}

// TestBackchannelRoutesAuthorizeBasicCredentialsByScope verifies that every route family answers to its own
// scopes: nauthilus:authenticate opens only the routes without a scope of their own, and no other route asks for it.
func TestBackchannelRoutesAuthorizeBasicCredentialsByScope(t *testing.T) {
	router := newRouteScopeRouter(t)

	tests := []struct {
		name     string
		method   string
		path     string
		username string
		refused  bool
	}{
		{name: "unrestricted credential reads the contract", method: http.MethodGet, path: routeScopeOpenAPIPath, username: routeScopeUnrestrictedUser},
		{name: "authenticate scope reads the contract", method: http.MethodGet, path: routeScopeOpenAPIPath, username: routeScopeAuthUser},
		{name: "support scope does not open the base group", method: http.MethodGet, path: routeScopeOpenAPIPath, username: routeScopeSupportUser, refused: true},
		{name: "security scope does not open the base group", method: http.MethodGet, path: routeScopeOpenAPIPath, username: routeScopeSecurityUser, refused: true},
		{name: "security scope flushes the cache without authenticate", method: http.MethodDelete, path: routeScopeCachePath, username: routeScopeSecurityUser},
		{name: "unrestricted credential flushes the cache", method: http.MethodDelete, path: routeScopeCachePath, username: routeScopeUnrestrictedUser},
		{name: "authenticate scope does not flush the cache", method: http.MethodDelete, path: routeScopeCachePath, username: routeScopeAuthUser, refused: true},
		{name: "support scope does not flush the cache", method: http.MethodDelete, path: routeScopeCachePath, username: routeScopeSupportUser, refused: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := serveRouteScopeRequest(router, tt.method, tt.path, tt.username)

			if tt.refused {
				assert.Equal(t, http.StatusForbidden, response.Code, response.Body.String())

				return
			}

			assert.NotEqual(t, http.StatusUnauthorized, response.Code, response.Body.String())
			assert.NotEqual(t, http.StatusForbidden, response.Code, response.Body.String())
		})
	}
}

// TestBackchannelSecurityRoutesSeparateReadFromWrite verifies that the read scope opens only listings, the write
// scope only mutations, both follow an asynchronous job, and the wider security scope still opens all of them.
func TestBackchannelSecurityRoutesSeparateReadFromWrite(t *testing.T) {
	router := newRouteScopeRouter(t)

	routes := []struct {
		name      string
		method    string
		path      string
		readOpen  bool
		writeOpen bool
	}{
		{name: "brute-force listing", method: http.MethodGet, path: routeScopeListPath, readOpen: true},
		{name: "filtered brute-force listing", method: http.MethodPost, path: routeScopeListPath, readOpen: true},
		{name: "brute-force flush", method: http.MethodDelete, path: routeScopeFlushPath, writeOpen: true},
		{name: "asynchronous brute-force flush", method: http.MethodDelete, path: routeScopeFlushPath + "/async", writeOpen: true},
		{name: "cache flush", method: http.MethodDelete, path: routeScopeCachePath, writeOpen: true},
		{name: "asynchronous cache flush", method: http.MethodDelete, path: routeScopeCachePath + "/async", writeOpen: true},
		{name: "asynchronous job status", method: http.MethodGet, path: routeScopeJobPath, readOpen: true, writeOpen: true},
	}

	for _, route := range routes {
		for username, open := range map[string]bool{
			routeScopeReadUser:     route.readOpen,
			routeScopeWriteUser:    route.writeOpen,
			routeScopeSecurityUser: true,
			routeScopeSupportUser:  false,
		} {
			t.Run(route.name+" as "+username, func(t *testing.T) {
				response := serveRouteScopeRequest(router, route.method, route.path, username)

				if refused := response.Code == http.StatusForbidden; refused == open {
					t.Fatalf("status = %d body = %s, want open = %t", response.Code, response.Body.String(), open)
				}

				assert.NotEqual(t, http.StatusUnauthorized, response.Code, response.Body.String())
			})
		}
	}
}

// TestBackchannelSupportRoutesNeedNoAuthenticateScope verifies that the support routes are reached with a support
// scope alone and stay closed to credentials that hold none, including the unrestricted one.
func TestBackchannelSupportRoutesNeedNoAuthenticateScope(t *testing.T) {
	router := newRouteScopeRouter(t)

	tests := []struct {
		username   string
		wantStatus int
	}{
		// No history source is configured, so an authorized caller is told exactly that.
		{username: routeScopeSupportUser, wantStatus: http.StatusServiceUnavailable},
		{username: routeScopeAuthUser, wantStatus: http.StatusForbidden},
		{username: routeScopeSecurityUser, wantStatus: http.StatusForbidden},
		{username: routeScopeUnrestrictedUser, wantStatus: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			response := serveRouteScopeRequest(router, http.MethodPost, routeScopeSupportPath, tt.username)

			assert.Equal(t, tt.wantStatus, response.Code, response.Body.String())
		})
	}
}

// TestBackchannelRejectsUnknownBasicCredential verifies that a wrong password of a scoped credential is a
// credential rejection, not a scope decision.
func TestBackchannelRejectsUnknownBasicCredential(t *testing.T) {
	router := newRouteScopeRouter(t)

	request := httptest.NewRequest(http.MethodPost, routeScopeSupportPath, strings.NewReader("{}"))
	request.SetBasicAuth(routeScopeSupportUser, "not-the-configured-password")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
}
