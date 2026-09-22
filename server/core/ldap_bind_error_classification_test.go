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
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	nautherrors "github.com/croessner/nauthilus/v4/server/errors"
	"github.com/go-ldap/ldap/v3"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// newLDAPBindErrorTestManager builds the smallest manager that can classify a
// bind error. The logger stays nil so the debug helper short-circuits.
func newLDAPBindErrorTestManager() (*ldapManagerImpl, *AuthState, trace.Span) {
	mcfg := new(mockConfig)
	lm := &ldapManagerImpl{
		poolName: "test",
		deps:     AuthDeps{Cfg: mcfg},
	}

	auth := &AuthState{deps: lm.deps}
	auth.Runtime.GUID = "test-guid"

	_, span := noop.NewTracerProvider().Tracer("test").Start(context.Background(), "test")

	return lm, auth, span
}

// ldapBindErrorCase describes one failed bind and how it must be classified.
type ldapBindErrorCase struct {
	name string
	err  error
	// verdict is true when the failure is a statement about the password.
	verdict bool
	// technical is true when the error must be classified as a backend
	// failure, so the request answers TempFail instead of a rejection.
	technical bool
}

// ldapBindErrorCases covers the failure shapes a bind can produce: protocol
// rejections, transport faults, cancelled contexts, and errors no layer
// classified.
func ldapBindErrorCases() []ldapBindErrorCase {
	return []ldapBindErrorCase{
		{
			name:    "invalid credentials is the only credential verdict",
			err:     &ldap.Error{ResultCode: uint16(ldap.LDAPResultInvalidCredentials), Err: errors.New("invalid credentials")},
			verdict: true,
		},
		{
			name: "ldap server down is not a credential verdict",
			err:  &ldap.Error{ResultCode: uint16(ldap.LDAPResultServerDown), Err: errors.New("connection closed")},
		},
		{
			name: "ldap busy is not a credential verdict",
			err:  &ldap.Error{ResultCode: uint16(ldap.LDAPResultBusy), Err: errors.New("server busy")},
		},
		{
			name:      "bare context deadline is technical",
			err:       context.DeadlineExceeded,
			technical: true,
		},
		{
			name:      "wrapped context deadline is technical",
			err:       fmt.Errorf("ldap bind: %w", context.DeadlineExceeded),
			technical: true,
		},
		{
			name:      "cancelled context is technical",
			err:       context.Canceled,
			technical: true,
		},
		{
			name:      "closed connection is technical",
			err:       io.EOF,
			technical: true,
		},
		{
			name:      "network operation error is technical",
			err:       &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET},
			technical: true,
		},
		{
			name: "unclassified error is still not a credential verdict",
			err:  errors.New("something unexpected"),
		},
	}
}

// TestLDAPBindErrorOnlyInvalidCredentialsIsAVerdict pins the rule that decides
// whether a failed bind counts against the user: only an LDAP protocol
// rejection with LDAPResultInvalidCredentials may answer "wrong password"
// (err == nil). Every transport failure has to surface as an error, because a
// nil error here is read by the caller as a credential rejection and feeds
// brute-force accounting for what is really an outage.
func TestLDAPBindErrorOnlyInvalidCredentialsIsAVerdict(t *testing.T) {
	for _, tc := range ldapBindErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			lm, auth, span := newLDAPBindErrorTestManager()

			authenticated, err := lm.handleLDAPPassDBBindError(auth, span, tc.err)

			if authenticated {
				t.Fatalf("a failed bind must never report authentication, got authenticated=true")
			}

			if tc.verdict {
				if err != nil {
					t.Fatalf("invalid credentials must answer a credential verdict (nil error), got %v", err)
				}

				return
			}

			if err == nil {
				t.Fatalf("%v was rendered as a wrong password: a nil error here counts the failure against the user", tc.err)
			}

			if tc.technical && !nautherrors.IsBackendTechnicalFailure(err) {
				t.Fatalf("%v must be classified as a technical backend failure so the request answers TempFail", tc.err)
			}
		})
	}
}
