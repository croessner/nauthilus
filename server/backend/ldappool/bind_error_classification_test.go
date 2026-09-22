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

package ldappool

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/croessner/nauthilus/v4/server/errors"
	"github.com/go-ldap/ldap/v3"
)

// TestClassifyBindErrorUsesTheShapesGoLDAPActuallyDelivers pins the bind
// classifier against the error values go-ldap really produces, not against
// idealised ones.
//
// A load test banned source addresses that had only ever sent correct
// credentials. The cause was that these failures arrived unclassified and were
// read further up as rejected passwords. The two shapes seen most often were a
// context deadline and result code 200 "Network Error".
func TestClassifyBindErrorUsesTheShapesGoLDAPActuallyDelivers(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{
			name: "connection closed arrives as result code 200",
			err:  &ldap.Error{ResultCode: uint16(ldap.ErrorNetwork), Err: stderrors.New("ldap: connection closed")},
			want: errors.ErrBackendTemporaryFailure,
		},
		{
			name: "server down arrives as result code 81",
			err:  &ldap.Error{ResultCode: uint16(ldap.LDAPResultServerDown), Err: stderrors.New("connection lost")},
			want: errors.ErrBackendTemporaryFailure,
		},
		{
			name: "the go-ldap bind deadline says timed out, not timeout",
			err:  &ldap.Error{ResultCode: uint16(ldap.ErrorNetwork), Err: stderrors.New("ldap: connection timed out")},
			want: errors.ErrLDAPBindTimeout,
		},
		{
			name: "context deadline during the bind",
			err:  fmt.Errorf("ldap bind: %w", context.DeadlineExceeded),
			want: errors.ErrLDAPBindTimeout,
		},
		{
			name: "server side time limit exceeded",
			err:  &ldap.Error{ResultCode: uint16(ldap.LDAPResultTimeLimitExceeded), Err: stderrors.New("time limit exceeded")},
			want: errors.ErrLDAPBindTimeout,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyBindError(tc.err)

			if !stderrors.Is(got, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}

			if !errors.IsBackendTechnicalFailure(got) {
				t.Fatalf("%v must be a technical failure, or it is counted as a wrong password", tc.err)
			}
		})
	}
}

// TestClassifyBindErrorKeepsCredentialVerdicts pins the other direction: a
// result the directory itself produced must reach the next layer with its
// result code intact.
//
// Only code 49 is counted as a wrong password further up; 48 and 53 answer a
// temporary failure without counting. The point here is that the classifier
// must not swallow the code, because the layer above cannot tell a directory
// that answered from a bind that never happened once the code is gone.
func TestClassifyBindErrorKeepsCredentialVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{
			name: "invalid credentials",
			err:  &ldap.Error{ResultCode: uint16(ldap.LDAPResultInvalidCredentials), Err: stderrors.New("invalid credentials")},
		},
		{
			name: "inappropriate authentication",
			err:  &ldap.Error{ResultCode: uint16(ldap.LDAPResultInappropriateAuthentication), Err: stderrors.New("inappropriate authentication")},
		},
		{
			name: "unwilling to perform",
			err:  &ldap.Error{ResultCode: uint16(ldap.LDAPResultUnwillingToPerform), Err: stderrors.New("unwilling to perform")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyBindError(tc.err)

			if errors.IsBackendTechnicalFailure(got) {
				t.Fatalf("%v is a protocol verdict and must not be classified as technical", tc.err)
			}

			var ldapErr *ldap.Error
			if !stderrors.As(got, &ldapErr) {
				t.Fatalf("expected the LDAP result code to survive classification, got %v", got)
			}
		})
	}
}

// TestClassifyBindErrorLeavesUnknownShapesUnclassified documents the deliberate
// gap. go-ldap formats some read failures with %s, which destroys the wrapped
// error, so nothing here can recognise them. They stay unclassified on purpose:
// the pipeline still answers a temporary failure for any backend error, and the
// warn log for unclassified errors is what makes a new shape visible instead of
// silently counted.
func TestClassifyBindErrorLeavesUnknownShapesUnclassified(t *testing.T) {
	err := stderrors.New("unable to read LDAP response packet: EOF")

	got := classifyBindError(err)

	if !stderrors.Is(got, err) {
		t.Fatalf("an unknown shape must be passed through unchanged, got %v", got)
	}

	if errors.IsBackendTechnicalFailure(got) {
		t.Fatal("this shape is not recognised today; if it now is, tighten this test instead of deleting it")
	}
}
