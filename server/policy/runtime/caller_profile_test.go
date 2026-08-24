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

package runtime

import (
	"errors"
	"slices"
	"testing"
)

func TestPolicyCallerCredentialProfilesPreserveExactOAuthPrincipal(t *testing.T) {
	t.Parallel()

	want := []string{"Policy-Client@Example", "urn:client:service"}

	credentials, err := NewCredentialProfiles(want)
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	admission, err := NewAdmissionProfiles(want)
	if err != nil {
		t.Fatalf("NewAdmissionProfiles() error = %v", err)
	}

	expected := []string{"Policy-Client@Example", "urn:client:service"}
	if !slices.Equal(credentials.IDs(), expected) || !slices.Equal(admission.IDs(), expected) {
		t.Fatalf("profile identities = %v/%v, want exact %v", credentials.IDs(), admission.IDs(), expected)
	}
}

func TestCallerAdmissionProfilesRequireExactCredentialParity(t *testing.T) {
	t.Parallel()

	credentials, err := NewCredentialProfiles([]string{"registered", "unregistered"})
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	admission, err := NewAdmissionProfiles([]string{"registered"})
	if err != nil {
		t.Fatalf("NewAdmissionProfiles() error = %v", err)
	}

	if err = admission.ValidateCredentials(credentials); !errors.Is(err, ErrInvalidGeneration) {
		t.Fatalf("ValidateCredentials() error = %v, want ErrInvalidGeneration", err)
	}
}
