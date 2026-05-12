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

package authv1

import (
	"testing"

	commonv1 "github.com/croessner/nauthilus/server/grpcapi/common/v1"

	"google.golang.org/protobuf/proto"
)

const (
	authResponseAttributeUID = "uid"
	authResponseAttributeID  = "1000"
	authResponseProtocolIMAP = "imap"
)

func TestAuthResponseRoundTripUsesCommonMessages(t *testing.T) {
	t.Parallel()

	response := &AuthResponse{
		Ok:              true,
		Decision:        AuthDecision_AUTH_DECISION_OK,
		Session:         "session-id",
		AccountField:    "account",
		TotpSecretField: "totp",
		Backend:         1,
		Attributes: map[string]*commonv1.AttributeValues{
			authResponseAttributeUID: {Values: []string{authResponseAttributeID}},
		},
		StatusMessage: "OK",
		BackendRef: &commonv1.BackendRef{
			Type:        "ldap",
			Name:        "default",
			Protocol:    authResponseProtocolIMAP,
			Authority:   "authority-a",
			OpaqueToken: "opaque-ref",
		},
	}

	data, err := proto.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var roundTripped AuthResponse
	if err := proto.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if !proto.Equal(response, &roundTripped) {
		t.Fatalf("roundtrip mismatch:\n got: %v\nwant: %v", &roundTripped, response)
	}
}

func TestAuthAttributeValuesAliasKeepsCallerSourceCompatibility(t *testing.T) {
	t.Parallel()

	response := &AuthResponse{
		Attributes: map[string]*AttributeValues{
			authResponseAttributeUID: {Values: []string{authResponseAttributeID}},
		},
	}

	if got := response.GetAttributes()[authResponseAttributeUID].GetValues()[0]; got != authResponseAttributeID {
		t.Fatalf("attribute value = %q, want %q", got, authResponseAttributeID)
	}
}
