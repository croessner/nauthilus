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

package commonv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

type commonRoundTripCase struct {
	name       string
	message    proto.Message
	newMessage func() proto.Message
}

func TestCommonMessagesRoundTrip(t *testing.T) {
	t.Parallel()

	for _, testCase := range commonRoundTripCases() {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			data, err := proto.Marshal(testCase.message)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			roundTripped := testCase.newMessage()
			if err := proto.Unmarshal(data, roundTripped); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if !proto.Equal(testCase.message, roundTripped) {
				t.Fatalf("roundtrip mismatch:\n got: %v\nwant: %v", roundTripped, testCase.message)
			}
		})
	}
}

func commonRoundTripCases() []commonRoundTripCase {
	return []commonRoundTripCase{
		newBackendRefRoundTripCase(),
		newOperationStatusRoundTripCase(),
		{
			name:       "error detail",
			message:    &ErrorDetail{Field: "code", Reason: "invalid"},
			newMessage: func() proto.Message { return &ErrorDetail{} },
		},
		{
			name:       "attribute values",
			message:    &AttributeValues{Values: []string{"one", "two"}},
			newMessage: func() proto.Message { return &AttributeValues{} },
		},
	}
}

func newBackendRefRoundTripCase() commonRoundTripCase {
	return commonRoundTripCase{
		name: "backend ref",
		message: &BackendRef{
			Type:        "ldap",
			Name:        "default",
			Protocol:    "imap",
			Authority:   "authority-a",
			OpaqueToken: "opaque-ref",
		},
		newMessage: func() proto.Message { return &BackendRef{} },
	}
}

func newOperationStatusRoundTripCase() commonRoundTripCase {
	return commonRoundTripCase{
		name: "operation status",
		message: &OperationStatus{
			Result:             OperationResult_OPERATION_RESULT_TEMPFAIL,
			ErrorCode:          "backend_timeout",
			SafeMessage:        "Temporary backend failure",
			EdgeRequestId:      "edge-request",
			AuthorityRequestId: "authority-request",
			Details: []*ErrorDetail{
				{Field: "username", Reason: "missing"},
			},
		},
		newMessage: func() proto.Message { return &OperationStatus{} },
	}
}
