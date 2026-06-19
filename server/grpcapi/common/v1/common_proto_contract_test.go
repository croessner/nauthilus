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

	"github.com/croessner/nauthilus/v3/server/grpcapi/internal/prototest"

	"google.golang.org/protobuf/reflect/protoreflect"
)

const commonProtoPackage = "nauthilus.common.v1"

func TestCommonProtoContract(t *testing.T) {
	t.Parallel()

	fileDescriptor := File_server_grpcapi_common_v1_common_proto

	prototest.AssertPackage(t, fileDescriptor, commonProtoPackage)
	assertOperationResultValues(t)
	assertErrorDetailShape(t, fileDescriptor)
	assertOperationStatusShape(t, fileDescriptor)
	assertAttributeValuesShape(t, fileDescriptor)
	assertBackendRefShape(t, fileDescriptor)
}

func assertOperationResultValues(t *testing.T) {
	t.Helper()

	cases := []struct {
		name  string
		value OperationResult
		want  int32
	}{
		{name: "unspecified", value: OperationResult_OPERATION_RESULT_UNSPECIFIED, want: 0},
		{name: "ok", value: OperationResult_OPERATION_RESULT_OK, want: 1},
		{name: "fail", value: OperationResult_OPERATION_RESULT_FAIL, want: 2},
		{name: "tempfail", value: OperationResult_OPERATION_RESULT_TEMPFAIL, want: 3},
		{name: "denied", value: OperationResult_OPERATION_RESULT_DENIED, want: 4},
		{name: "not_found", value: OperationResult_OPERATION_RESULT_NOT_FOUND, want: 5},
		{name: "conflict", value: OperationResult_OPERATION_RESULT_CONFLICT, want: 6},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := int32(testCase.value); got != testCase.want {
				t.Fatalf("unexpected enum value: got %d want %d", got, testCase.want)
			}
		})
	}
}

func assertErrorDetailShape(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	message := prototest.Message(t, fileDescriptor, "ErrorDetail")
	prototest.AssertFieldNumber(t, message, "field", 1)
	prototest.AssertFieldNumber(t, message, "reason", 2)
}

func assertOperationStatusShape(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	message := prototest.Message(t, fileDescriptor, "OperationStatus")
	prototest.AssertFieldNumber(t, message, "result", 1)
	prototest.AssertFieldNumber(t, message, "error_code", 2)
	prototest.AssertFieldNumber(t, message, "safe_message", 3)
	prototest.AssertFieldNumber(t, message, "edge_request_id", 4)
	prototest.AssertFieldNumber(t, message, "authority_request_id", 5)
	prototest.AssertMessageField(t, message, "details", 6, "nauthilus.common.v1.ErrorDetail")
}

func assertAttributeValuesShape(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	message := prototest.Message(t, fileDescriptor, "AttributeValues")
	prototest.AssertFieldNumber(t, message, "values", 1)
}

func assertBackendRefShape(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	message := prototest.Message(t, fileDescriptor, "BackendRef")
	prototest.AssertFieldNumber(t, message, "type", 1)
	prototest.AssertFieldNumber(t, message, "name", 2)
	prototest.AssertFieldNumber(t, message, "protocol", 3)
	prototest.AssertFieldNumber(t, message, "authority", 4)
	prototest.AssertFieldNumber(t, message, "opaque_token", 5)
}
