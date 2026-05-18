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

// Package prototest provides descriptor assertions for protobuf contract tests.
package prototest

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// AssertPackage verifies the protobuf package name.
func AssertPackage(t *testing.T, fileDescriptor protoreflect.FileDescriptor, expected string) {
	t.Helper()

	if got := string(fileDescriptor.Package()); got != expected {
		t.Fatalf("unexpected proto package: got %q want %q", got, expected)
	}
}

// Message returns a named top-level message descriptor or fails the test.
func Message(
	t *testing.T,
	fileDescriptor protoreflect.FileDescriptor,
	messageName protoreflect.Name,
) protoreflect.MessageDescriptor {
	t.Helper()

	message := fileDescriptor.Messages().ByName(messageName)
	if message == nil {
		t.Fatalf("%s message not found in descriptor", messageName)
	}

	return message
}

// Service returns a named top-level service descriptor or fails the test.
func Service(
	t *testing.T,
	fileDescriptor protoreflect.FileDescriptor,
	serviceName protoreflect.Name,
) protoreflect.ServiceDescriptor {
	t.Helper()

	service := fileDescriptor.Services().ByName(serviceName)
	if service == nil {
		t.Fatalf("%s service not found in descriptor", serviceName)
	}

	return service
}

// AssertFieldNumber verifies that a field exists with the expected number.
func AssertFieldNumber(
	t *testing.T,
	message protoreflect.MessageDescriptor,
	fieldName protoreflect.Name,
	expectedNumber protoreflect.FieldNumber,
) protoreflect.FieldDescriptor {
	t.Helper()

	field := message.Fields().ByName(fieldName)
	if field == nil {
		t.Fatalf("%s field not found in %s", fieldName, message.Name())
	}

	if got := field.Number(); got != expectedNumber {
		t.Fatalf(
			"unexpected field number for %s.%s: got %d want %d",
			message.Name(),
			fieldName,
			got,
			expectedNumber,
		)
	}

	return field
}

// AssertMessageField verifies field number and message type.
func AssertMessageField(
	t *testing.T,
	message protoreflect.MessageDescriptor,
	fieldName protoreflect.Name,
	expectedNumber protoreflect.FieldNumber,
	expectedType protoreflect.FullName,
) {
	t.Helper()

	field := AssertFieldNumber(t, message, fieldName, expectedNumber)
	if field.Message() == nil {
		t.Fatalf("%s.%s should be a message field", message.Name(), fieldName)
	}

	if got := field.Message().FullName(); got != expectedType {
		t.Fatalf("unexpected type for %s.%s: got %q want %q", message.Name(), fieldName, got, expectedType)
	}
}

// AssertMapValueMessage verifies that a map field points at the expected value message type.
func AssertMapValueMessage(
	t *testing.T,
	message protoreflect.MessageDescriptor,
	fieldName protoreflect.Name,
	expectedNumber protoreflect.FieldNumber,
	expectedType protoreflect.FullName,
) {
	t.Helper()

	field := AssertFieldNumber(t, message, fieldName, expectedNumber)
	if !field.IsMap() {
		t.Fatalf("%s.%s should be a map field", message.Name(), fieldName)
	}

	valueField := field.Message().Fields().ByName("value")
	if valueField == nil || valueField.Message() == nil {
		t.Fatalf("%s.%s map value should be a message", message.Name(), fieldName)
	}

	if got := valueField.Message().FullName(); got != expectedType {
		t.Fatalf("unexpected map value type for %s.%s: got %q want %q", message.Name(), fieldName, got, expectedType)
	}
}
