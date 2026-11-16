// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package flow

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestDiagnosticFlowRefIsStableDomainSeparatedAndBounded pins the analytics flow reference contract.
func TestDiagnosticFlowRefIsStableDomainSeparatedAndBounded(t *testing.T) {
	const flowID = "flow-handle-for-test"

	got := DiagnosticFlowRef(flowID)
	if got != DiagnosticFlowRef(" "+flowID+" ") || len(got) != 32 {
		t.Fatalf("DiagnosticFlowRef() = %q, want a stable 32-character digest", got)
	}

	plain := sha256.Sum256([]byte(flowID))
	if strings.Contains(hex.EncodeToString(plain[:]), got) || strings.Contains(got, flowID) {
		t.Fatalf("DiagnosticFlowRef() = %q, want a domain-separated digest unrelated to the handle", got)
	}

	if DiagnosticFlowRef("") != "" || DiagnosticFlowRef("other-flow") == got {
		t.Fatal("DiagnosticFlowRef() must be empty for no flow and distinct per flow")
	}
}
