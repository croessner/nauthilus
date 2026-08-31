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

package decision_test

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

func TestTargetRequiresExactBoundedIdentifiers(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		action    string
		ok        bool
	}{
		{name: "auth builtin", namespace: "authn", action: "lookup_identity", ok: true},
		{name: "nested namespace", namespace: "mail.dkim2", action: "sign-message-instance", ok: true},
		{name: "uppercase namespace", namespace: "DKIM2", action: "sign"},
		{name: "empty namespace segment", namespace: "mail..dkim2", action: "sign"},
		{name: "uppercase action", namespace: "dkim2", action: "Sign"},
		{name: "adjacent action separators", namespace: "dkim2", action: "sign-_message"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := decision.NewTarget(test.namespace, test.action)
			if test.ok {
				if err != nil {
					t.Fatalf("NewTarget() error = %v", err)
				}

				if target.Namespace() != test.namespace || target.Action() != test.action {
					t.Fatalf("NewTarget() = %q, want %s/%s", target.String(), test.namespace, test.action)
				}

				return
			}

			if !errors.Is(err, decision.ErrInvalidTarget) {
				t.Fatalf("NewTarget() error = %v, want ErrInvalidTarget", err)
			}
		})
	}
}

func TestContractErrorsExposeStableCodeAndSafeField(t *testing.T) {
	_, err := decision.NewTarget("DKIM2", "sign")

	contractError := new(decision.ContractError)
	if !errors.As(err, &contractError) {
		t.Fatalf("NewTarget() error = %T, want *ContractError", err)
	}

	if contractError.Code() != decision.ErrorCodeInvalidTarget {
		t.Fatalf("ContractError.Code() = %q, want %q", contractError.Code(), decision.ErrorCodeInvalidTarget)
	}

	if contractError.Field() != "target.namespace" {
		t.Fatalf("ContractError.Field() = %q, want target.namespace", contractError.Field())
	}
}
