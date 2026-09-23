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

package registry

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

const operandTestFactID = "input.subject"

// TestPolicyExpressionPrecompilesPattern keeps one compiled pattern across validation, clones, and parents.
func TestPolicyExpressionPrecompilesPattern(t *testing.T) {
	expression, err := NewPolicyExpression(PolicyExpressionInput{
		FactID: operandTestFactID, Operator: ExpressionOperatorMatches,
		Values: []decision.Value{mustRegistryOperandString(t, "^admin-[0-9]+$")},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	if expression.pattern == nil || !expression.MatchPattern("admin-7") || expression.MatchPattern("user-7") {
		t.Fatal("matches expression did not precompile its operand")
	}

	parent, err := NewPolicyExpression(PolicyExpressionInput{Kind: ExpressionKindNot, Children: []PolicyExpression{expression}})
	if err != nil {
		t.Fatalf("NewPolicyExpression(not) error = %v", err)
	}

	if child := parent.Children()[0]; child.pattern != expression.pattern || !child.Valid() {
		t.Fatal("detached child clone lost or recompiled its shared pattern")
	}

	if clone := expression.clone(); clone.pattern != expression.pattern || !clone.Equal(expression) {
		t.Fatal("expression clone lost its shared pattern or equality")
	}
}

// TestPolicyExpressionRejectsUncompilableOperands keeps exact load-time rejection reasons for patterns and networks.
func TestPolicyExpressionRejectsUncompilableOperands(t *testing.T) {
	for _, test := range []struct {
		name     string
		operator ExpressionOperator
		operand  string
		reason   string
	}{
		{"invalid pattern", ExpressionOperatorMatches, "(", "matches operand must compile as a regular expression"},
		{
			"pattern over aggregate byte bound", ExpressionOperatorMatches,
			strings.Repeat("a", maximumExpressionValueBytes+1), "operands exceed the aggregate byte bound",
		},
		{"invalid network", ExpressionOperatorCIDRContains, "10.0.0.0/33", "cidr_contains requires one IP or CIDR operand"},
		{"hostname network", ExpressionOperatorCIDRContains, "example.org", "cidr_contains requires one IP or CIDR operand"},
	} {
		_, err := NewPolicyExpression(PolicyExpressionInput{
			FactID: operandTestFactID, FactKind: decision.ValueKindString, Operator: test.operator,
			Values: []decision.Value{mustRegistryOperandString(t, test.operand)},
		})
		if !errors.Is(err, ErrInvalidPolicyExpression) || !strings.Contains(err.Error(), test.reason) {
			t.Fatalf("%s: NewPolicyExpression() error = %v, want %v with reason %q", test.name, err, ErrInvalidPolicyExpression, test.reason)
		}
	}
}

// TestPolicyExpressionWithoutCompiledOperandIsInvalid defines expressions that bypassed the constructor.
func TestPolicyExpressionWithoutCompiledOperandIsInvalid(t *testing.T) {
	for _, operator := range []ExpressionOperator{ExpressionOperatorMatches, ExpressionOperatorCIDRContains} {
		expression := PolicyExpression{
			factID:   operandTestFactID,
			values:   []decision.Value{mustRegistryOperandString(t, "10.0.0.0/8")},
			kind:     ExpressionKindAttribute,
			operator: operator,
			factKind: decision.ValueKindString,
		}

		if expression.Valid() || expression.MatchPattern("10.0.0.0/8") || expression.Networks().Len() != 0 {
			t.Fatalf("%s expression without precompiled operands was valid or matched", operator)
		}
	}
}

// TestNetworkSetKeepsNetipSemantics keeps prefix, exact-address, zone, and IPv4-mapped behavior.
func TestNetworkSetKeepsNetipSemantics(t *testing.T) {
	integer := int64(8)

	integerValue, err := decision.NewValue(decision.ValueInput{Integer: &integer})
	if err != nil {
		t.Fatalf("NewValue(integer) error = %v", err)
	}

	set := NewNetworkSet([]decision.Value{
		mustRegistryOperandString(t, "10.1.2.3/8"),
		mustRegistryOperandString(t, "2001:db8::/32"),
		mustRegistryOperandString(t, "192.0.2.7"),
		mustRegistryOperandString(t, "fe80::1%eth0"),
		mustRegistryOperandString(t, "invalid"),
		integerValue,
	})
	if set.Len() != 4 {
		t.Fatalf("NetworkSet.Len() = %d, want 4 admitted operands", set.Len())
	}

	for _, test := range []struct {
		address string
		want    bool
	}{
		{"10.200.0.1", true},
		{"2001:db8::1", true},
		{"192.0.2.7", true},
		{"fe80::1%eth0", true},
		{"fe80::1", false},
		{"::ffff:10.200.0.1", false},
		{"::ffff:192.0.2.7", false},
		{"192.0.2.8", false},
	} {
		if got := set.Contains(netip.MustParseAddr(test.address)); got != test.want {
			t.Fatalf("NetworkSet.Contains(%s) = %t, want %t", test.address, got, test.want)
		}
	}

	if (NetworkSet{}).Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("empty NetworkSet matched an address")
	}
}

// mustRegistryOperandString constructs one strict string operand.
func mustRegistryOperandString(t *testing.T, text string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &text})
	if err != nil {
		t.Fatalf("NewValue(%q) error = %v", text, err)
	}

	return value
}
