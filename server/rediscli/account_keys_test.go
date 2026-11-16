// Copyright (C) 2026 Christian Roessner
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

package rediscli

import (
	"errors"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/testing/redisslot"
)

func TestSlotSiblingKeySharesTheClusterSlot(t *testing.T) {
	for _, prefix := range []string{"nt:", "", "{nt}:", "a}b{c}:", "x{:", "pre{fix:"} {
		key := prefix + "affected_accounts"

		sibling, err := SlotSiblingKey(prefix, key, "retention")
		if err != nil {
			t.Fatalf("SlotSiblingKey(%q) error: %v", key, err)
		}

		if got, want := redisslot.Slot(sibling), redisslot.Slot(key); got != want {
			t.Fatalf("sibling %q has slot %d, key %q has slot %d", sibling, got, key, want)
		}

		// Prefix-scoped ACLs keep working unless the prefix itself contains an opening brace.
		if !strings.Contains(prefix, "{") && !strings.HasPrefix(sibling, prefix) {
			t.Fatalf("sibling %q does not start with prefix %q", sibling, prefix)
		}
	}
}

func TestSlotSiblingKeyRejectsKeysWithoutExactSibling(t *testing.T) {
	// "{}" is an empty tag (the whole key is hashed) and a stray "}" would cut a wrapping tag short.
	for _, prefix := range []string{"{}x:", "a}b:"} {
		key := prefix + "affected_accounts"
		if sibling, err := SlotSiblingKey(prefix, key, "retention"); !errors.Is(err, ErrNoSlotSibling) {
			t.Fatalf("SlotSiblingKey(%q) = %q, %v; want ErrNoSlotSibling", key, sibling, err)
		}
	}
}

func TestAffectedAccountsRetentionKeyLayout(t *testing.T) {
	key, err := GetAffectedAccountsRetentionKey("nt:")
	if err != nil || key != "nt:{nt:affected_accounts}:retention" {
		t.Fatalf("retention key = %q, %v", key, err)
	}
}
