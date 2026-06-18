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

import "testing"

func TestBuildKeyAppliesPrefixWithoutChangingHashTag(t *testing.T) {
	key := BuildKey("ntc:", "acct:{acm-demo}alice:stepup")
	if key != "ntc:acct:{acm-demo}alice:stepup" {
		t.Fatalf("BuildKey() = %q, want prefixed key with hash tag preserved", key)
	}
}

func TestBuildKeysAppliesPrefixToAllKeys(t *testing.T) {
	keys := BuildKeys("ntc:", []string{"one", "two"})
	if len(keys) != 2 || keys[0] != "ntc:one" || keys[1] != "ntc:two" {
		t.Fatalf("BuildKeys() = %#v, want all keys prefixed", keys)
	}
}

func TestEnsureKeysInSameSlotPreservesCommonHashTag(t *testing.T) {
	keys := []string{"ntc:acct:{acm-demo}alice:ips", "ntc:acct:{acm-demo}alice:fails"}
	sameSlot := EnsureKeysInSameSlot(keys, "{native}")

	if sameSlot[0] != keys[0] || sameSlot[1] != keys[1] {
		t.Fatalf("EnsureKeysInSameSlot() = %#v, want existing common tag preserved", sameSlot)
	}
}

func TestEnsureKeysInSameSlotReplacesMismatchedHashTags(t *testing.T) {
	keys := []string{"ntc:acct:{left}alice:ips", "ntc:acct:{right}alice:fails"}
	sameSlot := EnsureKeysInSameSlot(keys, "{native}")

	want := []string{"ntc:acct:{native}alice:ips", "ntc:acct:{native}alice:fails"}
	if len(sameSlot) != len(want) || sameSlot[0] != want[0] || sameSlot[1] != want[1] {
		t.Fatalf("EnsureKeysInSameSlot() = %#v, want %#v", sameSlot, want)
	}
}
