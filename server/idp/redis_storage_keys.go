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

package idp

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

const (
	// oidcSubjectSlotDigestDomain domain-separates subject hash tags from every other token digest.
	oidcSubjectSlotDigestDomain = "nauthilus-oidc-token-subject\x00"
	// oidcSubjectEpochKeyKind names the per-subject revocation epoch inside a subject slot.
	oidcSubjectEpochKeyKind = "epoch"
	// oidcSubjectEpochFloor is the epoch of a subject without an epoch key and the lower bound of every valid
	// epoch.
	//
	// Epochs issued before the subject-slot layout were INCR counters that started at 0 and grew by one per
	// user-wide revocation. Even one revocation per millisecond for thirty years stays below 10^12, so no
	// earlier token can carry an epoch at or above the floor. Every token issued before the layout change
	// is therefore rejected, whether it was revoked or not. The value stays far below the int64 range of
	// INCR and the exact-integer range of Lua numbers.
	oidcSubjectEpochFloor = "1000000000000"
)

// subjectEpochFloorValue is the numeric form of oidcSubjectEpochFloor used for range checks.
var subjectEpochFloorValue = mustParseSubjectEpoch(oidcSubjectEpochFloor)

// subjectEpochAdvanceScript starts a missing epoch at the floor before incrementing it, so the first
// revocation of a subject yields floor+1 instead of 1. It touches a single key.
const subjectEpochAdvanceScript = `
redis.call('SET', KEYS[1], ARGV[1], 'NX')
return redis.call('INCR', KEYS[1])
`

// mustParseSubjectEpoch converts the compile-time epoch floor and fails fast on an invalid constant.
func mustParseSubjectEpoch(value string) int64 {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		panic(err)
	}

	return parsed
}

// isCurrentSubjectEpoch accepts a token epoch only when it equals the current subject epoch and is not
// below the floor. Missing, malformed, and pre-floor epochs are rejected.
func isCurrentSubjectEpoch(tokenEpoch string, currentEpoch string) bool {
	if tokenEpoch == "" || tokenEpoch != currentEpoch {
		return false
	}

	parsed, err := strconv.ParseInt(tokenEpoch, 10, 64)

	return err == nil && parsed >= subjectEpochFloorValue
}

// oidcTokenKeys owns the Redis Cluster key layout of epoch-bound OIDC token state.
//
// Every key that one Lua script or MULTI/EXEC transaction touches together lives in the hash slot of
// the owning subject (user or service client): the revocation epoch, the per-subject token indexes,
// the token records and the refresh-family state share the subject hash tag. Subjects therefore spread
// across the cluster while each atomic unit stays inside one slot.
//
// Bearer lookups only know a token reference, so each reference owns a single-key locator in its own
// slot that names the subject slot holding the token state. The locator never takes part in a
// multi-key operation.
type oidcTokenKeys struct {
	prefix string
}

// oidcSubjectKeys builds the keys inside one subject hash slot.
type oidcSubjectKeys struct {
	slot string
	base string
}

// oidcSubjectSlot derives the stable hash tag of one subject.
//
// The digest is unkeyed on purpose: a digest keyed with the rotatable storage secret would move the
// revocation epoch after a rotation and silently revive revoked tokens. It keeps arbitrary subject
// identifiers, including braces, out of the hash tag and gives every subject a fixed-length tag.
func oidcSubjectSlot(subject string) string {
	sum := sha256.Sum256([]byte(oidcSubjectSlotDigestDomain + subject))

	return hex.EncodeToString(sum[:])
}

// isHexDigest reports whether a value is exactly one lowercase hex-encoded SHA-256 digest.
func isHexDigest(value string) bool {
	if len(value) != hex.EncodedLen(sha256.Size) {
		return false
	}

	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}

	return true
}

// subject returns the key builder for the slot owned by one subject identifier.
func (k oidcTokenKeys) subject(subject string) oidcSubjectKeys {
	return k.subjectBySlot(oidcSubjectSlot(subject))
}

// subjectBySlot returns the key builder for an already resolved subject slot.
func (k oidcTokenKeys) subjectBySlot(slot string) oidcSubjectKeys {
	return oidcSubjectKeys{slot: slot, base: k.prefix + "oidc:subject:{" + slot + "}:"}
}

// locator returns the single-key pointer from a bearer reference to its subject slot.
func (k oidcTokenKeys) locator(reference string) string {
	return k.prefix + "oidc:token:{" + reference + "}:subject"
}

// epoch returns the subject-wide revocation epoch key.
func (o oidcSubjectKeys) epoch() string {
	return o.base + oidcSubjectEpochKeyKind
}

// index returns a per-subject collection key such as a token reference set.
func (o oidcSubjectKeys) index(kind string) string {
	return o.base + kind
}

// entry returns one keyed record inside the subject slot.
func (o oidcSubjectKeys) entry(kind string, value string) string {
	return o.base + kind + ":" + value
}

// owns reports whether a decoded session belongs to this subject slot.
func (o oidcSubjectKeys) owns(session *OIDCSession) bool {
	return session != nil && oidcSubjectSlot(session.UserID) == o.slot
}
