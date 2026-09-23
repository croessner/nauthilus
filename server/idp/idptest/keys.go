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

// Package idptest provides an independent expectation of the IdP Redis Cluster key layout for tests.
//
// The helpers intentionally re-derive the documented layout instead of calling the production key
// builder, so a silent layout change breaks the tests that pin it.
package idptest

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// SubjectEpochFloor mirrors the documented epoch of a subject without an epoch key and the lower bound of
// every valid token epoch.
const SubjectEpochFloor = "1000000000000"

// subjectSlotDigestDomain mirrors the documented domain separator of subject hash tags.
const subjectSlotDigestDomain = "nauthilus-oidc-token-subject\x00"

// SubjectSlot returns the hash tag that groups all token state of one subject.
func SubjectSlot(subject string) string {
	sum := sha256.Sum256([]byte(subjectSlotDigestDomain + subject))

	return hex.EncodeToString(sum[:])
}

// SubjectKey returns one key inside the Redis Cluster slot of a subject.
func SubjectKey(prefix string, subject string, suffix string) string {
	return prefix + "oidc:subject:{" + SubjectSlot(subject) + "}:" + suffix
}

// TokenLocatorKey returns the single-key locator of a bearer token reference.
func TokenLocatorKey(prefix string, reference string) string {
	return prefix + "oidc:token:{" + reference + "}:subject"
}

// TokenLocatorPattern returns a regular expression for locators whose reference matches referencePattern.
func TokenLocatorPattern(prefix string, referencePattern string) string {
	const placeholder = "\x00"

	return strings.Replace(regexp.QuoteMeta(TokenLocatorKey(prefix, placeholder)), placeholder, referencePattern, 1)
}

// DynamicClientKey returns the record key of a dynamic client in its own slot.
func DynamicClientKey(prefix string, clientID string) string {
	return prefix + "oidc:dcr:client:{" + clientID + "}"
}

// Reference returns the index digest that test fixtures without a storage secret derive for a value.
func Reference(namespace string, value string) string {
	return rediscli.NewSecurityManager(secret.Value{}).IndexDigest(namespace, value)
}

// AuthorizationCodeKey returns the digest key of a single-use authorization code or consent challenge.
func AuthorizationCodeKey(prefix string, code string) string {
	return prefix + "oidc:code:" + Reference("oidc-authorization-code", code)
}

// DeviceCodeKey returns the request key of a device code in its own hash slot.
func DeviceCodeKey(prefix string, deviceCode string) string {
	return prefix + "oidc:device_code:{" + Reference("oidc-device-code", deviceCode) + "}"
}

// DeviceUserCodeKey returns the locator key of a normalized user code in its own hash slot.
func DeviceUserCodeKey(prefix string, userCode string) string {
	return prefix + "oidc:device_user_code:{" + Reference("oidc-device-user-code", userCode) + "}"
}
