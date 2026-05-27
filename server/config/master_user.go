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

package config

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

const (
	// DefaultMasterUserFormat matches the nauthilus-director default backend login format.
	DefaultMasterUserFormat = "{user}*{master_user}"

	// MasterUserTargetPlaceholder marks the requested target account in a master-user login format.
	MasterUserTargetPlaceholder = "{user}"

	// MasterUserPlaceholder marks the authenticating master account in a master-user login format.
	MasterUserPlaceholder = "{master_user}"
)

type masterUserLoginFormat struct {
	prefix      string `mapstructure:"-"`
	separator   string `mapstructure:"-"`
	suffix      string `mapstructure:"-"`
	targetFirst bool   `mapstructure:"-"`
}

// ValidMasterUserFormat reports whether a format contains exactly one target and one master placeholder.
func ValidMasterUserFormat(userFormat string) bool {
	_, ok := parseMasterUserLoginFormat(userFormat)

	return ok
}

// ParseMasterUserLogin applies a master-user format to the supplied login name.
func ParseMasterUserLogin(username string, userFormat string) (targetUser string, masterUser string, ok bool) {
	loginFormat, ok := parseMasterUserLoginFormat(userFormat)
	if !ok {
		return "", "", false
	}

	return loginFormat.parse(username)
}

// isMasterUserFormat adapts the master-user format grammar for go-playground validator.
func isMasterUserFormat(fl validator.FieldLevel) bool {
	return ValidMasterUserFormat(fl.Field().String())
}

// parseMasterUserLoginFormat turns the public placeholder format into fixed match boundaries.
func parseMasterUserLoginFormat(userFormat string) (masterUserLoginFormat, bool) {
	if strings.Count(userFormat, MasterUserTargetPlaceholder) != 1 {
		return masterUserLoginFormat{}, false
	}

	if strings.Count(userFormat, MasterUserPlaceholder) != 1 {
		return masterUserLoginFormat{}, false
	}

	targetStart := strings.Index(userFormat, MasterUserTargetPlaceholder)
	masterStart := strings.Index(userFormat, MasterUserPlaceholder)

	if targetStart < masterStart {
		targetEnd := targetStart + len(MasterUserTargetPlaceholder)
		masterEnd := masterStart + len(MasterUserPlaceholder)

		return newMasterUserLoginFormat(
			userFormat[:targetStart],
			userFormat[targetEnd:masterStart],
			userFormat[masterEnd:],
			true,
		)
	}

	masterEnd := masterStart + len(MasterUserPlaceholder)
	targetEnd := targetStart + len(MasterUserTargetPlaceholder)

	return newMasterUserLoginFormat(
		userFormat[:masterStart],
		userFormat[masterEnd:targetStart],
		userFormat[targetEnd:],
		false,
	)
}

// newMasterUserLoginFormat rejects adjacent placeholders because they cannot be split deterministically.
func newMasterUserLoginFormat(prefix string, separator string, suffix string, targetFirst bool) (masterUserLoginFormat, bool) {
	if separator == "" {
		return masterUserLoginFormat{}, false
	}

	return masterUserLoginFormat{
		prefix:      prefix,
		separator:   separator,
		suffix:      suffix,
		targetFirst: targetFirst,
	}, true
}

// parse extracts the target and master user from a formatted login name.
func (f masterUserLoginFormat) parse(username string) (targetUser string, masterUser string, ok bool) {
	body, ok := f.trimStaticBounds(username)
	if !ok {
		return "", "", false
	}

	left, right, ok := splitMasterUserLoginBody(body, f.separator)
	if !ok {
		return "", "", false
	}

	if f.targetFirst {
		return left, right, true
	}

	return right, left, true
}

// trimStaticBounds removes the configured fixed prefix and suffix from the login name.
func (f masterUserLoginFormat) trimStaticBounds(username string) (string, bool) {
	body, ok := strings.CutPrefix(username, f.prefix)
	if !ok {
		return "", false
	}

	body, ok = strings.CutSuffix(body, f.suffix)
	if !ok {
		return "", false
	}

	return body, true
}

// splitMasterUserLoginBody separates the two identities and rejects repeated separators.
func splitMasterUserLoginBody(body string, separator string) (string, string, bool) {
	left, right, ok := strings.Cut(body, separator)
	if !ok {
		return "", "", false
	}

	if left == "" || right == "" {
		return "", "", false
	}

	if strings.Contains(left, separator) || strings.Contains(right, separator) {
		return "", "", false
	}

	return left, right, true
}
