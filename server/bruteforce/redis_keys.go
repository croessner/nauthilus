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

package bruteforce

import (
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

// PasswordHistoryRedisKey returns the bounded password-history set key of one RWP-scoped address.
//
// With an account name the key is account-scoped and tagged by account and address
// (`<prefix>pw_hist:{<account>:<ip>}:<account>:<ip>`); without one it is the address-wide set
// (`<prefix>pw_hist:{<ip>}:<ip>`). Writers, readers, and flush paths must all use this builder.
func PasswordHistoryRedisKey(prefix string, accountName string, scopedIP string) string {
	hashTag := scopedIP
	suffix := scopedIP

	if accountName != "" {
		hashTag = accountName + ":" + scopedIP
		suffix = hashTag
	}

	var sb strings.Builder

	sb.WriteString(prefix)
	sb.WriteString(definitions.RedisPwHashKey)
	sb.WriteString(":{")
	sb.WriteString(hashTag)
	sb.WriteString("}:")
	sb.WriteString(suffix)

	return sb.String()
}

// RWPAllowanceRedisKey returns the repeating-wrong-password window key of one scoped address and login identity.
//
// The identity is the account-mapping field `<username>|<protocol>|<oidc_cid>` of a named login, or the
// account name when the request carried no username (see bucketManagerImpl.rwpIdentity).
func RWPAllowanceRedisKey(prefix string, scopedIP string, identity string) string {
	var sb strings.Builder

	sb.WriteString(prefix)
	sb.WriteString(definitions.RedisBFRWPAllowPrefix)
	sb.WriteString(scopedIP)
	sb.WriteByte(':')
	sb.WriteString(identity)

	return sb.String()
}
