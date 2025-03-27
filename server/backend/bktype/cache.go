// Copyright (C) 2024 Christian Rößner
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

package bktype

import "github.com/croessner/nauthilus/server/definitions"

// PasswordHistory is a map of hashed passwords with their failure counter.
type PasswordHistory map[string]uint

// PositivePasswordCache is a container that stores all kinds of user information upon a successful authentication. It
// is used for Redis as a short cache object and as a proxy structure between Nauthilus instances. The cache object is not
// refreshed upon continuous requests. If the Redis TTL has expired, the object is removed from the cache to force a refresh
// of the user data from underlying databases.
type PositivePasswordCache struct {
	Backend           definitions.Backend `json:"passdb_backend"`
	Password          string              `json:"password,omitempty"`
	AccountField      *string             `json:"account_field"`
	TOTPSecretField   *string             `json:"totp_secret_field"`
	UniqueUserIDField *string             `json:"webauth_userid_field"`
	DisplayNameField  *string             `json:"display_name_field"`
	Attributes        AttributeMapping    `json:"attributes"`
}
