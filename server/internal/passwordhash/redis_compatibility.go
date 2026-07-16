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

// Package passwordhash contains bounded server-internal Redis hash compatibility.
package passwordhash

import pluginpassword "github.com/croessner/nauthilus/v3/pluginapi/v1/password"

// RedisCompatibilityCandidates holds one canonical digest and its exact legacy read candidate.
type RedisCompatibilityCandidates struct {
	full   string
	legacy string
}

// DeriveRedisCompatibilityCandidates derives bounded candidates from prepared credential bytes.
func DeriveRedisCompatibilityCandidates(value []byte) RedisCompatibilityCandidates {
	full := pluginpassword.FullHash(value)

	return RedisCompatibilityCandidates{full: full, legacy: full[:8]}
}

// Full returns the canonical digest used by every new Redis write.
func (c RedisCompatibilityCandidates) Full() string {
	return c.full
}

// Legacy returns the exact eight-hex candidate accepted only on bounded Redis reads.
func (c RedisCompatibilityCandidates) Legacy() string {
	return c.legacy
}
