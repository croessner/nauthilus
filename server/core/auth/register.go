// Copyright (C) 2024-2025 Christian Rößner
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

package auth

import (
	"github.com/croessner/nauthilus/server/core"
)

// Package auth wires the default implementations for pluggable auth services
// via init() to avoid import cycles. It lives in subpackage server/core/auth
// and only registers implementations defined in core.

func init() {
	// Register default implementations provided by subpackage.
	core.RegisterLuaFilter(DefaultLuaFilter{})
	core.RegisterPostAction(DefaultPostAction{})
	core.RegisterBruteForceService(DefaultBruteForceService{})
	core.RegisterCacheService(DefaultCacheService{})
	core.RegisterPasswordVerifier(DefaultPasswordVerifier{})
}
