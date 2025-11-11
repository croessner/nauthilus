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
	"github.com/gin-gonic/gin"
)

// DefaultPasswordVerifier implements core.PasswordVerifier by mirroring the
// legacy verification loop using core helpers. It iterates configured backends
// and returns the first decisive result or an aggregated configuration error.
//
//goland:nointerface
type DefaultPasswordVerifier struct{}

func (DefaultPasswordVerifier) Verify(ctx *gin.Context, auth *core.AuthState, passDBs []*core.PassDBMap) (*core.PassDBResult, error) {
	return core.VerifyPasswordPipeline(ctx, auth, passDBs)
}
