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

//go:build !hydra
// +build !hydra

package twofa

import (
	"github.com/croessner/nauthilus/server/handler/deps"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Handler is a no-op 2FA frontend when built without the hydra tag.
type Handler struct {
	Store sessions.Store
	Deps  *deps.Deps
}

// New returns a new no-op 2FA Handler.
func New(store sessions.Store, d *deps.Deps) *Handler { return &Handler{Store: store, Deps: d} }

// Register registers no routes when Hydra is disabled (no-op).
func (h *Handler) Register(router gin.IRouter) {
	// no-op: hydra disabled build
}
