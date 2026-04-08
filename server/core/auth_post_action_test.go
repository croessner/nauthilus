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

package core

import (
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

func TestAuthStateMarkFeatureRejected_SetsGinContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())

	auth := &AuthState{}
	auth.markFeatureRejected(ctx)

	if !ctx.GetBool(definitions.CtxFeatureRejectedKey) {
		t.Fatal("expected feature_rejected context flag to be set")
	}
}
