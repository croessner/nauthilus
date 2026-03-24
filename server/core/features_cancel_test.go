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
	"context"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/gin-gonic/gin"
)

func TestHandleFeatures_SkipsCanceledRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/auth", nil).WithContext(reqCtx)

	auth := NewAuthStateFromContextWithDeps(ctx, AuthDeps{
		Cfg:    &config.FileSettings{Server: &config.ServerSection{}},
		Logger: log.GetLogger(),
	}).(*AuthState)

	auth.Runtime.GUID = "guid-canceled-features"
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.Service = definitions.ServNginx
	auth.Request.Username = "user@example.com"

	result := auth.HandleFeatures(ctx)
	if result != definitions.AuthResultTempFail {
		t.Fatalf("expected AuthResultTempFail, got %v", result)
	}
}
