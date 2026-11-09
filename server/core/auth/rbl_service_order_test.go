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

package auth

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/gin-gonic/gin"
)

// TestCollectRBLListFactsKeepsConfigurationOrder pins that concurrent RBL lookups report their per-list facts, and
// therefore the matched-list names exposed to policy and plugins, in configuration order.
func TestCollectRBLListFactsKeepsConfigurationOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	lists := make([]config.RBL, 64)
	for index := range lists {
		// IPv4 lookups are disabled, so every lookup returns its named fact without DNS traffic.
		lists[index] = config.RBL{Name: fmt.Sprintf("list-%02d", index), RBL: "rbl.example.test", IPv6: true}
	}

	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{
		Cfg:    &config.FileSettings{Server: &config.ServerSection{}},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).(*core.AuthState)
	auth.Request.ClientIP = "192.0.2.10"

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	for attempt := range 20 {
		facts := collectRBLListFacts(ctx, auth.View(), auth, lists)
		if len(facts) != len(lists) {
			t.Fatalf("attempt %d: facts = %d, want %d", attempt, len(facts), len(lists))
		}

		for index, fact := range facts {
			if fact.Name != lists[index].Name {
				t.Fatalf("attempt %d: fact %d = %q, want %q", attempt, index, fact.Name, lists[index].Name)
			}
		}
	}
}
