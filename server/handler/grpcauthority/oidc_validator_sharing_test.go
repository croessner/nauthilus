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

package grpcauthority

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
)

// TestSharedOIDCValidatorIsResolvedOncePerServer pins that every call of one server reuses the same bearer
// validator, so its verification-key cache is not rebuilt per request.
func TestSharedOIDCValidatorIsResolvedOncePerServer(t *testing.T) {
	db, _ := redismock.NewClientMock()
	deps := ServerDeps{Cfg: &config.FileSettings{Server: &config.ServerSection{}}, Redis: rediscli.NewTestClient(db)}

	if deps.effectiveOIDCValidator() == deps.effectiveOIDCValidator() {
		t.Fatal("reproducer precondition: unresolved dependencies build one validator per call")
	}

	shared := deps.withSharedOIDCValidator()

	first := shared.effectiveOIDCValidator()
	if first == nil || first != shared.effectiveOIDCValidator() {
		t.Fatal("server calls do not share one bearer validator")
	}

	if (ServerDeps{}).withSharedOIDCValidator().OIDCValidator != nil {
		t.Fatal("an unconfigured server obtained a bearer validator")
	}
}
