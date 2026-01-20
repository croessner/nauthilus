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

package core_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	corepkg "github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

func setupMinimalConfigForBF(t *testing.T) {
	t.Helper()

	// Minimal environment and file config enabling brute_force and protocol "imap"
	feature := config.Feature{}
	_ = feature.Set(definitions.FeatureBruteForce)

	proto := &config.Protocol{}
	proto.Set("imap")

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Features:            []*config.Feature{&feature},
			BruteForceProtocols: []*config.Protocol{proto},
			Redis:               config.Redis{Prefix: "nt:"},
		},
		BruteForce: &config.BruteForceSection{
			Buckets: []config.BruteForceRule{{
				Name:           "bf",
				Period:         60,
				CIDR:           24,
				IPv4:           true,
				IPv6:           false,
				FailedRequests: 10,
			}},
		},
	}

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(cfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")
}

func TestComputeBruteForceHints_InvalidIPOrFeatureOff(t *testing.T) {
	// Feature off by default (no test file set)
	cn, rep := corepkg.ComputeBruteForceHints(context.Background(), config.GetFile(), rediscli.GetClient(), "", "imap", "")
	if cn != "" || rep {
		t.Fatalf("expected no hints for empty IP")
	}

	cn, rep = corepkg.ComputeBruteForceHints(context.Background(), config.GetFile(), rediscli.GetClient(), "not-an-ip", "imap", "")
	if cn != "" || rep {
		t.Fatalf("expected no hints for invalid IP")
	}
}

func TestComputeBruteForceHints_PositiveRepeatViaRedis(t *testing.T) {
	setupMinimalConfigForBF(t)

	// Start a gin context for consistency (not required for the function)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	_, _ = gin.CreateTestContext(w)

	db, mock := redismock.NewClientMock()
	rediscli.NewTestClient(db)

	// Expect HExists on sharded pre-result map key for candidate network
	prefix := config.GetFile().GetServer().GetRedis().GetPrefix()
	key := rediscli.GetBruteForceHashKey(prefix, "203.0.113.0/24")
	mock.ExpectHExists(key, "203.0.113.0/24").SetVal(true)

	ctx := context.Background()
	cn, rep := corepkg.ComputeBruteForceHints(ctx, config.GetFile(), rediscli.GetClient(), "203.0.113.1", "imap", "")
	if !rep {
		t.Fatalf("expected repeating=true from redis hit")
	}

	if cn != "203.0.113.0/24" {
		t.Fatalf("expected clientNet to be 203.0.113.0/24, got %q", cn)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet redis expectations: %v", err)
	}
}
