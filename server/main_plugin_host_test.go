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

package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/rediscli"

	"github.com/go-redis/redismock/v9"
	"github.com/spf13/viper"
)

func TestRuntimePluginHostProvidesProductionFacades(t *testing.T) {
	db, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	queue := priorityqueue.NewLDAPRequestQueue(logger)

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("plugins.modules", []map[string]any{
		{
			"name": "geoip",
			"type": "go",
			"path": "/tmp/geoip.so",
			"config": map[string]any{
				"enabled": true,
			},
		},
	})

	host := newRuntimePluginHost(context.Background(), logger, &config.FileSettings{}, redisClient, queue)

	if host.Redis() == nil {
		t.Fatal("Redis facade is nil")
	}

	if host.LDAP() == nil {
		t.Fatal("LDAP facade is nil")
	}

	if host.Config().IsZero() {
		t.Fatal("config facade is empty")
	}

	if _, ok := host.Config().GetPath([]string{"plugins", "modules"}); !ok {
		t.Fatal("config facade does not expose loaded plugin module settings")
	}
}
