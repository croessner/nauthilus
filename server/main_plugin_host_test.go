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
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/rediscli"

	"github.com/go-redis/redismock/v9"
)

func TestRuntimePluginHostProvidesProductionFacades(t *testing.T) {
	db, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	queue := priorityqueue.NewLDAPRequestQueue(logger)

	cfg := loadRuntimePluginHostConfig(t)
	host := newRuntimePluginHost(
		context.Background(),
		logger,
		cfg,
		redisClient,
		queue,
	)

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

	if _, ok := host.Config().Get("policy"); ok {
		t.Fatal("config facade exposes the policy authority subtree")
	}

	if _, ok := host.Config().GetPath([]string{"policy", "namespaces", "authn"}); ok {
		t.Fatal("config facade resolves nested policy authority values")
	}
}

// loadRuntimePluginHostConfig returns a production-decoded snapshot with no ambient Viper dependency.
func loadRuntimePluginHostConfig(t *testing.T) config.File {
	t.Helper()

	directory := t.TempDir()

	pluginPath := filepath.Join(directory, "geoip.so")
	if err := os.WriteFile(pluginPath, []byte("fixture plugin artifact"), 0o600); err != nil {
		t.Fatalf("write plugin artifact: %v", err)
	}

	configPath := filepath.Join(directory, "nauthilus.yaml")

	contents := fmt.Sprintf(`
plugins:
  allowed_dirs: [%q]
  modules:
    - name: geoip
      type: go
      path: %q
      config:
        enabled: true
policy:
  api:
    enabled: false
`, directory, pluginPath)
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	previousPath := config.ConfigFilePath
	previousType := config.ConfigFileType
	config.ConfigFilePath = configPath
	config.ConfigFileType = "yaml"

	t.Cleanup(func() {
		config.ConfigFilePath = previousPath
		config.ConfigFileType = previousType
	})

	loaded, err := config.PrepareFile()
	if err != nil {
		t.Fatalf("PrepareFile() error = %v", err)
	}

	return loaded
}
