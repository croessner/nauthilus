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

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/server/app/bootfx"
	"github.com/croessner/nauthilus/server/app/envfx"
	"github.com/croessner/nauthilus/server/app/languagefx"
	"github.com/croessner/nauthilus/server/app/logfx"
	"github.com/croessner/nauthilus/server/app/loopsfx"
	"github.com/croessner/nauthilus/server/app/opsfx"
	"github.com/croessner/nauthilus/server/app/reloadfx"
	"github.com/croessner/nauthilus/server/app/restartfx"
	"github.com/croessner/nauthilus/server/app/signalsfx"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/svcctx"

	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

func TestHookOnlyConfigurationStartsAndStopsWithoutBackends(t *testing.T) {
	miniRedis, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer miniRedis.Close()

	listenAddress := reserveLoopbackAddress(t)
	configPath := writeHookOnlyConfig(t, miniRedis.Addr(), listenAddress)

	viper.Reset()
	t.Cleanup(viper.Reset)
	t.Cleanup(func() {
		config.SetTestFile(nil)
		config.ConfigFilePath = ""
		config.ConfigFileType = "yaml"
		viper.Reset()
	})

	config.ConfigFilePath = configPath
	config.ConfigFileType = "yaml"
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	if err := bootfx.SetupConfiguration(); err != nil {
		t.Fatalf("setup configuration: %v", err)
	}

	ctx, cancel := svcctx.GetCtxWithCancel()
	app := newHookOnlyTestApp(ctx, cancel)

	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer startCancel()

	if err := app.Start(startCtx); err != nil {
		t.Fatalf("app start: %v", err)
	}

	if err := waitForTCPListener(listenAddress, 5*time.Second); err != nil {
		_ = app.Stop(context.Background())
		t.Fatalf("hook-only listener did not come up: %v", err)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()

	if err := app.Stop(stopCtx); err != nil {
		t.Fatalf("app stop: %v", err)
	}
}

func newHookOnlyTestApp(ctx context.Context, cancel context.CancelFunc) *fx.App {
	return fx.New(
		fx.WithLogger(func(logger *slog.Logger) fxevent.Logger {
			if logger.Enabled(context.Background(), slog.LevelDebug) {
				return logfx.NewFxEventLogger(logger)
			}

			return fxevent.NopLogger
		}),
		rootContextOption(ctx, cancel),
		fx.Provide(newBootstrapped),
		fx.Provide(newConfigDeps),
		fx.Provide(newLogger),
		fx.Provide(newDbgModuleMapping),
		fx.Provide(newRedisDeps),
		fx.Provide(newAccountCache),
		fx.Provide(newBackendChannel),
		envfx.Module(),
		languagefx.Module(),
		loopsfx.Module(),
		opsfx.Module(),
		reloadfx.Module(),
		restartfx.Module(),
		fx.Provide(newActionWorkers),
		fx.Provide(newContextStoreForRuntime),
		fx.Provide(newReloadOrchestrator),
		fx.Provide(newRestartOrchestrator),
		fx.Invoke(registerRuntimeLifecycle),
		signalsfx.Module(),
	)
}

func writeHookOnlyConfig(t *testing.T, redisAddress string, listenAddress string) string {
	t.Helper()

	projectRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	hookScriptPath := filepath.Join(projectRoot, "lua-plugins.d", "hooks", "hello-world-request-dump.lua")
	languageResourcesPath := filepath.Join(projectRoot, "resources")
	configPath := filepath.Join(t.TempDir(), "nauthilus.yml")
	configBody := fmt.Sprintf(`runtime:
  instance_name: "hook-only-startup"
  listen:
    address: "%s"

storage:
  redis:
    primary:
      address: "%s"
    password_nonce: "nonce-secret-1234"
    encryption_secret: "redis-secret-1234"

identity:
  frontend:
    assets:
      language_resources: "%s"

auth:
  controls:
    lua:
      hooks:
        - http_location: "/demo"
          http_method: "POST"
          script_path: "%s"
`, listenAddress, redisAddress, languageResourcesPath, hookScriptPath)

	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return configPath
}

func reserveLoopbackAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", net.JoinHostPort(definitions.Localhost4, "0"))
	if err != nil {
		t.Fatalf("reserve loopback address: %v", err)
	}

	address := listener.Addr().String()

	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}

	return address
}

func waitForTCPListener(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()

			return nil
		}

		time.Sleep(50 * time.Millisecond)
	}

	return fmt.Errorf("listener %s did not accept connections within %s", address, timeout)
}
