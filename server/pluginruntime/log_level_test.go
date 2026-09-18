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


package pluginruntime

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/definitions"
	serverlog "github.com/croessner/nauthilus/v4/server/log"
)

func TestPluginLoggerHonorsHostLevelAcrossReload(t *testing.T) {
	output := capturePluginLogOutput(t)

	serverlog.SetupLogging(definitions.LogLevelDebug, true, false, false, "test")

	host := NewHost(WithLogger(serverlog.GetLogger()))
	logger := host.moduleHost(testRuntimeModuleName).Logger(testDebugModuleLookup)

	for _, level := range []struct {
		minimum   int
		threshold slog.Level
	}{{definitions.LogLevelWarn, slog.LevelWarn}, {definitions.LogLevelError, slog.LevelError}, {definitions.LogLevelInfo, slog.LevelInfo}} {
		serverlog.SetupLogging(level.minimum, true, false, false, "test")

		for _, emission := range []struct {
			write    func(context.Context, string, ...pluginapi.LogField)
			severity slog.Level
		}{{logger.Debug, slog.LevelDebug}, {logger.Info, slog.LevelInfo}, {logger.Warn, slog.LevelWarn}, {logger.Error, slog.LevelError}} {
			if err := output.Truncate(0); err != nil {
				t.Fatal(err)
			}

			if _, err := output.Seek(0, 0); err != nil {
				t.Fatal(err)
			}

			emission.write(t.Context(), "level probe")

			data, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}

			if got, want := strings.Contains(string(data), "level probe"), emission.severity >= level.threshold; got != want {
				t.Fatalf("minimum %v, severity %v: emitted = %v, want %v", level.minimum, emission.severity, got, want)
			}
		}
	}
}

// capturePluginLogOutput redirects host output for serial logger reconfiguration tests.
func capturePluginLogOutput(t *testing.T) *os.File {
	t.Helper()

	output, err := os.CreateTemp(t.TempDir(), "plugin-logs")
	if err != nil {
		t.Fatal(err)
	}

	previousOutput := os.Stdout
	os.Stdout = output

	t.Cleanup(func() {
		os.Stdout = previousOutput

		serverlog.SetupLogging(definitions.LogLevelInfo, true, false, false, "")

		_ = output.Close()
	})

	return output
}
