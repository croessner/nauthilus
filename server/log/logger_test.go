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

package log

import (
	"bytes"
	"testing"

	"github.com/croessner/nauthilus/server/global"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func TestSetupLogging(t *testing.T) {
	tests := []struct {
		name           string
		configLogLevel int
		formatJSON     bool
		useColor       bool
		instance       string
	}{
		{
			name:           "LogLevelNone, JSON format, Color",
			configLogLevel: global.LogLevelNone,
			formatJSON:     true,
			useColor:       true,
			instance:       "none_json_color",
		},
		{
			name:           "LogLevelError, Logfmt format, No Color",
			configLogLevel: global.LogLevelError,
			formatJSON:     false,
			useColor:       false,
			instance:       "error_logfmt_nocolor",
		},
		{
			name:           "LogLevelWarn, JSON format, Color",
			configLogLevel: global.LogLevelWarn,
			formatJSON:     true,
			useColor:       true,
			instance:       "warn_json_color",
		},
		{
			name:           "LogLevelInfo, Logfmt format, No Color",
			configLogLevel: global.LogLevelInfo,
			formatJSON:     false,
			useColor:       false,
			instance:       "info_logfmt_nocolor",
		},
		{
			name:           "LogLevelDebug, JSON format, No color",
			configLogLevel: global.LogLevelDebug,
			formatJSON:     true,
			useColor:       false,
			instance:       "debug_json_nocolor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}

			Logger = log.NewLogfmtLogger(log.NewSyncWriter(buf))

			SetupLogging(tt.configLogLevel, tt.formatJSON, tt.useColor, tt.instance)

			// testing log level
			level.Debug(Logger).Log("msg", "debug")
			level.Info(Logger).Log("msg", "info")
			level.Warn(Logger).Log("msg", "warn")
			level.Error(Logger).Log("msg", "error")

			// testing instance
			logTest := log.With(Logger, global.LogKeyInstance, tt.instance)
			logTest.Log("msg", "instance test")
		})
	}
}
