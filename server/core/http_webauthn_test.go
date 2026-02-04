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
	"io"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/server/config"
)

func TestInitWebAuthnSkipsWhenIdPAndFrontendDisabled(t *testing.T) {
	env := config.NewTestEnvironmentConfig()
	config.SetTestEnvironmentConfig(env)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{},
	}
	config.SetTestFile(cfg)
	SetDefaultConfigFile(config.GetFile())

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := HTTPDeps{
		Cfg:    config.GetFile(),
		Logger: logger,
		Env:    env,
	}

	if err := NewDefaultBootstrap(deps).InitWebAuthn(); err != nil {
		t.Fatalf("expected InitWebAuthn to skip without error, got %v", err)
	}
}
