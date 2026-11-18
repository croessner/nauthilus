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

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/mcpserver"
	"github.com/croessner/nauthilus/v4/server/supportapi"
)

// mcpConfigProvider is the narrow config surface of the MCP endpoint wiring.
type mcpConfigProvider interface {
	GetMCPServer() *config.RuntimeMCPServerSection
}

// startMCPForHTTP starts the optional MCP endpoint with the HTTP servers, so it follows their configuration snapshot
// and restart. A disabled endpoint opens no listener. The endpoint shares the process-owned support services.
func startMCPForHTTP(ctx context.Context, runtime httpServerRuntime, options httpServerStartOptions) error {
	runtime.store.mcpDone = nil

	provider, ok := runtime.cfg.(mcpConfigProvider)
	if !ok || !provider.GetMCPServer().Enabled {
		return nil
	}

	server, err := mcpserver.New(mcpserver.Deps{Settings: provider.GetMCPServer(), Logger: runtime.logger, Version: version,
		Tokens:   idp.NewNauthilusIDP(frontendHandlerDeps(runtime)),
		Services: supportapi.Services{History: runtime.store.supportHistory, Operations: runtime.store.supportOperations}})
	if err == nil {
		runtime.store.mcpDone, err = server.Start(ctx)
	}

	if err == nil {
		return nil
	}

	if options.continueHTTPOnGRPCAuthorityError {
		_ = level.Warn(runtime.logger).Log(definitions.LogKeyMsg, "Unable to start MCP endpoint; continuing HTTP startup", definitions.LogKeyError, err)

		return nil
	}

	return fmt.Errorf("start MCP endpoint: %w", err)
}
