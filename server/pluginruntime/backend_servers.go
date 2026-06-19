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

package pluginruntime

import (
	"context"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
)

// BackendServerProvider returns the current host-owned backend server slice.
type BackendServerProvider func() []*config.BackendServer

type backendServerFacade struct {
	provider BackendServerProvider
}

// NewBackendServerFacade exposes backend-monitoring candidates as API-level values.
func NewBackendServerFacade(provider BackendServerProvider) pluginapi.BackendServers {
	return backendServerFacade{provider: provider}
}

// List returns defensive value copies of the current backend server candidates.
func (f backendServerFacade) List(context.Context) []pluginapi.BackendServerCandidate {
	if f.provider == nil {
		return nil
	}

	servers := f.provider()
	if len(servers) == 0 {
		return nil
	}

	candidates := make([]pluginapi.BackendServerCandidate, 0, len(servers))
	for _, server := range servers {
		if server == nil {
			continue
		}

		candidates = append(candidates, backendServerCandidateFromConfig(server))
	}

	return candidates
}

// backendServerCandidateFromConfig copies the safe fields needed for plugin selection logic.
func backendServerCandidateFromConfig(server *config.BackendServer) pluginapi.BackendServerCandidate {
	return pluginapi.BackendServerCandidate{
		Protocol:  server.GetProtocol(),
		Address:   server.GetHost(),
		Port:      server.GetPort(),
		HAProxyV2: server.IsHAProxyV2(),
		Alive:     true,
	}
}
