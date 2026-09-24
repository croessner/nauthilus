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
	"github.com/croessner/nauthilus/v4/server/config"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// connectionLifetimePolicy owns the gRPC transport settings that bound how long
// one client connection may stay pinned to this listener and how tolerant the
// listener is towards client keepalive pings.
type connectionLifetimePolicy struct {
	parameters  keepalive.ServerParameters
	enforcement keepalive.EnforcementPolicy
}

// newConnectionLifetimePolicy resolves the configured keepalive section. A zero
// age, grace, or idle limit maps to grpc-go's "infinite" default; grpc-go adds
// a +/-10% jitter to the connection age by itself.
func newConnectionLifetimePolicy(settings *config.RuntimeGRPCKeepAliveSection) connectionLifetimePolicy {
	return connectionLifetimePolicy{
		parameters: keepalive.ServerParameters{
			MaxConnectionIdle:     settings.GetMaxConnectionIdle(),
			MaxConnectionAge:      settings.GetMaxConnectionAge(),
			MaxConnectionAgeGrace: settings.GetMaxConnectionAgeGrace(),
		},
		enforcement: keepalive.EnforcementPolicy{
			MinTime:             settings.GetMinPingInterval(),
			PermitWithoutStream: settings.PermitsWithoutStream(),
		},
	}
}

// serverOptions returns the gRPC server options that apply the policy.
func (p connectionLifetimePolicy) serverOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveParams(p.parameters),
		grpc.KeepaliveEnforcementPolicy(p.enforcement),
	}
}
