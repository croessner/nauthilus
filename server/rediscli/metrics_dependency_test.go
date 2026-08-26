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

package rediscli

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
)

type metricsDependencyProbe struct {
	Client
	writeCalls int
	readCalls  int
}

// GetWriteHandle records that metrics used the injected write handle.
func (probe *metricsDependencyProbe) GetWriteHandle() redis.UniversalClient {
	probe.writeCalls++

	return nil
}

// GetReadHandle records that metrics used the injected read handle.
func (probe *metricsDependencyProbe) GetReadHandle() redis.UniversalClient {
	probe.readCalls++

	return nil
}

func TestCollectRedisServerMetricsUsesInjectedClient(t *testing.T) {
	probe := &metricsDependencyProbe{}

	collectRedisServerMetrics(context.Background(), nil, nil, probe)

	if probe.writeCalls != 1 || probe.readCalls != 1 {
		t.Fatalf("injected Redis client calls = write:%d/read:%d, want 1/1", probe.writeCalls, probe.readCalls)
	}
}
