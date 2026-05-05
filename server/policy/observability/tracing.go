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

package observability

import monittrace "github.com/croessner/nauthilus/server/monitoring/trace"

// TracerScope is the OpenTelemetry instrumentation scope for policy internals.
const TracerScope = "nauthilus/policy"

// NewTracer returns the OpenTelemetry tracer facade for policy internals.
func NewTracer() monittrace.Tracer {
	return monittrace.New(TracerScope)
}
