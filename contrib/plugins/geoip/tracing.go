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

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	spanGeoIPPrimaryDatabaseLookup = "geoip.database.primary.lookup"
	spanGeoIPASNRoutingLookup      = "geoip.asn.routing.lookup"
	spanGeoIPASNDatabaseLookup     = "geoip.database.asn.lookup"
	spanGeoIPASNRegistryLookup     = "geoip.asn.registry.lookup"
	spanGeoIPPrivacyLookup         = "geoip.privacy.lookup"
	traceAttrLookupResult          = "geoip.lookup.result"
)

// traceGeoIPLookup records one bounded lookup step with a stable result attribute.
func traceGeoIPLookup[T any](
	ctx context.Context,
	tracer pluginapi.Tracer,
	spanName string,
	lookup func(context.Context) (T, bool, error),
) (value T, matched bool, err error) {
	spanCtx := ctx
	span := pluginapi.Span(noopSpan{})

	if tracer != nil {
		spanCtx, span = tracer.Start(ctx, spanName)
	}

	value, matched, err = lookup(spanCtx)

	result := resultMiss
	if err != nil {
		result = resultError

		span.RecordError(err)
	} else if matched {
		result = resultMatched
	}

	span.SetAttributes(pluginapi.TraceAttribute{Key: traceAttrLookupResult, Value: result})
	span.End()

	return value, matched, err
}
