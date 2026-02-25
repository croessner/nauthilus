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

package core

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/dspinhirne/netaddr-go"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// RBLIsListed is a small wrapper exposing the internal isListed logic to subpackages
// without duplicating implementation details. It accepts a StateView to avoid import cycles.
func RBLIsListed(ctx *gin.Context, view *StateView, rbl *config.RBL) (bool, string, error) {
	if view == nil || view.auth == nil {
		return false, "", nil
	}

	return view.auth.isListed(ctx, rbl)
}

// isListed triggers a result of true, if an IP address was found on a RBL list. It also returns a human readable name.
func (a *AuthState) isListed(ctx *gin.Context, rbl *config.RBL) (rblListStatus bool, rblName string, err error) {
	var (
		results       []net.IP
		reverseIPAddr string
	)

	if stats.HavePrometheusLabelEnabled(a.Cfg(), definitions.PromFeature) {
		timer := prometheus.NewTimer(stats.GetMetrics().GetRblDuration().WithLabelValues(rbl.Name))

		defer timer.ObserveDuration()
	}

	guid := ctx.GetString(definitions.CtxGUIDKey)
	ipAddress := net.ParseIP(a.Request.ClientIP)
	if ipAddress.IsLoopback() {
		return false, "", nil
	}

	if strings.Contains(ipAddress.String(), ".") {
		if !rbl.IPv4 {
			return false, "", nil
		}

		tmp := strings.Split(a.Request.ClientIP, ".")
		tmp = []string{tmp[3], tmp[2], tmp[1], tmp[0]}
		reverseIPAddr = strings.Join(tmp, ".")
	} else {
		if !rbl.IPv6 {
			return false, "", nil
		}

		tmp, err := netaddr.ParseIPv6(a.Request.ClientIP) //nolint:govet // Ignore
		if err != nil {
			return false, "", err
		}

		// Long version uncompressed
		ipv6Str := tmp.Long()

		// Remove ':' signs
		ipv6Slice := strings.Split(ipv6Str, ":")
		ipv6Str = strings.Join(ipv6Slice, "")

		// Reverse address
		ipv6Slice = strings.Split(ipv6Str, "")
		for n := 0; n < (len(ipv6Slice) / 2); n++ { //nolint:gomnd // Ignore
			ipv6Slice[n], ipv6Slice[len(ipv6Slice)-n-1] = ipv6Slice[len(ipv6Slice)-n-1], ipv6Slice[n]
		}

		reverseIPAddr = strings.Join(ipv6Slice, ".")
	}

	query := fmt.Sprintf("%s.%s", reverseIPAddr, rbl.GetRBL())

	ctxTimeout, cancel := context.WithDeadline(ctx, time.Now().Add(a.Cfg().GetServer().GetDNS().GetTimeout()))

	defer cancel()

	resolver := util.NewDNSResolver(a.Cfg())

	// Trace DNS lookup for RBL
	tr := monittrace.New("nauthilus/dns")
	tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup",
		attribute.String("rpc.system", "dns"),
		semconv.PeerService("dns"),
		attribute.String("dns.question.name", query),
		attribute.String("dns.question.type", func() string {
			if strings.Contains(a.Request.ClientIP, ":") {
				return "AAAA"
			}

			return "A"
		}()),
	)

	results, err = resolver.LookupIP(tctx, "ip4", query)
	if err != nil {
		tsp.RecordError(err)
	}

	tsp.SetAttributes(attribute.Int("dns.answer.count", len(results)))
	tsp.End()

	if err != nil {
		return false, "", err
	}

	for _, result := range results {
		if result.String() == rbl.GetReturnCode() {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				a.Cfg(),
				a.Logger(),
				definitions.DbgRBL,
				definitions.LogKeyGUID, guid,
				"query", query, "result", result.String(), "rbl", rbl.GetName(),
			)

			return true, rbl.Name, nil
		}

		if slices.Contains(rbl.GetReturnCodes(), result.String()) {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				a.Cfg(),
				a.Logger(),
				definitions.DbgRBL,
				definitions.LogKeyGUID, guid,
				"query", query, "result", result.String(), "rbl", rbl.GetName(),
			)

			return true, rbl.Name, nil
		}
	}

	return false, "", nil
}
