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
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/dspinhirne/netaddr-go"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

// isListed triggers a result of true, if an IP address was found on a RBL list. It also returns a human readable name.
func (a *AuthState) isListed(ctx *gin.Context, rbl *config.RBL) (rblListStatus bool, rblName string, err error) {
	var (
		results       []net.IP
		reverseIPAddr string
	)

	if stats.HavePrometheusLabelEnabled(definitions.PromFeature) {
		timer := prometheus.NewTimer(stats.GetMetrics().GetRblDuration().WithLabelValues(rbl.Name))

		defer timer.ObserveDuration()
	}

	guid := ctx.GetString(definitions.CtxGUIDKey)
	ipAddress := net.ParseIP(a.ClientIP)
	if ipAddress.IsLoopback() {
		return false, "", nil
	}

	if strings.Contains(ipAddress.String(), ".") {
		if !rbl.IPv4 {
			return false, "", nil
		}

		tmp := strings.Split(a.ClientIP, ".")
		tmp = []string{tmp[3], tmp[2], tmp[1], tmp[0]}
		reverseIPAddr = strings.Join(tmp, ".")
	} else {
		if !rbl.IPv6 {
			return false, "", nil
		}

		tmp, err := netaddr.ParseIPv6(a.ClientIP) //nolint:govet // Ignore
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

	ctxTimeut, cancel := context.WithDeadline(ctx, time.Now().Add(config.GetFile().GetServer().GetDNS().GetTimeout()*time.Second))

	defer cancel()

	resolver := util.NewDNSResolver()

	results, err = resolver.LookupIP(ctxTimeut, "ip4", query)
	if err != nil {
		return false, "", err
	}

	for _, result := range results {
		if result.String() == rbl.GetReturnCode() {
			util.DebugModule(
				definitions.DbgRBL,
				definitions.LogKeyGUID, guid,
				"query", query, "result", result.String(), "rbl", rbl.GetName(),
			)

			return true, rbl.Name, nil
		}

		for _, returnCode := range rbl.GetReturnCodes() {
			if result.String() == returnCode {
				util.DebugModule(
					definitions.DbgRBL,
					definitions.LogKeyGUID, guid,
					"query", query, "result", result.String(), "rbl", rbl.GetName(),
				)

				return true, rbl.Name, nil
			}
		}
	}

	return false, "", nil
}
