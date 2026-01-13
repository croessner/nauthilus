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
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
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

	ctxTimeut, cancel := context.WithDeadline(ctx, time.Now().Add(a.Cfg().GetServer().GetDNS().GetTimeout()*time.Second))

	defer cancel()

	resolver := util.NewDNSResolver()

	// Trace DNS lookup for RBL
	tr := monittrace.New("nauthilus/dns")
	tctx, tsp := tr.StartClient(ctxTimeut, "dns.lookup",
		attribute.String("rpc.system", "dns"),
		semconv.PeerService("dns"),
		attribute.String("dns.question.name", query),
		attribute.String("dns.question.type", func() string {
			if strings.Contains(a.ClientIP, ":") {
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
				a.Cfg(),
				a.Logger(),
				definitions.DbgRBL,
				definitions.LogKeyGUID, guid,
				"query", query, "result", result.String(), "rbl", rbl.GetName(),
			)

			return true, rbl.Name, nil
		}

		for _, returnCode := range rbl.GetReturnCodes() {
			if result.String() == returnCode {
				util.DebugModuleWithCfg(
					a.Cfg(),
					a.Logger(),
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

// processRBL processes a single RBL check for a given AuthState and updates associated metrics or outcomes.
func (a *AuthState) processRBL(ctx *gin.Context, rbl *config.RBL, rblChan chan int, dnsResolverErr *atomic.Bool) {
	isListed, rblName, rblErr := a.isListed(ctx, rbl)
	if rblErr != nil {
		handleRBLError(a.Cfg(), a.Logger(), a.GUID, rblErr, rbl, dnsResolverErr)
		handleRBLOutcome(rblChan, 0)

		return
	}

	if isListed {
		stats.GetMetrics().GetRblRejected().WithLabelValues(rblName).Inc()
		logMatchedRBL(a, rblName, rbl.Weight)
		handleRBLOutcome(rblChan, rbl.Weight)

		return
	}

	handleRBLOutcome(rblChan, 0)
}

// handleRBLOutcome sends the provided weight value to the specified rblChan channel.
func handleRBLOutcome(rblChan chan int, weight int) {
	rblChan <- weight
}

// handleRBLError handles errors encountered during RBL checks, logs them, and updates failure status if needed.
func handleRBLError(cfg config.File, logger *slog.Logger, guid string, err error, rbl *config.RBL, dnsResolverErr *atomic.Bool) {
	if strings.Contains(err.Error(), "no such host") {
		util.DebugModuleWithCfg(cfg, logger, definitions.DbgRBL, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)
	} else {
		if !rbl.IsAllowFailure() {
			dnsResolverErr.Store(true)
		}

		level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "RBL check failed",
			definitions.LogKeyError, err,
		)
	}
}

// logMatchedRBL appends the RBL name and weight to the AdditionalLogs of the provided AuthState, if it's not nil.
func logMatchedRBL(auth *AuthState, rblName string, weight int) {
	if auth == nil {
		return
	}

	auth.AdditionalLogs = append(auth.AdditionalLogs, "rbl "+rblName)
	auth.AdditionalLogs = append(auth.AdditionalLogs, weight)
}

// checkRBLs checks the remote client IP address against a list of realtime blocklists.
func (a *AuthState) checkRBLs(ctx *gin.Context) (totalRBLScore int, err error) {
	var (
		dnsResolverErr atomic.Bool
	)

	rbls := a.Cfg().GetRBLs()
	if rbls == nil {
		return
	}

	g := &sync.WaitGroup{}

	dnsResolverErr.Store(false)
	rblLists := rbls.GetLists()
	numberOfRBLs := len(rblLists)
	rblChan := make(chan int, numberOfRBLs)

	for _, rbl := range rblLists {
		r := rbl
		g.Add(1)
		go func() {
			defer g.Done()
			a.processRBL(ctx, &r, rblChan, &dnsResolverErr)
		}()
	}

	g.Wait()

	if dnsResolverErr.Load() {
		err = errors.ErrDNSResolver

		return
	}

	for rblScore := range rblChan {
		totalRBLScore += rblScore
		numberOfRBLs--

		if numberOfRBLs == 0 {
			break
		}
	}

	return
}
