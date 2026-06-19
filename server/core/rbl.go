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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/dspinhirne/netaddr-go"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

const (
	rblIPFamilyIPv4  = "ipv4"
	rblIPFamilyIPv6  = "ipv6"
	rblReverseHalves = 2
)

// RBLIsListed is a small wrapper exposing the internal isListed logic to subpackages
// without duplicating implementation details. It accepts a StateView to avoid import cycles.
func RBLIsListed(ctx *gin.Context, view *StateView, rbl *config.RBL) (bool, string, error) {
	fact, err := RBLPolicyLookup(ctx, view, rbl)
	if err != nil {
		return false, "", err
	}

	if !fact.Listed {
		return false, "", nil
	}

	return true, fact.Name, nil
}

// RBLPolicyLookup exposes the internal RBL lookup together with policy-visible list facts.
func RBLPolicyLookup(ctx *gin.Context, view *StateView, rbl *config.RBL) (RBLListPolicyFact, error) {
	if view == nil || view.auth == nil {
		return RBLListPolicyFact{}, nil
	}

	return view.auth.rblPolicyLookup(ctx, rbl)
}

// rblPolicyLookup triggers a result of true, if an IP address was found on a RBL list,
// and returns the request-local policy view of the lookup.
func (a *AuthState) rblPolicyLookup(ctx *gin.Context, rbl *config.RBL) (RBLListPolicyFact, error) {
	var (
		results []net.IP
	)

	fact := RBLListPolicyFact{
		Name:         rbl.GetName(),
		Host:         rbl.GetRBL(),
		Weight:       rbl.GetWeight(),
		AllowFailure: rbl.IsAllowFailure(),
	}

	if stats.HavePrometheusLabelEnabled(a.Cfg(), definitions.PromEnvironment) {
		timer := prometheus.NewTimer(stats.GetMetrics().GetRblDuration().WithLabelValues(rbl.Name))

		defer timer.ObserveDuration()
	}

	guid := ctx.GetString(definitions.CtxGUIDKey)
	reverseIPAddr, ipFamily, active, err := reverseRBLClientIP(a.Request.ClientIP, rbl)
	fact.IPFamily = ipFamily
	if err != nil {
		fact.Error = true
		fact.ReasonCode = "invalid_ipv6"

		return fact, err
	}

	if !active {
		return fact, nil
	}

	query := fmt.Sprintf("%s.%s", reverseIPAddr, rbl.GetRBL())
	fact.Query = query

	results, err = a.rblQueryResults(ctx, query)
	if err != nil {
		markRBLPolicyFactError(&fact, err)

		return fact, err
	}

	fact = a.applyRBLPolicyResults(ctx, fact, rbl, results, query, guid)

	return fact, nil
}

func reverseRBLClientIP(clientIP string, rbl *config.RBL) (string, string, bool, error) {
	if strings.Contains(clientIP, ".") {
		if !rbl.IPv4 {
			return "", rblIPFamilyIPv4, false, nil
		}

		tmp := strings.Split(clientIP, ".")
		tmp = []string{tmp[3], tmp[2], tmp[1], tmp[0]}

		return strings.Join(tmp, "."), rblIPFamilyIPv4, true, nil
	}

	if !rbl.IPv6 {
		return "", rblIPFamilyIPv6, false, nil
	}

	tmp, err := netaddr.ParseIPv6(clientIP) //nolint:govet // Ignore
	if err != nil {
		return "", rblIPFamilyIPv6, true, err
	}

	ipv6Str := strings.Join(strings.Split(tmp.Long(), ":"), "")
	ipv6Slice := strings.Split(ipv6Str, "")
	for n := 0; n < (len(ipv6Slice) / rblReverseHalves); n++ {
		ipv6Slice[n], ipv6Slice[len(ipv6Slice)-n-1] = ipv6Slice[len(ipv6Slice)-n-1], ipv6Slice[n]
	}

	return strings.Join(ipv6Slice, "."), rblIPFamilyIPv6, true, nil
}

func (a *AuthState) rblQueryResults(ctx *gin.Context, query string) ([]net.IP, error) {
	ctxTimeout, cancel := context.WithDeadline(ctx, time.Now().Add(a.Cfg().GetServer().GetDNS().GetTimeout()))
	defer cancel()

	resolver := util.NewDNSResolver(a.Cfg())
	tr := monittrace.New("nauthilus/dns")
	tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup",
		attribute.String("rpc.system", "dns"),
		semconv.PeerService("dns"),
		attribute.String("dns.question.name", query),
		attribute.String("dns.question.type", a.rblQuestionType()),
	)

	results, err := resolver.LookupIP(tctx, "ip4", query)
	if err != nil {
		tsp.RecordError(err)
	}

	tsp.SetAttributes(attribute.Int("dns.answer.count", len(results)))
	tsp.End()

	return results, err
}

func (a *AuthState) rblQuestionType() string {
	if strings.Contains(a.Request.ClientIP, ":") {
		return "AAAA"
	}

	return "A"
}

func markRBLPolicyFactError(fact *RBLListPolicyFact, err error) {
	fact.Error = true
	fact.ReasonCode = "dns_error"
	if strings.Contains(err.Error(), "no such host") {
		fact.ReasonCode = "dns_no_such_host"
	}
}

func (a *AuthState) applyRBLPolicyResults(
	ctx *gin.Context,
	fact RBLListPolicyFact,
	rbl *config.RBL,
	results []net.IP,
	query string,
	guid string,
) RBLListPolicyFact {
	for _, result := range results {
		if result.String() != rbl.GetReturnCode() && !slices.Contains(rbl.GetReturnCodes(), result.String()) {
			continue
		}

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			a.Cfg(),
			a.Logger(),
			definitions.DbgRBL,
			definitions.LogKeyGUID, guid,
			"query", query, "result", result.String(), "rbl", rbl.GetName(),
		)

		fact.Listed = true
		fact.ReturnCode = result.String()

		return fact
	}

	return fact
}
