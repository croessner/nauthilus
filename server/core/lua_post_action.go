// Copyright (C) 2024-2025 Christian Rößner
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
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/svcctx"
	"github.com/croessner/nauthilus/server/util"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// PostActionArgs bundles all necessary inputs for the Lua post-action dispatch.
// Request is passed by value and copied into a pooled lualib.CommonRequest.
// StatusMessage is copied and its address is set on the pooled request.
//
// Callers should prefer providing BF hints (ClientNet/Repeating) when available;
// if absent, RunLuaPostAction will derive them via ComputeBruteForceHints.
//
// This API replaces the legacy ExecuteLuaPostAction monster signature.
// The legacy function is kept as a thin wrapper for backward compatibility.
//
//goland:nointerface
type PostActionArgs struct {
	Context       *lualib.Context
	HTTPRequest   *http.Request
	ParentSpan    trace.SpanContext
	StatusMessage string
	Request       lualib.CommonRequest
}

// RunLuaPostAction enqueues a Lua post action on the worker channel using the
// pooled CommonRequest object. It mirrors prior behavior and preserves metrics.
func (a *AuthState) RunLuaPostAction(args PostActionArgs) {
	if !a.Cfg().HasFeature(definitions.FeatureBruteForce) || args.Request.ClientIP == "" {
		return
	}

	resource := util.RequestResource(a.Request.HTTPClientContext, a.Request.HTTPClientRequest, a.Request.Service)
	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromPostAction, "lua_post_action_request_total", resource)
	if stopTimer != nil {
		defer stopTimer()
	}

	finished := make(chan action.Done)

	// Get a CommonRequest from the pool and fill from args
	cr := lualib.GetCommonRequest()

	defer lualib.PutCommonRequest(cr)

	// Derive brute-force hints if not provided
	clientNet := args.Request.ClientNet
	repeating := args.Request.Repeating

	if clientNet == "" {
		// Use service-root context; derive a bounded Redis read context for hint computation
		base := svcctx.Get()
		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(base, a.Cfg())
		cn, rep := ComputeBruteForceHints(dCtx, a.Cfg(), a.Redis(), args.Request.ClientIP, args.Request.Protocol, args.Request.OIDCCID)

		cancel()

		if cn != "" || rep {
			clientNet = cn
			repeating = rep
		}
	}

	// Copy-by-value from args.Request then set computed hints
	*cr = args.Request
	if len(args.Request.Password) > 0 {
		cr.Password = bytes.Clone(args.Request.Password)
	} else {
		cr.Password = nil
	}
	cr.ClientNet = clientNet
	cr.Repeating = repeating
	// Deep copy StatusMessage string if it exists
	if args.StatusMessage != "" {
		sm := args.StatusMessage
		cr.StatusMessage = &sm
	} else {
		cr.StatusMessage = nil
	}

	action.RequestChan <- &action.Action{
		LuaAction:             definitions.LuaActionPost,
		Context:               args.Context,
		FinishedChan:          finished,
		HTTPRequest:           args.HTTPRequest,
		HTTPContext:           nil,
		OTelParentSpanContext: args.ParentSpan,
		CommonRequest:         cr,
	}

	<-finished
}

// ComputeBruteForceHints derives clientNet and repeating fields for the post action
// based on config rules, protocol and optional OIDC client id. The logic matches
// the previous inline implementation used by ExecuteLuaPostAction.
func ComputeBruteForceHints(ctx context.Context, cfg config.File, redisClient rediscli.Client, clientIP, protocol, oidccid string) (clientNet string, repeating bool) {
	if !cfg.HasFeature(definitions.FeatureBruteForce) || clientIP == "" {
		return "", false
	}

	tr := monittrace.New("nauthilus/auth")
	_, sp := tr.Start(ctx, "auth.bruteforce.hints",
		attribute.String("client_ip", clientIP),
		attribute.String("protocol", protocol),
		attribute.String("oidc_cid", oidccid),
	)
	defer sp.End()

	// Check whether the protocol is enabled for brute-force processing
	bfProtoEnabled := false
	for _, p := range cfg.GetServer().GetBruteForceProtocols() {
		if p.Get() == protocol {
			bfProtoEnabled = true

			break
		}
	}

	if !bfProtoEnabled {
		return "", false
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return "", false
	}

	rules := cfg.GetBruteForceRules()
	sp.SetAttributes(attribute.Int("rules.total", len(rules)))

	var (
		foundRepeatingNet string
		foundRepeating    bool
		bestCIDRRepeating uint = 0 // prefer most specific repeating
		bestCIDRFallback  uint = 0 // prefer most specific fallback
		considered        int
	)

	for i := range rules {
		r := &rules[i]
		if !r.MatchesContext(protocol, oidccid, ip) {
			continue
		}

		considered++

		if r.CIDR > 0 {
			if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", clientIP, r.CIDR)); err == nil && n != nil {
				candidate := n.String()

				// (1) Check for active ban on this network via dedicated ban key.
				if !foundRepeating {
					prefix := cfg.GetServer().GetRedis().GetPrefix()
					banKey := rediscli.GetBruteForceBanKey(prefix, candidate)

					stats.GetMetrics().GetRedisReadCounter().Inc()

					if existsVal, err := redisClient.GetReadHandle().Exists(ctx, banKey).Result(); err == nil && existsVal > 0 {
						if r.CIDR > bestCIDRRepeating {
							bestCIDRRepeating = r.CIDR
							foundRepeatingNet = candidate
						}

						foundRepeating = true
					}
				}

				// (2) Fallback: choose the most specific network
				if clientNet == "" && (r.CIDR > bestCIDRFallback) {
					bestCIDRFallback = r.CIDR
					clientNet = candidate
				}
			}
		}
	}

	sp.SetAttributes(
		attribute.Int("rules.considered", considered),
		attribute.Bool("repeating", foundRepeating),
	)

	if foundRepeating {
		repeating = true
		if foundRepeatingNet != "" {
			clientNet = foundRepeatingNet
		}
	}

	return clientNet, repeating
}
