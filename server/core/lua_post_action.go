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
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/svcctx"
	"github.com/croessner/nauthilus/server/util"
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
	StatusMessage string
	Request       lualib.CommonRequest
}

// RunLuaPostAction enqueues a Lua post action on the worker channel using the
// pooled CommonRequest object. It mirrors prior behavior and preserves metrics.
func RunLuaPostAction(args PostActionArgs) {
	stopTimer := stats.PrometheusTimer(definitions.PromPostAction, "lua_post_action_request_total")
	if stopTimer != nil {
		defer stopTimer()
	}

	finished := make(chan action.Done)

	// Get a CommonRequest from the pool and fill from args
	cr := lualib.GetCommonRequest()

	// Derive brute-force hints if not provided
	clientNet := args.Request.ClientNet
	repeating := args.Request.Repeating

	if clientNet == "" {
		// Use service-root context; derive a bounded Redis read context for hint computation
		base := svcctx.Get()
		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(base)
		cn, rep := ComputeBruteForceHints(dCtx, args.Request.ClientIP, args.Request.Protocol, args.Request.OIDCCID)

		cancel()

		if cn != "" || rep {
			clientNet = cn
			repeating = rep
		}
	}

	// Copy-by-value from args.Request then set computed hints
	*cr = args.Request
	cr.ClientNet = clientNet
	cr.Repeating = repeating
	cr.StatusMessage = &args.StatusMessage

	action.RequestChan <- &action.Action{
		LuaAction:     definitions.LuaActionPost,
		Context:       args.Context,
		FinishedChan:  finished,
		HTTPRequest:   args.HTTPRequest,
		HTTPContext:   nil,
		CommonRequest: cr,
	}

	<-finished

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(cr)
}

// ComputeBruteForceHints derives clientNet and repeating fields for the post action
// based on config rules, protocol and optional OIDC client id. The logic matches
// the previous inline implementation used by ExecuteLuaPostAction.
func ComputeBruteForceHints(ctx context.Context, clientIP, protocol, oidccid string) (clientNet string, repeating bool) {
	if !config.GetFile().HasFeature(definitions.FeatureBruteForce) || clientIP == "" {
		return "", false
	}

	// Check whether the protocol is enabled for brute-force processing
	bfProtoEnabled := false
	for _, p := range config.GetFile().GetServer().GetBruteForceProtocols() {
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

	var (
		foundRepeatingNet string
		foundRepeating    bool
		bestCIDRRepeating uint = 0 // prefer most specific repeating
		bestCIDRFallback  uint = 0 // prefer most specific fallback
	)

	for i := range config.GetFile().GetBruteForceRules() {
		r := &config.GetFile().GetBruteForceRules()[i]

		// FilterByProtocol
		if len(r.FilterByProtocol) > 0 && protocol != "" {
			matched := false
			for _, fp := range r.FilterByProtocol {
				if fp == protocol {
					matched = true

					break
				}
			}

			if !matched {
				continue
			}
		}

		// FilterByOIDCCID
		if len(r.FilterByOIDCCID) > 0 && oidccid != "" {
			matched := false
			for _, cid := range r.FilterByOIDCCID {
				if cid == oidccid {
					matched = true

					break
				}
			}

			if !matched {
				continue
			}
		}

		// IP version
		if ip.To4() != nil {
			if !r.IPv4 {
				continue
			}
		} else if ip.To16() != nil {
			if !r.IPv6 {
				continue
			}
		} else {
			continue
		}

		if r.CIDR > 0 {
			if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", clientIP, r.CIDR)); err == nil && n != nil {
				candidate := n.String()

				// (1) Historical hit in the pre-result hash map?
				if !foundRepeating {
					key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey
					stats.GetMetrics().GetRedisReadCounter().Inc()
					if exists, err := rediscli.GetClient().GetReadHandle().HExists(ctx, key, candidate).Result(); err == nil && exists {
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

	if foundRepeating {
		repeating = true
		if foundRepeatingNet != "" {
			clientNet = foundRepeatingNet
		}
	}

	return clientNet, repeating
}
