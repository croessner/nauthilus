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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/action"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/svcctx"
	"github.com/croessner/nauthilus/v3/server/util"

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
	if !a.Cfg().HasRuntimeModule(definitions.ControlBruteForce) || args.Request.ClientIP == "" {
		return
	}

	postActionRequest := util.DetachedHTTPRequest(context.TODO(), a.postActionHTTPRequest(args))
	if util.IsHTTPRequestCanceled(a.Logger(), postActionRequest, args.Request.Session, "enqueue.lua_post_action") {
		return
	}

	defer a.stopPostActionTimer()()

	finished := make(chan action.Done)
	cr := lualib.GetCommonRequest()

	defer lualib.PutCommonRequest(cr)

	clientNet, repeating := a.postActionBruteForceHints(args)
	preparePostActionCommonRequest(cr, args, clientNet, repeating)

	action.RequestChan <- newPostActionRequest(args, postActionRequest, cr, finished)

	<-finished
}

// postActionHTTPRequest resolves the HTTP request used for cancellation checks.
func (a *AuthState) postActionHTTPRequest(args PostActionArgs) *http.Request {
	if args.HTTPRequest != nil {
		return args.HTTPRequest
	}

	return a.Request.HTTPClientRequest
}

// stopPostActionTimer starts and returns the post-action metric timer stop hook.
func (a *AuthState) stopPostActionTimer() func() {
	resource := util.RequestResource(a.Request.HTTPClientContext, a.Request.HTTPClientRequest, a.Request.Service)

	stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromPostAction, "lua_post_action_request_total", resource)
	if stopTimer == nil {
		return func() {}
	}

	return stopTimer
}

// postActionBruteForceHints returns configured or derived brute-force hints.
func (a *AuthState) postActionBruteForceHints(args PostActionArgs) (string, bool) {
	clientNet := args.Request.ClientNet

	repeating := args.Request.Repeating
	if clientNet != "" {
		return clientNet, repeating
	}

	base := svcctx.Get()
	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(base, a.Cfg())
	computedNet, computedRepeating := ComputeBruteForceHints(
		dCtx,
		a.Cfg(),
		a.Redis(),
		args.Request.ClientIP,
		args.Request.Protocol,
		args.Request.OIDCCID,
	)

	cancel()

	if computedNet != "" || computedRepeating {
		clientNet = computedNet
		repeating = computedRepeating
	}

	return clientNet, repeating
}

// preparePostActionCommonRequest copies request data into the pooled request.
func preparePostActionCommonRequest(cr *lualib.CommonRequest, args PostActionArgs, clientNet string, repeating bool) {
	*cr = args.Request
	if len(args.Request.Password) > 0 {
		cr.Password = bytes.Clone(args.Request.Password)
	} else {
		cr.Password = nil
	}

	cr.ClientNet = clientNet
	cr.Repeating = repeating

	if args.StatusMessage != "" {
		statusMessage := args.StatusMessage
		cr.StatusMessage = &statusMessage
	} else {
		cr.StatusMessage = nil
	}
}

// newPostActionRequest creates the worker action for Lua post processing.
func newPostActionRequest(
	args PostActionArgs,
	httpRequest *http.Request,
	cr *lualib.CommonRequest,
	finished chan action.Done,
) *action.Action {
	return &action.Action{
		LuaAction:             definitions.LuaActionPost,
		Context:               args.Context,
		FinishedChan:          finished,
		HTTPRequest:           httpRequest,
		HTTPContext:           nil,
		OTelParentSpanContext: args.ParentSpan,
		CommonRequest:         cr,
	}
}

// ComputeBruteForceHints derives clientNet and repeating fields for the post action
// based on config rules, protocol and optional OIDC client id. The logic matches
// the previous inline implementation used by ExecuteLuaPostAction.
func ComputeBruteForceHints(ctx context.Context, cfg config.File, redisClient rediscli.Client, clientIP, protocol, oidccid string) (clientNet string, repeating bool) {
	if !cfg.HasRuntimeModule(definitions.ControlBruteForce) || clientIP == "" {
		return "", false
	}

	tr := monittrace.New("nauthilus/auth")

	_, sp := tr.Start(ctx, "auth.bruteforce.hints",
		attribute.String("client_ip", clientIP),
		attribute.String("protocol", protocol),
		attribute.String("oidc_cid", oidccid),
	)
	defer sp.End()

	if !bruteForceProtocolEnabled(cfg, protocol) {
		return "", false
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return "", false
	}

	rules := cfg.GetBruteForceRules()
	sp.SetAttributes(attribute.Int("rules.total", len(rules)))

	state := &bruteForceHintState{}

	for i := range rules {
		state.considerRule(ctx, cfg, redisClient, &rules[i], bruteForceHintRuleInput{
			clientIP: clientIP,
			protocol: protocol,
			oidcCID:  oidccid,
			ip:       ip,
		})
	}

	sp.SetAttributes(
		attribute.Int("rules.considered", state.considered),
		attribute.Bool("repeating", state.foundRepeating),
	)

	if state.foundRepeating {
		repeating = true

		if state.foundRepeatingNet != "" {
			clientNet = state.foundRepeatingNet
		}
	} else if state.clientNet != "" {
		clientNet = state.clientNet
	}

	return clientNet, repeating
}

type bruteForceHintRuleInput struct {
	clientIP string
	protocol string
	oidcCID  string
	ip       net.IP
}

type bruteForceHintState struct {
	foundRepeatingNet string
	clientNet         string
	foundRepeating    bool
	bestCIDRRepeating uint
	bestCIDRFallback  uint
	considered        int
}

// bruteForceProtocolEnabled reports whether hints apply to the protocol.
func bruteForceProtocolEnabled(cfg config.File, protocol string) bool {
	for _, configuredProtocol := range cfg.GetServer().GetBruteForceProtocols() {
		if configuredProtocol.Get() == protocol {
			return true
		}
	}

	return false
}

// considerRule evaluates one matching brute-force hint rule.
func (s *bruteForceHintState) considerRule(
	ctx context.Context,
	cfg config.File,
	redisClient rediscli.Client,
	rule *config.BruteForceRule,
	input bruteForceHintRuleInput,
) {
	if !rule.MatchesContext(input.protocol, input.oidcCID, input.ip) {
		return
	}

	s.considered++

	candidate, ok := bruteForceRuleCIDRNetwork(input.clientIP, rule.CIDR)
	if !ok {
		return
	}

	s.applyRepeatingRule(ctx, cfg, redisClient, candidate, rule.CIDR)
	s.applyFallbackRule(candidate, rule.CIDR)
}

// bruteForceRuleCIDRNetwork builds a candidate network for a rule CIDR.
func bruteForceRuleCIDRNetwork(clientIP string, cidr uint) (string, bool) {
	if cidr == 0 {
		return "", false
	}

	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", clientIP, cidr))
	if err != nil || network == nil {
		return "", false
	}

	return network.String(), true
}

// applyRepeatingRule records a matching active ban network.
func (s *bruteForceHintState) applyRepeatingRule(
	ctx context.Context,
	cfg config.File,
	redisClient rediscli.Client,
	candidate string,
	cidr uint,
) {
	if s.foundRepeating || !bruteForceBanExists(ctx, cfg, redisClient, candidate) {
		return
	}

	if cidr > s.bestCIDRRepeating {
		s.bestCIDRRepeating = cidr
		s.foundRepeatingNet = candidate
	}

	s.foundRepeating = true
}

// bruteForceBanExists checks whether the candidate network has an active ban.
func bruteForceBanExists(ctx context.Context, cfg config.File, redisClient rediscli.Client, candidate string) bool {
	prefix := cfg.GetServer().GetRedis().GetPrefix()
	banKey := rediscli.GetBruteForceBanKey(prefix, candidate)

	stats.GetMetrics().GetRedisReadCounter().Inc()

	existsVal, err := redisClient.GetReadHandle().Exists(ctx, banKey).Result()

	return err == nil && existsVal > 0
}

// applyFallbackRule records the first eligible fallback network.
func (s *bruteForceHintState) applyFallbackRule(candidate string, cidr uint) {
	if s.clientNet != "" || cidr <= s.bestCIDRFallback {
		return
	}

	s.bestCIDRFallback = cidr
	s.clientNet = candidate
}
