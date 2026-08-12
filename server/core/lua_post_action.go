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
	"log/slog"
	"net"
	"net/http"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/action"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
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

// PostActionRuntime is an immutable dependency snapshot for detached Lua work.
type PostActionRuntime struct {
	request  *http.Request
	cfg      config.File
	logger   *slog.Logger
	redis    rediscli.Client
	resource string
}

// NewPostActionRuntime captures all request-derived data before detached execution.
func NewPostActionRuntime(auth *AuthState) PostActionRuntime {
	if auth == nil {
		return PostActionRuntime{}
	}

	return PostActionRuntime{
		request:  auth.Request.HTTPClientRequest,
		cfg:      auth.Cfg(),
		logger:   auth.Logger(),
		redis:    auth.Redis(),
		resource: util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, auth.Request.Service),
	}
}

// RunLuaPostAction enqueues a Lua post action on the worker channel using the
// pooled CommonRequest object. It mirrors prior behavior and preserves metrics.
func (a *AuthState) RunLuaPostAction(args PostActionArgs) {
	_ = NewPostActionRuntime(a).RunContext(svcctx.Get(), args)
}

// QueueLuaPostAction transfers captured direct Lua work into supervisor ownership.
func (a *AuthState) QueueLuaPostAction(args PostActionArgs) bool {
	if a == nil {
		return false
	}

	if args.Context == nil {
		args.Context = lualib.NewContext()
	}

	if err := ValidateLuaPostActionCapture(args); err != nil {
		return false
	}

	runtime := NewPostActionRuntime(a)
	args.Request = args.Request.CloneForPostAction()
	args.Context = args.Context.Clone()
	args.HTTPRequest = util.DetachedHTTPRequest(svcctx.Get(), args.HTTPRequest)
	work := &directLuaPostActionWork{runtime: runtime, args: args}

	if _, err := acceptAuthPostAction(a.Request.HTTPClientContext, a.View(), 1, work); err != nil {
		work.Cleanup()

		return false
	}

	return true
}

// ValidateLuaPostActionCapture rejects oversized request-owned Lua capture.
func ValidateLuaPostActionCapture(args PostActionArgs) error {
	var runtimeValues map[string]any
	if args.Context != nil {
		runtimeValues = args.Context.Snapshot()
	}

	var headers http.Header
	if args.HTTPRequest != nil {
		headers = args.HTTPRequest.Header
	}

	return effectsupervisor.ValidateBoundedValue(struct {
		Runtime       map[string]any
		Headers       http.Header
		Request       lualib.CommonRequest
		StatusMessage string
	}{
		Runtime:       runtimeValues,
		Headers:       headers,
		Request:       args.Request,
		StatusMessage: args.StatusMessage,
	}, effectsupervisor.DefaultWorkBounds())
}

// RunContext executes one Lua post-action and reports known successful completion.
func (r PostActionRuntime) RunContext(ctx context.Context, args PostActionArgs) bool {
	return r.RunResult(ctx, args).State() == effectsupervisor.StateSucceeded
}

// RunResult executes one Lua post-action and preserves bounded worker outcome semantics.
func (r PostActionRuntime) RunResult(ctx context.Context, args PostActionArgs) effectsupervisor.Result {
	if r.cfg == nil || !r.cfg.HasRuntimeModule(definitions.ControlBruteForce) || args.Request.ClientIP == "" {
		return effectsupervisor.Succeeded()
	}

	if ctx == nil {
		ctx = svcctx.Get()
	}

	postActionRequest := util.DetachedHTTPRequest(ctx, r.postActionHTTPRequest(args))
	if util.IsHTTPRequestCanceled(r.logger, postActionRequest, args.Request.Session, "enqueue.lua_post_action") {
		return effectsupervisor.Failed("canceled")
	}

	defer r.stopPostActionTimer()()

	finished := make(chan action.Done, 1)
	cr := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(cr)

	clientNet, repeating := r.postActionBruteForceHints(args)
	preparePostActionCommonRequest(cr, args, clientNet, repeating)

	select {
	case action.PostActionRequestChan <- newPostActionRequest(args, postActionRequest, cr, finished):
	case <-ctx.Done():
		return effectsupervisor.Failed("canceled")
	}

	completion := <-finished
	if completion.Err == nil {
		return effectsupervisor.Succeeded()
	}

	if completion.OutcomeUnknown {
		return effectsupervisor.OutcomeUnknown("lua_dispatch_ambiguous")
	}

	return effectsupervisor.Failed("lua_worker_failure")
}

// postActionHTTPRequest resolves the HTTP request used for cancellation checks.
func (r PostActionRuntime) postActionHTTPRequest(args PostActionArgs) *http.Request {
	if args.HTTPRequest != nil {
		return args.HTTPRequest
	}

	return r.request
}

// stopPostActionTimer starts and returns the post-action metric timer stop hook.
func (r PostActionRuntime) stopPostActionTimer() func() {
	stopTimer := stats.PrometheusTimer(r.cfg, definitions.PromPostAction, "lua_post_action_request_total", r.resource)
	if stopTimer == nil {
		return func() {}
	}

	return stopTimer
}

// postActionBruteForceHints returns configured or derived brute-force hints.
func (r PostActionRuntime) postActionBruteForceHints(args PostActionArgs) (string, bool) {
	clientNet := args.Request.ClientNet

	repeating := args.Request.Repeating
	if clientNet != "" {
		return clientNet, repeating
	}

	base := svcctx.Get()
	if args.ParentSpan.IsValid() {
		base = trace.ContextWithSpanContext(base, args.ParentSpan)
	}

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(base, r.cfg)
	computedNet, computedRepeating := ComputeBruteForceHints(
		dCtx,
		r.cfg,
		r.redis,
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
		ExecutionContext:      httpRequest.Context(),
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
