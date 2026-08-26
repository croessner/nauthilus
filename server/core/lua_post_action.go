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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/stats"

	"go.opentelemetry.io/otel/attribute"
)

// ComputeBruteForceHints derives client-network and repetition facts for configured actions.
// It evaluates the active brute-force rules without relying on a process-wide Lua worker.
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
