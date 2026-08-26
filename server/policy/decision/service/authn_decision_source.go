// Copyright (C) 2026 Christian Rößner
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

package service

import (
	"context"
	"fmt"

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/report"
)

type authnDecisionSourceContextKey struct{}
type capturedPolicyModeContextKey struct{}

// AuthnDecisionSource supplies request-local standard-auth facts and receives the unified selection.
//
// The source is request-local application state. It cannot evaluate rules, select configured
// policy sets, or bypass the captured Decision Service generation.
type AuthnDecisionSource interface {
	StandardAuthFacts(context.Context, decision.Target, string) (decision.FactSet, error)
	StandardAuthEffectsEnabled(context.Context, decision.Target, string) bool
	CaptureAuthnDecision(context.Context, decision.Target, string, *report.FinalDecision)
}

// ContextWithAuthnDecisionSource attaches one request-local standard-auth fact source.
func ContextWithAuthnDecisionSource(ctx context.Context, source AuthnDecisionSource) context.Context {
	ctx = normalizeContext(ctx)
	if nilDependency(source) {
		return ctx
	}

	return context.WithValue(ctx, authnDecisionSourceContextKey{}, source)
}

// CapturedPolicyMode returns the immutable policy mode attached by the active DecisionSession.
func CapturedPolicyMode(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}

	mode, ok := ctx.Value(capturedPolicyModeContextKey{}).(string)

	return mode, ok && mode != ""
}

// contextWithCapturedPolicyMode attaches catalog-owned authn authority metadata.
func contextWithCapturedPolicyMode(ctx context.Context, mode string) context.Context {
	if mode == "" {
		return ctx
	}

	return context.WithValue(ctx, capturedPolicyModeContextKey{}, mode)
}

// authnDecisionSourceFromContext returns the request-local application source when present.
func authnDecisionSourceFromContext(ctx context.Context) AuthnDecisionSource {
	if ctx == nil {
		return nil
	}

	source, _ := ctx.Value(authnDecisionSourceContextKey{}).(AuthnDecisionSource)
	if nilDependency(source) {
		return nil
	}

	return source
}

// collectAuthnSourceFacts merges request-local host facts before schema validation and rule selection.
func collectAuthnSourceFacts(
	ctx context.Context,
	target decision.Target,
	checkpoint string,
	base decision.FactSet,
) (decision.FactSet, error) {
	if target.Namespace() != policy.AuthnNamespace {
		return base, nil
	}

	source := authnDecisionSourceFromContext(ctx)
	if source == nil {
		return base, nil
	}

	additional, err := source.StandardAuthFacts(ctx, target, checkpoint)
	if err != nil {
		return decision.FactSet{}, fmt.Errorf("collect request-local authn facts: %w", err)
	}

	facts := append(base.Facts(), additional.Facts()...)

	merged, err := decision.NewFactSet(facts)
	if err != nil {
		return decision.FactSet{}, fmt.Errorf("merge request-local authn facts: %w", err)
	}

	return merged, nil
}
