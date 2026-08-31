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
	"strings"

	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/presentation"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	"github.com/croessner/nauthilus/v4/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// resolveAuthnDecisionSelection evaluates the catalog-selected authn authority into one plan.
func resolveAuthnDecisionSelection(
	ctx context.Context,
	target policyruntime.CompiledTarget,
	checkpoint string,
	facts decision.FactSet,
	selected selectedRule,
) (decisionSelection, *report.FinalDecision, []*report.FinalDecision, error) {
	selection := projectDecisionSelection(target, checkpoint, selected)
	if target.Target().Namespace() != policy.AuthnNamespace {
		return selection, nil, nil, nil
	}

	if !selected.matched {
		return selection, nil, nil, nil
	}

	builtinStandard := selected.policySet == registry.BuiltinStandardAuthPolicySet
	final := authnFinalDecisionFromRule(selected.rule, checkpoint, facts, builtinStandard)
	controls := authnControlDecisions(selected.controls, checkpoint, facts)

	effectsEnabled := standardAuthEffectsEnabled(
		ctx,
		target.Target(),
		checkpoint,
	)
	if !effectsEnabled {
		selection.obligations = nil
		selection.advice = nil
		final.Obligations = nil
		final.Advice = nil
	}

	return selection, final, controls, nil
}

// authnControlDecisions projects nonterminal catalog controls in their matched order.
func authnControlDecisions(
	rules []policyruntime.CompiledRule,
	checkpoint string,
	facts decision.FactSet,
) []*report.FinalDecision {
	controls := make([]*report.FinalDecision, 0, len(rules))
	for _, rule := range rules {
		controls = append(controls, authnFinalDecisionFromRule(rule, checkpoint, facts, true))
	}

	return controls
}

// standardAuthEffectsEnabled applies the existing request-local observe and suppression gate.
func standardAuthEffectsEnabled(ctx context.Context, target decision.Target, checkpoint string) bool {
	source := authnDecisionSourceFromContext(ctx)
	if source == nil {
		return false
	}

	return source.StandardAuthEffectsEnabled(ctx, target, checkpoint)
}

// captureAuthnDecisionSelection publishes application metadata before any selected host effect starts.
func captureAuthnDecisionSelection(
	ctx context.Context,
	target decision.Target,
	checkpoint string,
	final *report.FinalDecision,
) {
	if target.Namespace() != policy.AuthnNamespace || final == nil {
		return
	}

	if source := authnDecisionSourceFromContext(ctx); source != nil {
		source.CaptureAuthnDecision(ctx, target, checkpoint, report.CloneFinalDecision(final))
	}
}

// authnFinalDecisionFromRule projects compiled response and FSM metadata for the application adapter.
func authnFinalDecisionFromRule(
	rule policyruntime.CompiledRule,
	checkpoint string,
	facts decision.FactSet,
	builtinStandard bool,
) *report.FinalDecision {
	responseMessage := authnRuleResponseMessage(rule.ResponseMessage(), rule.ResponseMarker(), facts)
	if builtinStandard {
		responseMessage = authnBuiltinResponseMessage(responseMessage, rule.ResponseMessage())
	}

	stage := policy.Stage(checkpoint)
	if rule.PresentationStage() != "" {
		stage = policy.Stage(rule.PresentationStage())
	}

	final := &report.FinalDecision{
		PolicyName:       rule.Name(),
		Reason:           rule.Reason(),
		OutcomeMarker:    rule.OutcomeMarker(),
		FSMEventMarker:   rule.FSMEventMarker(),
		ResponseMarker:   rule.ResponseMarker(),
		Stage:            stage,
		Effect:           authnPolicyDecision(rule.Decision()),
		ResponseMessage:  responseMessage,
		ResponseLanguage: authnRuleResponseLanguage(rule.ResponseLanguage(), responseMessage, facts),
		Obligations:      authnReportEffectRequests(rule.Effects()),
		Advice:           authnReportEffectRequests(rule.Advice()),
	}
	if rule.SkipRemainingCheckpointProviders() {
		final.Control = &report.DecisionControl{SkipRemainingStageChecks: true}
	}

	return final
}

// authnBuiltinResponseMessage preserves the builtin standard-auth report identity without changing public text.
func authnBuiltinResponseMessage(
	selection *report.ResponseMessageSelection,
	message registry.PolicyResponseMessage,
) *report.ResponseMessageSelection {
	if selection == nil {
		return nil
	}

	projected := *selection

	projected.Truncated = false
	if projected.Source == policy.ResponseSourceAttributeDetail {
		projected.AttributeID = authnBuiltinResponseAttributeID(message.FactID(), message.Detail())
	}

	return &projected
}

// authnBuiltinResponseAttributeID maps one canonical detail fact to its builtin presentation attribute.
func authnBuiltinResponseAttributeID(factID string, detail string) string {
	attributeID := factID
	if detail != "" {
		attributeID = strings.TrimSuffix(factID, "."+detail)
	}

	if strings.HasPrefix(attributeID, "nauthilus.auth.") {
		return strings.TrimPrefix(attributeID, "nauthilus.")
	}

	return attributeID
}

// authnPolicyDecision maps all closed generic decisions into established application vocabulary.
func authnPolicyDecision(effect decision.Effect) policy.Decision {
	switch effect {
	case decision.EffectPermit:
		return policy.DecisionPermit
	case decision.EffectDeny:
		return policy.DecisionDeny
	case decision.EffectIndeterminate:
		return policy.DecisionTempFail
	default:
		return policy.DecisionNeutral
	}
}

// authnReportEffectRequests projects canonical effect identities and detached scalar parameters.
func authnReportEffectRequests(uses []registry.EffectUse) []report.EffectRequest {
	requests := make([]report.EffectRequest, 0, len(uses))

	for _, use := range uses {
		var args map[string]any
		if use.Parameters().Len() > 0 {
			args = make(map[string]any, use.Parameters().Len())
		}

		for key, value := range use.Parameters().Values() {
			args[key] = authnEffectParameterValue(value)
		}

		requests = append(requests, report.EffectRequest{ID: use.ID(), Args: args})
	}

	return requests
}

// authnEffectParameterValue projects one strict immutable value to the retained report vocabulary.
func authnEffectParameterValue(value decision.Value) any {
	result, _ := value.Any()

	return result
}

// authnRuleResponseMessage resolves the configured literal, localization, or fact source.
func authnRuleResponseMessage(
	message registry.PolicyResponseMessage,
	responseMarker string,
	facts decision.FactSet,
) *report.ResponseMessageSelection {
	switch message.From() {
	case policy.ResponseSourceLiteral:
		text, truncated := presentation.SanitizeResponseMessageWithState(message.Text(), message.MaxLength())

		return &report.ResponseMessageSelection{
			Source: policy.ResponseSourceLiteral, Message: text, Truncated: truncated,
		}
	case policy.ResponseSourceI18N:
		fallback, truncated := presentation.SanitizeResponseMessageWithState(message.Fallback(), message.MaxLength())

		return &report.ResponseMessageSelection{
			Source: policy.ResponseSourceI18N, Message: fallback, I18NKey: message.I18NKey(),
			Fallback: message.Fallback(), Truncated: truncated,
		}
	case policy.ResponseSourceAttributeDetail:
		value, exists := facts.Get(message.FactID())
		if exists {
			if text, ok := value.Value().StringValue(); ok && authnResponseDetailSelected(facts, message.FactID(), text) {
				sanitized, truncated := presentation.SanitizeResponseMessageWithState(text, message.MaxLength())
				truncated = truncated || authnResponseDetailTruncated(facts, message.FactID())

				return &report.ResponseMessageSelection{
					Source: policy.ResponseSourceAttributeDetail, Message: sanitized,
					AttributeID: message.FactID(), Detail: message.Detail(), Truncated: truncated,
				}
			}
		}

		if message.Fallback() == "" {
			return presentation.DefaultResponseMessage(responseMarker)
		}

		fallback, truncated := presentation.SanitizeResponseMessageWithState(message.Fallback(), message.MaxLength())

		return &report.ResponseMessageSelection{
			Source: policy.ResponseSourceAttributeDetail, Message: fallback,
			AttributeID: message.FactID(), Detail: message.Detail(), Fallback: message.Fallback(), FallbackUsed: true,
			Truncated: truncated,
		}
	default:
		return presentation.DefaultResponseMessage(responseMarker)
	}
}

// authnResponseDetailSelected preserves raw nonblank selection before host-side sanitation.
func authnResponseDetailSelected(facts decision.FactSet, factID string, sanitized string) bool {
	fact, exists := facts.Get(factID + ".selected")
	if !exists {
		return strings.TrimSpace(sanitized) != ""
	}

	selected, ok := fact.Value().Boolean()

	return ok && selected
}

// authnResponseDetailTruncated restores host-side sanitation evidence for one projected detail.
func authnResponseDetailTruncated(facts decision.FactSet, factID string) bool {
	fact, exists := facts.Get(factID + ".truncated")
	if !exists {
		return false
	}

	truncated, ok := fact.Value().Boolean()

	return ok && truncated
}

// authnRuleResponseLanguage resolves one literal or strict string fact language source.
func authnRuleResponseLanguage(
	language registry.PolicyResponseLanguage,
	message *report.ResponseMessageSelection,
	facts decision.FactSet,
) *report.ResponseLanguageSelection {
	if message == nil || message.I18NKey == "" {
		return nil
	}

	switch language.From() {
	case policy.ResponseSourceLiteral:
		if language.Language() == "" {
			return nil
		}

		return &report.ResponseLanguageSelection{Source: policy.ResponseSourceLiteral, Language: language.Language()}
	case policy.ResponseSourceAttribute:
		value, exists := facts.Get(language.FactID())
		if exists {
			if text, ok := value.Value().StringValue(); ok {
				if normalized, valid := presentation.NormalizeResponseLanguage(text); valid {
					return &report.ResponseLanguageSelection{
						Source: policy.ResponseSourceAttribute, Language: normalized,
						AttributeID: language.FactID(), Fallback: language.Fallback(),
					}
				}
			}
		}

		if language.Fallback() == "" {
			return nil
		}

		return &report.ResponseLanguageSelection{
			Source: policy.ResponseSourceAttribute, Language: language.Fallback(),
			AttributeID: language.FactID(), Fallback: language.Fallback(), FallbackUsed: true,
		}
	default:
		return nil
	}
}
