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

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/presentation"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
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

	legacyStandard := selected.policySet == registry.BuiltinStandardAuthPolicySet
	final := authnFinalDecisionFromRule(selected.rule, checkpoint, facts, legacyStandard)
	controls := authnControlDecisions(selected.controls, checkpoint, facts)

	effectsEnabled := standardAuthEffectsEnabled(
		ctx,
		target.Target(),
		checkpoint,
	)
	if effectsEnabled && authnImplicitPostActionRequired(target.Target(), checkpoint, selected.rule) {
		withPostAction, err := registry.WithBuiltinAuthPostAction(selection.obligations)
		if err != nil {
			return decisionSelection{}, nil, nil, err
		}

		selection.obligations = withPostAction
	}

	if !effectsEnabled {
		selection.obligations = nil
		selection.advice = nil
		final.Obligations = nil
		final.Advice = nil
	}

	return selection, final, controls, nil
}

// authnImplicitPostActionRequired preserves the existing terminal pre-auth lifecycle hook.
func authnImplicitPostActionRequired(
	target decision.Target,
	checkpoint string,
	rule policyruntime.CompiledRule,
) bool {
	if target.Action() != string(policy.OperationAuthenticate) &&
		target.Action() != string(policy.OperationLookupIdentity) {
		return false
	}

	stage := rule.PresentationStage()
	if stage == "" {
		stage = checkpoint
	}

	if stage != string(policy.StagePreAuth) {
		return false
	}

	return rule.Decision() == decision.EffectDeny ||
		(rule.Decision() == decision.EffectIndeterminate &&
			rule.ResponseMarker() == policy.ResponseMarkerTempFailNoTLS)
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
	legacyStandard bool,
) *report.FinalDecision {
	responseMessage := authnRuleResponseMessage(rule.ResponseMessage(), rule.ResponseMarker(), facts)
	if legacyStandard {
		responseMessage = authnLegacyResponseMessage(responseMessage, rule.ResponseMessage())
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

// authnLegacyResponseMessage restores the established report identity without changing public text.
func authnLegacyResponseMessage(
	selection *report.ResponseMessageSelection,
	message registry.PolicyResponseMessage,
) *report.ResponseMessageSelection {
	if selection == nil {
		return nil
	}

	legacy := *selection

	legacy.Truncated = false
	if legacy.Source == policy.ResponseSourceAttributeDetail {
		legacy.AttributeID = authnLegacyResponseAttributeID(message.FactID(), message.Detail())
	}

	return &legacy
}

// authnLegacyResponseAttributeID maps one canonical detail fact back to its collected attribute.
func authnLegacyResponseAttributeID(factID string, detail string) string {
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

// authnReportEffectRequests restores established authn selection IDs and detached scalar parameters.
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

		selectionID := use.ID()
		if binding, exists := registry.BuiltinAuthEffectBindingForEffect(use.ID()); exists {
			selectionID = binding.Selection
		}

		requests = append(requests, report.EffectRequest{ID: selectionID, Args: args})
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
