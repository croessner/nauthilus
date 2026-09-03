// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	projectionSchema         = "dkim2.verifier-projection.v1"
	draftVersion             = "draft-ietf-dkim-dkim2-spec-06"
	maximumHops              = 128
	factProjectionSchema     = "resource.dkim2.projection_schema"
	factDraft                = "resource.dkim2.draft"
	factBindingAlgorithm     = "resource.dkim2.projection_binding_algorithm"
	factScope                = "resource.dkim2.scope"
	factHistoricalContent    = "resource.dkim2.historical_content"
	factHistoricalSignatures = "resource.dkim2.historical_signatures"
	factCustodyStructure     = "resource.dkim2.custody_structure"
	factReplayClass          = "resource.dkim2.replay_class"
	factLocalPolicyMode      = "resource.dkim2.local_policy_mode"
	factLocalPolicyVerdict   = "resource.dkim2.local_policy_verdict"
	factAuthenticationReason = "resource.dkim2.authentication_reason"
	factLocalPolicyReason    = "resource.dkim2.local_policy_reason"
	factDoNotModifyState     = "resource.dkim2.do_not_modify_state"
	factDoNotExplodeState    = "resource.dkim2.do_not_explode_state"
	factScanAction           = "environment.rspamd.scan_action_before_policy"
	factMetricScore          = "environment.rspamd.metric_score"
	factRejectThreshold      = "environment.rspamd.reject_threshold"
	factGreylistThreshold    = "environment.rspamd.greylist_threshold"
	factClientClass          = "environment.rspamd.client_class"
	factMailFromClass        = "environment.rspamd.mail_from_class"
	fieldSequence            = "sequence"
	fieldMessageInstance     = "message_instance"
	fieldHopBinding          = "hop_binding"
	custodyOrigin            = "origin"
	custodyOrdinary          = "ordinary"
	custodyNextDomain        = "next_domain"
	custodyTerminal          = "terminal_next_domain"
	custodyLinksEvaluated    = "nd_links_evaluated"
	custodyNotPresent        = "not_present"
	custodyTerminalRequires  = "terminal_nd_requires_oob"
	scopeCurrent             = "current"
	scopeChain               = "chain"
	recipeBodyAbsent         = "absent"
	historyMatched           = "matched"
	stateUnavailable         = "unavailable"
	stateComplete            = "complete"
	statePartial             = "partial"
	stateExploded            = "exploded"
	stateIndeterminate       = "indeterminate"
	stateNotEvaluated        = "not_evaluated"
	stateNotRequested        = "not_requested"
	verdictAccept            = "accept"
	verdictContinue          = "continue"
	verdictReject            = "reject"
	classLocal               = "local"
	classExternal            = "external"
)

var exactTarget = pluginapi.DecisionTargetSelector{Namespace: providerNamespace, Action: "accept-message-instance"}

var projectionScopes = []string{scopeCurrent, scopeChain}

var historicalContentStates = []string{stateNotEvaluated, stateComplete, statePartial}

var historicalSignatureStates = []string{stateNotEvaluated, stateComplete}

var custodyStructures = []string{stateNotEvaluated, custodyNotPresent, custodyLinksEvaluated, custodyTerminalRequires}

var doNotModifyStates = []string{stateNotRequested, stateIndeterminate, stateNotEvaluated}

var doNotExplodeStates = []string{stateNotRequested, "violated", stateIndeterminate, stateNotEvaluated}

var rspamdScanActions = []string{
	"no action", "accept", "add header", "rewrite subject", "greylist",
	"soft reject", "reject", "quarantine", "discard",
}

var requiredResourceFacts = []string{
	factProjectionSchema,
	factDraft,
	factBindingAlgorithm,
	"resource.dkim2.projection_binding",
	"resource.dkim2.verification_state",
	"resource.dkim2.verification_reason",
	factScope,
	factHistoricalContent,
	factHistoricalSignatures,
	factCustodyStructure,
	"resource.dkim2.target_sequence",
	"resource.dkim2.target_message_instance",
	"resource.dkim2.claimed_hop_count",
	"resource.dkim2.authentication_state",
	factAuthenticationReason,
	factReplayClass,
	factLocalPolicyMode,
	factLocalPolicyVerdict,
	factLocalPolicyReason,
	factDoNotModifyState,
	factDoNotExplodeState,
	"resource.dkim2.dns_testing_effective",
	"resource.dkim2.disposition",
	"resource.dkim2.chain",
}

var requiredEnvironmentFacts = []string{
	factScanAction,
	factMetricScore,
	factRejectThreshold,
	factGreylistThreshold,
	"environment.rspamd.normalized_signals",
	"environment.rspamd.smtp_client_ip",
	factClientClass,
	factMailFromClass,
	"environment.rspamd.recipient_classes",
	"environment.rspamd.smtp_authenticated",
	"environment.rspamd.recipient_count",
	"environment.rspamd.message_size",
	"environment.rspamd.message_fidelity",
}

// decodeVerifierProjection validates the complete admitted v1 projection and Rspamd context.
func decodeVerifierProjection(request pluginapi.DecisionFactRequest) (verifierProjection, error) {
	if request.Target() != exactTarget {
		return verifierProjection{}, fmt.Errorf("unexpected decision target")
	}

	facts, err := indexFacts(request.Facts())
	if err != nil {
		return verifierProjection{}, err
	}

	if err := validateFactSet(facts); err != nil {
		return verifierProjection{}, err
	}

	projection, err := decodeProjectionAggregate(facts)
	if err != nil {
		return verifierProjection{}, err
	}

	clientIP, err := validateEnvironmentFacts(facts)
	if err != nil {
		return verifierProjection{}, err
	}

	projection.clientIP = clientIP

	return projection, nil
}

// indexFacts rejects duplicate identities before typed extraction.
func indexFacts(input []pluginapi.DecisionFactView) (map[string]pluginapi.DecisionFactView, error) {
	result := make(map[string]pluginapi.DecisionFactView, len(input))
	for _, fact := range input {
		if _, exists := result[fact.ID()]; exists {
			return nil, fmt.Errorf("fact %s occurs more than once", fact.ID())
		}

		result[fact.ID()] = fact
	}

	return result, nil
}

// validateFactSet requires the exact v1 caller-owned namespace members.
func validateFactSet(facts map[string]pluginapi.DecisionFactView) error {
	for _, id := range requiredResourceFacts {
		if err := requireCategory(facts, id, pluginapi.DecisionFactCategoryResource); err != nil {
			return err
		}
	}

	for _, id := range requiredEnvironmentFacts {
		if err := requireCategory(facts, id, pluginapi.DecisionFactCategoryEnvironment); err != nil {
			return err
		}
	}

	for id := range facts {
		if strings.HasPrefix(id, "resource.dkim2.") && !slices.Contains(requiredResourceFacts, id) {
			return fmt.Errorf("unknown DKIM2 fact %s", id)
		}

		if strings.HasPrefix(id, "environment.rspamd.") && !slices.Contains(requiredEnvironmentFacts, id) {
			return fmt.Errorf("unknown Rspamd fact %s", id)
		}
	}

	return nil
}

// requireCategory verifies presence and the host-assigned provenance category.
func requireCategory(facts map[string]pluginapi.DecisionFactView, id string, category pluginapi.DecisionFactCategory) error {
	fact, exists := facts[id]
	if !exists {
		return fmt.Errorf("required fact %s is missing", id)
	}

	if fact.Category() != category {
		return fmt.Errorf("fact %s has an unexpected category", id)
	}

	return nil
}

// decodeProjectionAggregate extracts coherence-critical aggregate and chain values.
func decodeProjectionAggregate(facts map[string]pluginapi.DecisionFactView) (verifierProjection, error) {
	if err := validateAggregateFacts(facts); err != nil {
		return verifierProjection{}, err
	}

	projection, err := decodeAggregateValues(facts)
	if err != nil {
		return verifierProjection{}, err
	}

	chain, err := requireRecords(facts, "resource.dkim2.chain")
	if err != nil {
		return verifierProjection{}, err
	}

	projection.chain, err = decodeVerifierHops(chain)
	if err != nil {
		return verifierProjection{}, err
	}

	if err = validateAggregateCoherence(projection); err != nil {
		return verifierProjection{}, err
	}

	return projection, nil
}

type exactFactSpecification struct {
	id    string
	value string
}

type enumFactSpecification struct {
	id      string
	allowed []string
}

// validateAggregateFacts checks closed values that are not retained for assessment.
func validateAggregateFacts(facts map[string]pluginapi.DecisionFactView) error {
	exact := []exactFactSpecification{
		{id: factProjectionSchema, value: projectionSchema},
		{id: factDraft, value: draftVersion},
		{id: factBindingAlgorithm, value: "sha-256"},
	}
	if err := validateExactFacts(facts, exact); err != nil {
		return err
	}

	enums := []enumFactSpecification{
		{id: factScope, allowed: projectionScopes},
		{id: factHistoricalContent, allowed: historicalContentStates},
		{id: factHistoricalSignatures, allowed: historicalSignatureStates},
		{id: factCustodyStructure, allowed: custodyStructures},
		{id: factReplayClass, allowed: []string{"not_checked", "disabled", "first_seen", stateExploded, "replayed", stateIndeterminate}},
		{id: factLocalPolicyMode, allowed: []string{"strict", "permissive", "testing"}},
		{id: factLocalPolicyVerdict, allowed: []string{verdictAccept, verdictContinue, verdictReject, "tempfail"}},
		{id: factDoNotModifyState, allowed: doNotModifyStates},
		{id: factDoNotExplodeState, allowed: doNotExplodeStates},
	}
	if err := validateEnumFacts(facts, enums); err != nil {
		return err
	}

	for _, id := range []string{factAuthenticationReason, factLocalPolicyReason} {
		if _, err := requireToken(facts, id); err != nil {
			return err
		}
	}

	if _, err := requireToken(facts, "resource.dkim2.verification_reason"); err != nil {
		return err
	}

	if _, err := requireBoolean(facts, "resource.dkim2.dns_testing_effective"); err != nil {
		return err
	}

	return nil
}

// validateExactFacts validates a compact table of required literal values.
func validateExactFacts(facts map[string]pluginapi.DecisionFactView, specifications []exactFactSpecification) error {
	for _, specification := range specifications {
		if err := requireExactString(facts, specification.id, specification.value); err != nil {
			return err
		}
	}

	return nil
}

// validateEnumFacts validates a compact table of required closed vocabularies.
func validateEnumFacts(facts map[string]pluginapi.DecisionFactView, specifications []enumFactSpecification) error {
	for _, specification := range specifications {
		if _, err := requireStringIn(facts, specification.id, specification.allowed...); err != nil {
			return err
		}
	}

	return nil
}

// decodeAggregateValues extracts the aggregate values used by the assessment and coherence checks.
func decodeAggregateValues(facts map[string]pluginapi.DecisionFactView) (verifierProjection, error) {
	projection := verifierProjection{}

	var err error

	projection.projectionBinding, err = requireDigest(facts, "resource.dkim2.projection_binding")
	if err != nil {
		return verifierProjection{}, err
	}

	projection.verificationState, err = requireStringIn(facts, "resource.dkim2.verification_state", "PASS")
	if err != nil {
		return verifierProjection{}, err
	}

	projection.authenticationState, err = requireStringIn(facts, "resource.dkim2.authentication_state", "PASS", "FAIL", "PERMERROR", "TEMPERROR")
	if err != nil {
		return verifierProjection{}, err
	}

	projection.scope, err = requireStringIn(facts, factScope, projectionScopes...)
	if err != nil {
		return verifierProjection{}, err
	}

	projection.historicalContent, err = requireStringIn(facts, factHistoricalContent, historicalContentStates...)
	if err != nil {
		return verifierProjection{}, err
	}

	projection.historicalSignatures, err = requireStringIn(facts, factHistoricalSignatures, historicalSignatureStates...)
	if err != nil {
		return verifierProjection{}, err
	}

	projection.custodyStructure, err = requireStringIn(
		facts,
		factCustodyStructure,
		custodyStructures...,
	)
	if err != nil {
		return verifierProjection{}, err
	}

	projection.disposition, err = requireStringIn(facts, "resource.dkim2.disposition", verdictAccept, verdictContinue, verdictReject, "tempfail", "out_of_band_required")
	if err != nil {
		return verifierProjection{}, err
	}

	projection.doNotModifyState, err = requireStringIn(facts, factDoNotModifyState, doNotModifyStates...)
	if err != nil {
		return verifierProjection{}, err
	}

	projection.doNotExplodeState, err = requireStringIn(facts, factDoNotExplodeState, doNotExplodeStates...)
	if err != nil {
		return verifierProjection{}, err
	}

	projection.targetSequence, err = requirePositiveInteger(facts, "resource.dkim2.target_sequence")
	if err != nil {
		return verifierProjection{}, err
	}

	projection.targetMessageInstance, err = requirePositiveInteger(facts, "resource.dkim2.target_message_instance")
	if err != nil {
		return verifierProjection{}, err
	}

	projection.claimedHopCount, err = requirePositiveInteger(facts, "resource.dkim2.claimed_hop_count")
	if err != nil || projection.claimedHopCount > maximumHops {
		return verifierProjection{}, fmt.Errorf("invalid claimed hop count")
	}

	return projection, nil
}

// validateAggregateCoherence cross-checks target, custody, count, and cryptographic bindings.
//
//nolint:gocyclo // The aggregate contract has independent fail-closed coherence gates.
func validateAggregateCoherence(projection verifierProjection) error {
	last := projection.chain[len(projection.chain)-1]
	if int64(len(projection.chain)) != projection.claimedHopCount || last.sequence != projection.targetSequence ||
		last.messageInstance != projection.targetMessageInstance {
		return fmt.Errorf("chain count or target does not match aggregate facts")
	}

	if err := validateProjectionMode(projection); err != nil {
		return err
	}

	if err := validateCustodyStructure(projection); err != nil {
		return err
	}

	if err := validateAggregateProtectionStates(projection); err != nil {
		return err
	}

	if !validProjectionBindings(projection.projectionBinding, projection.chain) {
		return fmt.Errorf("projection or hop binding does not match canonical verifier facts")
	}

	return nil
}

// validateProjectionMode correlates aggregate evaluation states with the requested history scope.
func validateProjectionMode(projection verifierProjection) error {
	switch projection.scope {
	case scopeCurrent:
		return validateCurrentProjectionMode(projection)
	case scopeChain:
		return validateChainProjectionMode(projection)
	default:
		return fmt.Errorf("unsupported projection scope")
	}
}

// validateCurrentProjectionMode enforces the single-hop non-historical PASS envelope.
func validateCurrentProjectionMode(projection verifierProjection) error {
	if len(projection.chain) != 1 {
		return fmt.Errorf("current scope requires exactly one record")
	}

	if projection.historicalContent != stateNotEvaluated ||
		projection.historicalSignatures != stateNotEvaluated ||
		projection.custodyStructure != custodyNotPresent {
		return fmt.Errorf("current scope requires non-evaluated history and absent custody")
	}

	if projection.doNotModifyState != stateNotEvaluated || projection.doNotExplodeState != stateNotEvaluated {
		return fmt.Errorf("current scope requires non-evaluated protection aggregates")
	}

	return nil
}

// validateChainProjectionMode enforces complete historical and aggregate evaluation.
func validateChainProjectionMode(projection verifierProjection) error {
	if projection.historicalContent != stateComplete || projection.historicalSignatures != stateComplete {
		return fmt.Errorf("chain scope requires complete history aggregates")
	}

	if projection.custodyStructure == stateNotEvaluated {
		return fmt.Errorf("chain scope requires evaluated custody structure")
	}

	if projection.doNotModifyState == stateNotEvaluated || projection.doNotExplodeState == stateNotEvaluated {
		return fmt.Errorf("chain scope requires evaluated protection aggregates")
	}

	return nil
}

type custodyTransitionSummary struct {
	terminalCount int
	hasNextDomain bool
	lastTerminal  bool
}

// summarizeCustodyTransitions captures the facts needed to validate the aggregate custody state.
func summarizeCustodyTransitions(chain []verifierHop) custodyTransitionSummary {
	summary := custodyTransitionSummary{
		lastTerminal: chain[len(chain)-1].custodyTransition == custodyTerminal,
	}

	for _, hop := range chain {
		summary.hasNextDomain = summary.hasNextDomain || hop.custodyTransition == custodyNextDomain
		if hop.custodyTransition == custodyTerminal {
			summary.terminalCount++
		}
	}

	return summary
}

// terminalPlacementValid reports whether at most one terminal transition occurs and it is final.
func (s custodyTransitionSummary) terminalPlacementValid() bool {
	return s.terminalCount <= 1 && (s.terminalCount == 1) == s.lastTerminal
}

// validateCustodyStructure correlates aggregate custody with authenticated transition records.
func validateCustodyStructure(projection verifierProjection) error {
	if projection.scope == scopeCurrent {
		return nil
	}

	summary := summarizeCustodyTransitions(projection.chain)

	if !summary.terminalPlacementValid() {
		return fmt.Errorf("terminal custody transition must be the final hop")
	}

	switch projection.custodyStructure {
	case custodyNotPresent:
		if summary.hasNextDomain || summary.terminalCount > 0 {
			return fmt.Errorf("absent custody aggregate contains a next-domain transition")
		}
	case custodyLinksEvaluated:
		if !summary.hasNextDomain || summary.terminalCount > 0 {
			return fmt.Errorf("evaluated custody links require a non-terminal next-domain transition")
		}
	case custodyTerminalRequires:
		if !summary.lastTerminal {
			return fmt.Errorf("terminal custody aggregate does not match final hop")
		}
	default:
		return fmt.Errorf("unsupported custody aggregate")
	}

	return nil
}

// validateAggregateProtectionStates correlates chain requests with their aggregate evaluation states.
func validateAggregateProtectionStates(projection verifierProjection) error {
	if projection.scope == scopeCurrent {
		return nil
	}

	modifyRequested := slices.ContainsFunc(projection.chain, func(hop verifierHop) bool { return hop.doNotModify })
	explodeRequested := slices.ContainsFunc(projection.chain, func(hop verifierHop) bool { return hop.doNotExplode })

	if (projection.doNotModifyState == stateNotRequested) == modifyRequested {
		return fmt.Errorf("do-not-modify aggregate contradicts chain flags")
	}

	if (projection.doNotExplodeState == stateNotRequested) == explodeRequested {
		return fmt.Errorf("do-not-explode aggregate contradicts chain flags")
	}

	return nil
}

// validateEnvironmentFacts validates Rspamd observations and returns the exact SMTP peer.
func validateEnvironmentFacts(facts map[string]pluginapi.DecisionFactView) (netip.Addr, error) {
	enums := []enumFactSpecification{
		{id: factScanAction, allowed: rspamdScanActions},
		{id: factClientClass, allowed: []string{"untrusted", "trusted", classLocal, "authenticated"}},
		{id: factMailFromClass, allowed: []string{"null", classLocal, classExternal}},
	}
	if err := validateEnumFacts(facts, enums); err != nil {
		return netip.Addr{}, err
	}

	for _, id := range []string{factMetricScore, factRejectThreshold, factGreylistThreshold} {
		if _, err := requireDouble(facts, id); err != nil {
			return netip.Addr{}, err
		}
	}

	if err := validateEnvironmentLists(facts); err != nil {
		return netip.Addr{}, err
	}

	if err := validateEnvironmentScalars(facts); err != nil {
		return netip.Addr{}, err
	}

	clientIPText, err := requireString(facts, "environment.rspamd.smtp_client_ip")
	if err != nil {
		return netip.Addr{}, err
	}

	return parseCanonicalClientIP(clientIPText)
}

// validateEnvironmentLists validates bounded sorted Rspamd list facts.
func validateEnvironmentLists(facts map[string]pluginapi.DecisionFactView) error {
	signals, err := requireStrings(facts, "environment.rspamd.normalized_signals")
	if err != nil || len(signals) > 32 || !sortedUniqueStrings(signals) || !allStringsAllowed(signals, allowedRspamdSignal) {
		return fmt.Errorf("invalid normalized Rspamd signals")
	}

	recipients, err := requireStrings(facts, "environment.rspamd.recipient_classes")
	if err != nil || len(recipients) > 16 || !sortedUniqueStrings(recipients) || !allStringsAllowed(recipients, allowedRecipientClass) {
		return fmt.Errorf("invalid recipient classes")
	}

	return nil
}

// validateEnvironmentScalars validates non-reputation Rspamd scalar facts.
func validateEnvironmentScalars(facts map[string]pluginapi.DecisionFactView) error {
	if _, err := requireBoolean(facts, "environment.rspamd.smtp_authenticated"); err != nil {
		return err
	}

	if _, err := requirePositiveInteger(facts, "environment.rspamd.recipient_count"); err != nil {
		return err
	}

	if _, err := requireNonnegativeInteger(facts, "environment.rspamd.message_size"); err != nil {
		return err
	}

	if err := requireExactString(facts, "environment.rspamd.message_fidelity", "milter_reconstructed_crlf"); err != nil {
		return err
	}

	return nil
}

// decodeVerifierHops validates ordered complete-chain records.
func decodeVerifierHops(list pluginapi.DecisionRecordList) ([]verifierHop, error) {
	records := list.Records()
	if len(records) == 0 || len(records) > maximumHops {
		return nil, fmt.Errorf("chain must contain between one and %d records", maximumHops)
	}

	result := make([]verifierHop, 0, len(records))
	bindings := make(map[string]struct{}, len(records))

	for index, record := range records {
		hop, err := decodeVerifierHop(record)
		if err != nil {
			return nil, fmt.Errorf("chain record %d: %w", index, err)
		}

		expectedSequence := int64(index + 1)
		if hop.sequence != expectedSequence {
			return nil, fmt.Errorf("chain record %d has a noncontiguous sequence", index)
		}

		bindingKey := string(hop.hopBinding)
		if _, exists := bindings[bindingKey]; exists {
			return nil, fmt.Errorf("chain record %d repeats a hop binding", index)
		}

		bindings[bindingKey] = struct{}{}

		result = append(result, hop)
	}

	if result[0].custodyTransition != custodyOrigin {
		return nil, fmt.Errorf("first chain record must be the origin")
	}

	for index := 1; index < len(result); index++ {
		if result[index].custodyTransition == custodyOrigin {
			return nil, fmt.Errorf("chain record %d repeats origin custody", index)
		}
	}

	return result, nil
}

// decodeVerifierHop validates one exact closed verifier record.
//
//nolint:funlen,gocyclo // Keeping the closed record decoder together makes field auditing explicit.
func decodeVerifierHop(record pluginapi.DecisionRecord) (verifierHop, error) {
	fields, err := indexRecordFields(record)
	if err != nil {
		return verifierHop{}, err
	}

	required := []string{
		fieldSequence, fieldMessageInstance, fieldHopBinding, "signer_domain", "signature_algorithms", "signature_state",
		"custody_transition", "do_not_modify", "do_not_explode", "feedback", "feed_here", "exploded",
		"recipe_mode", "recipe_has_header_changes", "recipe_body_mode", "recipe_digest", "change_classes",
		"affected_headers", "history_header_state", "history_body_state", "body_availability", "change_count",
		"affected_header_count",
	}
	if len(fields) != len(required) {
		return verifierHop{}, fmt.Errorf("record has unknown or missing fields")
	}

	for _, name := range required {
		if _, exists := fields[name]; !exists {
			return verifierHop{}, fmt.Errorf("required field %s is missing", name)
		}
	}

	sequence, err := recordPositiveInteger(fields, fieldSequence)
	if err != nil {
		return verifierHop{}, err
	}

	instance, err := recordPositiveInteger(fields, fieldMessageInstance)
	if err != nil {
		return verifierHop{}, err
	}

	hopBinding, err := recordDigest(fields, fieldHopBinding)
	if err != nil {
		return verifierHop{}, err
	}

	domain, err := recordString(fields, "signer_domain")
	if err != nil || !canonicalDomain(domain) {
		return verifierHop{}, fmt.Errorf("signer_domain is not canonical")
	}

	algorithms, err := recordStrings(fields, "signature_algorithms")
	if err != nil || len(algorithms) == 0 || len(algorithms) > 4 || !sortedUniqueStrings(algorithms) || !allStringsAllowed(algorithms, allowedSignatureAlgorithm) {
		return verifierHop{}, fmt.Errorf("signature_algorithms is invalid")
	}

	signatureState, err := recordStringIn(fields, "signature_state", "pass")
	if err != nil {
		return verifierHop{}, err
	}

	custody, err := recordStringIn(fields, "custody_transition", custodyOrigin, custodyOrdinary, custodyNextDomain, custodyTerminal)
	if err != nil {
		return verifierHop{}, err
	}

	recipeMode, err := recordStringIn(fields, "recipe_mode", "unchanged", "applied")
	if err != nil {
		return verifierHop{}, err
	}

	recipeBodyMode, err := recordStringIn(fields, "recipe_body_mode", recipeBodyAbsent, "steps", stateUnavailable)
	if err != nil {
		return verifierHop{}, err
	}

	recipeDigest, err := recordDigest(fields, "recipe_digest")
	if err != nil {
		return verifierHop{}, err
	}

	changes, err := recordStrings(fields, "change_classes")
	if err != nil || len(changes) > 2 || !sortedUniqueStrings(changes) || !allStringsAllowed(changes, allowedChangeClass) {
		return verifierHop{}, fmt.Errorf("change_classes is invalid")
	}

	headers, err := recordStrings(fields, "affected_headers")
	if err != nil || len(headers) > 128 || !sortedUniqueStrings(headers) || !allStringsAllowed(headers, canonicalHeaderName) {
		return verifierHop{}, fmt.Errorf("affected_headers is invalid")
	}

	historyHeader, err := recordStringIn(fields, "history_header_state", historyMatched, "mismatch", stateUnavailable, "unsupported")
	if err != nil {
		return verifierHop{}, err
	}

	historyBody, err := recordStringIn(fields, "history_body_state", historyMatched, "mismatch", stateUnavailable, "unsupported")
	if err != nil {
		return verifierHop{}, err
	}

	bodyAvailability, err := recordStringIn(fields, "body_availability", "known", stateUnavailable)
	if err != nil {
		return verifierHop{}, err
	}

	if (bodyAvailability == stateUnavailable) != (historyBody == stateUnavailable) {
		return verifierHop{}, fmt.Errorf("body availability does not match history body state")
	}

	changeCount, err := recordNonnegativeInteger(fields, "change_count")
	if err != nil || changeCount != int64(len(changes)) {
		return verifierHop{}, fmt.Errorf("change_count does not match change_classes")
	}

	headerCount, err := recordNonnegativeInteger(fields, "affected_header_count")
	if err != nil || headerCount != int64(len(headers)) {
		return verifierHop{}, fmt.Errorf("affected_header_count does not match affected_headers")
	}

	hasHeaders, err := recordBoolean(fields, "recipe_has_header_changes")
	if err != nil || hasHeaders != (len(headers) > 0) || hasHeaders != slices.Contains(changes, "header.rewrite") {
		return verifierHop{}, fmt.Errorf("recipe header projection is incoherent")
	}

	if slices.Contains(changes, "body.rewrite") != (recipeBodyMode != recipeBodyAbsent) {
		return verifierHop{}, fmt.Errorf("recipe body projection is incoherent")
	}

	if recipeMode == "unchanged" && (len(changes) != 0 || len(headers) != 0 || recipeBodyMode != recipeBodyAbsent) {
		return verifierHop{}, fmt.Errorf("unchanged Recipe contains changes")
	}

	if recipeMode == "applied" && len(changes) == 0 {
		return verifierHop{}, fmt.Errorf("applied Recipe contains no changes")
	}

	doNotModify, err := recordBoolean(fields, "do_not_modify")
	if err != nil {
		return verifierHop{}, err
	}

	doNotExplode, err := recordBoolean(fields, "do_not_explode")
	if err != nil {
		return verifierHop{}, err
	}

	feedback, err := recordBoolean(fields, "feedback")
	if err != nil {
		return verifierHop{}, err
	}

	feedHere, err := recordBoolean(fields, "feed_here")
	if err != nil {
		return verifierHop{}, err
	}

	exploded, err := recordBoolean(fields, "exploded")
	if err != nil {
		return verifierHop{}, err
	}

	return verifierHop{
		signerDomain: domain, signatureAlgorithms: algorithms, hopBinding: hopBinding, recipeDigest: recipeDigest, changeClasses: changes,
		affectedHeaders: headers, signatureState: signatureState, custodyTransition: custody, recipeMode: recipeMode,
		recipeBodyMode: recipeBodyMode, historyHeaderState: historyHeader, historyBodyState: historyBody,
		bodyAvailability: bodyAvailability, sequence: sequence, messageInstance: instance, changeCount: changeCount,
		affectedHeaderCount: headerCount, doNotModify: doNotModify, doNotExplode: doNotExplode, feedback: feedback,
		feedHere: feedHere, exploded: exploded, recipeHasHeaders: hasHeaders,
	}, nil
}

// indexRecordFields rejects duplicate local names before typed extraction.
func indexRecordFields(record pluginapi.DecisionRecord) (map[string]pluginapi.DecisionRecordFieldValue, error) {
	result := make(map[string]pluginapi.DecisionRecordFieldValue, len(record.Fields()))
	for _, field := range record.Fields() {
		if _, exists := result[field.Name()]; exists {
			return nil, fmt.Errorf("field %s occurs more than once", field.Name())
		}

		result[field.Name()] = field.Value()
	}

	return result, nil
}

// requireString extracts one string fact.
func requireString(facts map[string]pluginapi.DecisionFactView, id string) (string, error) {
	value, ok := facts[id].Value().StringValue()
	if !ok {
		return "", fmt.Errorf("fact %s must be a string", id)
	}

	return value, nil
}

// requireExactString enforces one exact string fact.
func requireExactString(facts map[string]pluginapi.DecisionFactView, id string, expected string) error {
	value, err := requireString(facts, id)
	if err != nil || value != expected {
		return fmt.Errorf("fact %s must be %q", id, expected)
	}

	return nil
}

// requireStringIn extracts one string from an explicit vocabulary.
func requireStringIn(facts map[string]pluginapi.DecisionFactView, id string, allowed ...string) (string, error) {
	value, err := requireString(facts, id)
	if err != nil || !slices.Contains(allowed, value) {
		return "", fmt.Errorf("fact %s has an unsupported value", id)
	}

	return value, nil
}

// requireToken extracts one bounded lowercase policy token.
func requireToken(facts map[string]pluginapi.DecisionFactView, id string) (string, error) {
	value, err := requireString(facts, id)
	if err != nil || !canonicalToken(value) {
		return "", fmt.Errorf("fact %s must be a canonical token", id)
	}

	return value, nil
}

// requirePositiveInteger extracts one positive integer fact.
func requirePositiveInteger(facts map[string]pluginapi.DecisionFactView, id string) (int64, error) {
	value, err := requireNonnegativeInteger(facts, id)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("fact %s must be a positive integer", id)
	}

	return value, nil
}

// requireNonnegativeInteger extracts one nonnegative integer fact.
func requireNonnegativeInteger(facts map[string]pluginapi.DecisionFactView, id string) (int64, error) {
	value, ok := facts[id].Value().Integer()
	if !ok || value < 0 {
		return 0, fmt.Errorf("fact %s must be a nonnegative integer", id)
	}

	return value, nil
}

// requireBoolean extracts one boolean fact.
func requireBoolean(facts map[string]pluginapi.DecisionFactView, id string) (bool, error) {
	value, ok := facts[id].Value().Boolean()
	if !ok {
		return false, fmt.Errorf("fact %s must be a boolean", id)
	}

	return value, nil
}

// requireDouble extracts one finite double fact.
func requireDouble(facts map[string]pluginapi.DecisionFactView, id string) (float64, error) {
	value, ok := facts[id].Value().Double()
	if !ok {
		return 0, fmt.Errorf("fact %s must be a double", id)
	}

	return value, nil
}

// requireStrings extracts one detached string-list fact.
func requireStrings(facts map[string]pluginapi.DecisionFactView, id string) ([]string, error) {
	value, ok := facts[id].Value().Strings()
	if !ok {
		return nil, fmt.Errorf("fact %s must be a string list", id)
	}

	return value, nil
}

// requireDigest extracts one exact nonzero SHA-256-sized byte fact.
func requireDigest(facts map[string]pluginapi.DecisionFactView, id string) ([]byte, error) {
	value, ok := facts[id].Value().Bytes()
	if !ok || len(value) != 32 || bytes.Equal(value, make([]byte, 32)) {
		return nil, fmt.Errorf("fact %s must be a nonzero 32-byte digest", id)
	}

	return value, nil
}

// requireRecords extracts one detached record-list fact.
func requireRecords(facts map[string]pluginapi.DecisionFactView, id string) (pluginapi.DecisionRecordList, error) {
	value, ok := facts[id].Value().Records()
	if !ok {
		return pluginapi.DecisionRecordList{}, fmt.Errorf("fact %s must be a record list", id)
	}

	return value, nil
}

// recordString extracts one record string field.
func recordString(fields map[string]pluginapi.DecisionRecordFieldValue, name string) (string, error) {
	value, exists := fields[name]
	if !exists {
		return "", fmt.Errorf("field %s is missing", name)
	}

	result, ok := value.Value().StringValue()
	if !ok {
		return "", fmt.Errorf("field %s must be a string", name)
	}

	return result, nil
}

// recordStringIn extracts one record string from an explicit vocabulary.
func recordStringIn(fields map[string]pluginapi.DecisionRecordFieldValue, name string, allowed ...string) (string, error) {
	value, err := recordString(fields, name)
	if err != nil || !slices.Contains(allowed, value) {
		return "", fmt.Errorf("field %s has an unsupported value", name)
	}

	return value, nil
}

// recordPositiveInteger extracts one positive record integer.
func recordPositiveInteger(fields map[string]pluginapi.DecisionRecordFieldValue, name string) (int64, error) {
	value, err := recordNonnegativeInteger(fields, name)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("field %s must be positive", name)
	}

	return value, nil
}

// recordNonnegativeInteger extracts one nonnegative record integer.
func recordNonnegativeInteger(fields map[string]pluginapi.DecisionRecordFieldValue, name string) (int64, error) {
	field, exists := fields[name]
	if !exists {
		return 0, fmt.Errorf("field %s is missing", name)
	}

	value, ok := field.Value().Integer()
	if !ok || value < 0 {
		return 0, fmt.Errorf("field %s must be nonnegative", name)
	}

	return value, nil
}

// recordBoolean extracts one record boolean field.
func recordBoolean(fields map[string]pluginapi.DecisionRecordFieldValue, name string) (bool, error) {
	field, exists := fields[name]
	if !exists {
		return false, fmt.Errorf("field %s is missing", name)
	}

	value, ok := field.Value().Boolean()
	if !ok {
		return false, fmt.Errorf("field %s must be a boolean", name)
	}

	return value, nil
}

// recordStrings extracts one record string-list field.
func recordStrings(fields map[string]pluginapi.DecisionRecordFieldValue, name string) ([]string, error) {
	field, exists := fields[name]
	if !exists {
		return nil, fmt.Errorf("field %s is missing", name)
	}

	value, ok := field.Value().Strings()
	if !ok {
		return nil, fmt.Errorf("field %s must be a string list", name)
	}

	return value, nil
}

// recordDigest extracts one exact nonzero record digest.
func recordDigest(fields map[string]pluginapi.DecisionRecordFieldValue, name string) ([]byte, error) {
	field, exists := fields[name]
	if !exists {
		return nil, fmt.Errorf("field %s is missing", name)
	}

	value, ok := field.Value().Bytes()
	if !ok || len(value) != 32 || bytes.Equal(value, make([]byte, 32)) {
		return nil, fmt.Errorf("field %s must be a nonzero 32-byte digest", name)
	}

	return value, nil
}

// parseCanonicalClientIP rejects aliases and local-only addresses unsuitable as an SMTP peer identity.
func parseCanonicalClientIP(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.String() != value || address.Is4In6() || address.IsUnspecified() ||
		address.IsMulticast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return netip.Addr{}, fmt.Errorf("smtp_client_ip must be a canonical unicast IPv4 or IPv6 address")
	}

	return address, nil
}

// canonicalDomain validates an exact lower-case ASCII DNS name without a root dot.
//
//nolint:gocyclo // DNS label syntax is clearer as direct byte predicates.
func canonicalDomain(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}

	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for index := range len(label) {
			current := label[index]
			if current != '-' && (current < 'a' || current > 'z') && (current < '0' || current > '9') {
				return false
			}
		}
	}

	return true
}

// canonicalHeaderName validates a privacy-minimized lower-case RFC field name.
func canonicalHeaderName(value string) bool {
	if value == "" || len(value) > 64 || value != strings.ToLower(value) {
		return false
	}

	for index := range len(value) {
		current := value[index]
		if current < 33 || current > 126 || current == ':' {
			return false
		}
	}

	return true
}

// canonicalToken validates a bounded lower-case underscore token.
func canonicalToken(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}

	for index := range len(value) {
		current := value[index]
		if current != '_' && current != '-' && (current < 'a' || current > 'z') && (current < '0' || current > '9') {
			return false
		}
	}

	return true
}

// sortedUniqueStrings enforces the v1 byte-lexical list canonicalization.
func sortedUniqueStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] >= values[index] {
			return false
		}
	}

	return true
}

// allStringsAllowed checks a list against one closed member predicate.
func allStringsAllowed(values []string, allowed func(string) bool) bool {
	for _, value := range values {
		if !allowed(value) {
			return false
		}
	}

	return true
}

// allowedChangeClass reports the conservative Recipe descriptor vocabulary.
func allowedChangeClass(value string) bool {
	return value == "body.rewrite" || value == "header.rewrite"
}

// allowedSignatureAlgorithm reports the v1 authenticated algorithm vocabulary.
func allowedSignatureAlgorithm(value string) bool {
	return slices.Contains([]string{"ed25519-sha256", "ed25519-sha512", "rsa-sha256", "rsa-sha512"}, value)
}

// allowedRspamdSignal reports the v1 normalized signal vocabulary.
func allowedRspamdSignal(value string) bool {
	return slices.Contains([]string{
		"arc.fail", "arc.invalid", "arc.pass", "dkim.fail", "dkim.pass", "dkim.permerror", "dkim.temperror",
		"dmarc.fail", "dmarc.pass", "dmarc.permerror", "dmarc.temperror", "malware.detected", "phishing.detected",
		"spam.high_confidence", "spf.fail", "spf.neutral", "spf.pass", "spf.permerror", "spf.softfail", "spf.temperror",
	}, value)
}

// allowedRecipientClass reports the privacy-minimized recipient vocabulary.
func allowedRecipientClass(value string) bool {
	return value == "external" || value == "local" || value == "relay"
}
