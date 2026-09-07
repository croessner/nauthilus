// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package dkim2projection

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// Projection constants describe the closed admitted verifier wire contract.
const (
	factVerificationState   = "resource.dkim2.verification_state"
	factAuthenticationState = "resource.dkim2.authentication_state"
	factDisposition         = "resource.dkim2.disposition"
	factReceivedDSN         = "resource.dkim2.received_dsn_propagation"
	verdictTempfail         = "tempfail"
	verificationPass        = "PASS"

	ProjectionSchema         = "dkim2.verifier-projection.v1"
	DraftVersion             = "draft-ietf-dkim-dkim2-spec-06"
	maximumHops              = 128
	FactProjectionSchema     = "resource.dkim2.projection_schema"
	factDraft                = "resource.dkim2.draft"
	factBindingAlgorithm     = "resource.dkim2.projection_binding_algorithm"
	FactScope                = "resource.dkim2.scope"
	FactHistoricalContent    = "resource.dkim2.historical_content"
	FactHistoricalSignatures = "resource.dkim2.historical_signatures"
	FactCustodyStructure     = "resource.dkim2.custody_structure"
	factReplayClass          = "resource.dkim2.replay_class"
	factLocalPolicyMode      = "resource.dkim2.local_policy_mode"
	factLocalPolicyVerdict   = "resource.dkim2.local_policy_verdict"
	factAuthenticationReason = "resource.dkim2.authentication_reason"
	factLocalPolicyReason    = "resource.dkim2.local_policy_reason"
	FactDoNotModifyState     = "resource.dkim2.do_not_modify_state"
	FactDoNotExplodeState    = "resource.dkim2.do_not_explode_state"
	FactScanAction           = "environment.rspamd.scan_action_before_policy"
	factMetricScore          = "environment.rspamd.metric_score"
	factRejectThreshold      = "environment.rspamd.reject_threshold"
	factGreylistThreshold    = "environment.rspamd.greylist_threshold"
	factClientClass          = "environment.rspamd.client_class"
	factMailFromClass        = "environment.rspamd.mail_from_class"
	FieldSequence            = "sequence"
	FieldMessageInstance     = "message_instance"
	FieldHopBinding          = "hop_binding"
	CustodyOrigin            = "origin"
	CustodyOrdinary          = "ordinary"
	CustodyNextDomain        = "next_domain"
	CustodyTerminal          = "terminal_next_domain"
	CustodyLinksEvaluated    = "nd_links_evaluated"
	custodyNotPresent        = "not_present"
	CustodyTerminalRequires  = "terminal_nd_requires_oob"
	ScopeCurrent             = "current"
	scopeChain               = "chain"
	RecipeBodyAbsent         = "absent"
	HistoryMatched           = "matched"
	StateUnavailable         = "unavailable"
	stateComplete            = "complete"
	statePartial             = "partial"
	stateExploded            = "exploded"
	StateIndeterminate       = "indeterminate"
	StateNotEvaluated        = "not_evaluated"
	StateNotRequested        = "not_requested"
	VerdictAccept            = "accept"
	VerdictContinue          = "continue"
	verdictReject            = "reject"
	classLocal               = "local"
	classExternal            = "external"
)

// ExactTarget identifies the single verifier composition checkpoint.
var ExactTarget = pluginapi.DecisionTargetSelector{Namespace: "dkim2", Action: "accept-message-instance"}

var projectionScopes = []string{ScopeCurrent, scopeChain}

var historicalContentStates = []string{StateNotEvaluated, stateComplete, statePartial}

var historicalSignatureStates = []string{StateNotEvaluated, stateComplete}

var custodyStructures = []string{StateNotEvaluated, custodyNotPresent, CustodyLinksEvaluated, CustodyTerminalRequires}

var doNotModifyStates = []string{StateNotRequested, StateIndeterminate, StateNotEvaluated}

var doNotExplodeStates = []string{StateNotRequested, "violated", StateIndeterminate, StateNotEvaluated}

// RspamdScanActions lists the closed pre-Policy scan action vocabulary.
var RspamdScanActions = []string{
	"no action", "accept", "add header", "rewrite subject", "greylist",
	"soft reject", "reject", "quarantine", "discard",
}

var requiredResourceFacts = []string{
	FactProjectionSchema,
	factDraft,
	factBindingAlgorithm,
	"resource.dkim2.projection_binding",
	factVerificationState,
	"resource.dkim2.verification_reason",
	FactScope,
	FactHistoricalContent,
	FactHistoricalSignatures,
	FactCustodyStructure,
	"resource.dkim2.target_sequence",
	"resource.dkim2.target_message_instance",
	"resource.dkim2.claimed_hop_count",
	factAuthenticationState,
	factAuthenticationReason,
	factReplayClass,
	factLocalPolicyMode,
	factLocalPolicyVerdict,
	factLocalPolicyReason,
	FactDoNotModifyState,
	FactDoNotExplodeState,
	"resource.dkim2.dns_testing_effective",
	factDisposition,
	"resource.dkim2.chain",
}

var requiredEnvironmentFacts = []string{
	FactScanAction,
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

// Decode validates the complete admitted v1 projection and Rspamd context.
func Decode(request pluginapi.DecisionFactRequest) (Projection, error) {
	if request.Target() != ExactTarget {
		return Projection{}, fmt.Errorf("unexpected decision target")
	}

	facts, err := indexFacts(request.Facts())
	if err != nil {
		return Projection{}, err
	}

	if err := validateFactSet(facts); err != nil {
		return Projection{}, err
	}

	projection, err := decodeProjectionAggregate(facts)
	if err != nil {
		return Projection{}, err
	}

	ClientIP, err := validateEnvironmentFacts(facts)
	if err != nil {
		return Projection{}, err
	}

	projection.ClientIP = ClientIP

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
		if strings.HasPrefix(id, "resource.dkim2.") && id != factReceivedDSN && !slices.Contains(requiredResourceFacts, id) {
			return fmt.Errorf("unknown DKIM2 fact %s", id)
		}

		if strings.HasPrefix(id, "environment.rspamd.") && !slices.Contains(requiredEnvironmentFacts, id) {
			return fmt.Errorf("unknown Rspamd fact %s", id)
		}
	}

	return validateOptionalReceivedDSN(facts)
}

// validateOptionalReceivedDSN admits the verifier's optional delivery-status fact without deriving composition authority from it.
func validateOptionalReceivedDSN(facts map[string]pluginapi.DecisionFactView) error {
	if _, exists := facts[factReceivedDSN]; !exists {
		return nil
	}

	if err := requireCategory(facts, factReceivedDSN, pluginapi.DecisionFactCategoryResource); err != nil {
		return err
	}

	_, err := requireStringIn(facts, factReceivedDSN, "not_applicable", "eligible", "terminal_origin", "not_failure",
		"forbidden_null_previous_sender", "unsupported_chain", "not_reconstructable", "not_evaluated")

	return err
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
func decodeProjectionAggregate(facts map[string]pluginapi.DecisionFactView) (Projection, error) {
	if err := validateAggregateFacts(facts); err != nil {
		return Projection{}, err
	}

	projection, err := decodeAggregateValues(facts)
	if err != nil {
		return Projection{}, err
	}

	Chain, err := requireRecords(facts, "resource.dkim2.chain")
	if err != nil {
		return Projection{}, err
	}

	projection.Chain, err = decodeVerifierHops(Chain)
	if err != nil {
		return Projection{}, err
	}

	if err = validateAggregateCoherence(projection); err != nil {
		return Projection{}, err
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
		{id: FactProjectionSchema, value: ProjectionSchema},
		{id: factDraft, value: DraftVersion},
		{id: factBindingAlgorithm, value: "sha-256"},
	}
	if err := validateExactFacts(facts, exact); err != nil {
		return err
	}

	enums := []enumFactSpecification{
		{id: FactScope, allowed: projectionScopes},
		{id: FactHistoricalContent, allowed: historicalContentStates},
		{id: FactHistoricalSignatures, allowed: historicalSignatureStates},
		{id: FactCustodyStructure, allowed: custodyStructures},
		{id: factReplayClass, allowed: []string{"not_checked", "disabled", "first_seen", stateExploded, "replayed", StateIndeterminate}},
		{id: factLocalPolicyMode, allowed: []string{"strict", "permissive", "testing"}},
		{id: factLocalPolicyVerdict, allowed: []string{VerdictAccept, VerdictContinue, verdictReject, verdictTempfail}},
		{id: FactDoNotModifyState, allowed: doNotModifyStates},
		{id: FactDoNotExplodeState, allowed: doNotExplodeStates},
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
func decodeAggregateValues(facts map[string]pluginapi.DecisionFactView) (Projection, error) {
	projection := Projection{}

	binding, err := requireDigest(facts, "resource.dkim2.projection_binding")
	if err != nil {
		return Projection{}, err
	}

	projection.ProjectionBinding = binding

	specifications := []struct {
		destination *string
		id          string
		allowed     []string
	}{
		{&projection.VerificationState, factVerificationState, []string{verificationPass}},
		{&projection.AuthenticationState, factAuthenticationState, []string{verificationPass, "FAIL", "PERMERROR", "TEMPERROR"}},
		{&projection.Scope, FactScope, projectionScopes},
		{&projection.HistoricalContent, FactHistoricalContent, historicalContentStates},
		{&projection.HistoricalSignatures, FactHistoricalSignatures, historicalSignatureStates},
		{&projection.CustodyStructure, FactCustodyStructure, custodyStructures},
		{&projection.Disposition, factDisposition, []string{VerdictAccept, VerdictContinue, verdictReject, verdictTempfail, "out_of_band_required"}},
		{&projection.DoNotModifyState, FactDoNotModifyState, doNotModifyStates},
		{&projection.DoNotExplodeState, FactDoNotExplodeState, doNotExplodeStates},
	}
	for _, specification := range specifications {
		value, err := requireStringIn(facts, specification.id, specification.allowed...)
		if err != nil {
			return Projection{}, err
		}

		*specification.destination = value
	}

	projection.TargetSequence, err = requirePositiveInteger(facts, "resource.dkim2.target_sequence")
	if err != nil {
		return Projection{}, err
	}

	projection.TargetMessageInstance, err = requirePositiveInteger(facts, "resource.dkim2.target_message_instance")
	if err != nil {
		return Projection{}, err
	}

	projection.ClaimedHopCount, err = requirePositiveInteger(facts, "resource.dkim2.claimed_hop_count")
	if err != nil || projection.ClaimedHopCount > maximumHops {
		return Projection{}, fmt.Errorf("invalid claimed hop count")
	}

	return projection, nil
}

// validateAggregateCoherence cross-checks target, custody, count, and cryptographic bindings.
//
//nolint:gocyclo // The aggregate contract has independent fail-closed coherence gates.
func validateAggregateCoherence(projection Projection) error {
	last := projection.Chain[len(projection.Chain)-1]
	if int64(len(projection.Chain)) != projection.ClaimedHopCount || last.Sequence != projection.TargetSequence ||
		last.MessageInstance != projection.TargetMessageInstance {
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

	if !ValidProjectionBindings(projection.ProjectionBinding, projection.Chain) {
		return fmt.Errorf("projection or hop binding does not match canonical verifier facts")
	}

	return nil
}

// validateProjectionMode correlates aggregate evaluation states with the requested history scope.
func validateProjectionMode(projection Projection) error {
	switch projection.Scope {
	case ScopeCurrent:
		return validateCurrentProjectionMode(projection)
	case scopeChain:
		return validateChainProjectionMode(projection)
	default:
		return fmt.Errorf("unsupported projection scope")
	}
}

// validateCurrentProjectionMode enforces the single-hop non-historical PASS envelope.
func validateCurrentProjectionMode(projection Projection) error {
	if len(projection.Chain) != 1 {
		return fmt.Errorf("current scope requires exactly one record")
	}

	if projection.HistoricalContent != StateNotEvaluated ||
		projection.HistoricalSignatures != StateNotEvaluated ||
		projection.CustodyStructure != custodyNotPresent {
		return fmt.Errorf("current scope requires non-evaluated history and absent custody")
	}

	if projection.DoNotModifyState != StateNotEvaluated || projection.DoNotExplodeState != StateNotEvaluated {
		return fmt.Errorf("current scope requires non-evaluated protection aggregates")
	}

	return nil
}

// validateChainProjectionMode enforces complete historical and aggregate evaluation.
func validateChainProjectionMode(projection Projection) error {
	if projection.HistoricalContent != stateComplete || projection.HistoricalSignatures != stateComplete {
		return fmt.Errorf("chain scope requires complete history aggregates")
	}

	if projection.CustodyStructure == StateNotEvaluated {
		return fmt.Errorf("chain scope requires evaluated custody structure")
	}

	if projection.DoNotModifyState == StateNotEvaluated || projection.DoNotExplodeState == StateNotEvaluated {
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
func summarizeCustodyTransitions(Chain []Hop) custodyTransitionSummary {
	summary := custodyTransitionSummary{
		lastTerminal: Chain[len(Chain)-1].CustodyTransition == CustodyTerminal,
	}

	for _, hop := range Chain {
		summary.hasNextDomain = summary.hasNextDomain || hop.CustodyTransition == CustodyNextDomain
		if hop.CustodyTransition == CustodyTerminal {
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
func validateCustodyStructure(projection Projection) error {
	if projection.Scope == ScopeCurrent {
		return nil
	}

	summary := summarizeCustodyTransitions(projection.Chain)

	if !summary.terminalPlacementValid() {
		return fmt.Errorf("terminal custody transition must be the final hop")
	}

	switch projection.CustodyStructure {
	case custodyNotPresent:
		if summary.hasNextDomain || summary.terminalCount > 0 {
			return fmt.Errorf("absent custody aggregate contains a next-domain transition")
		}
	case CustodyLinksEvaluated:
		if !summary.hasNextDomain || summary.terminalCount > 0 {
			return fmt.Errorf("evaluated custody links require a non-terminal next-domain transition")
		}
	case CustodyTerminalRequires:
		if !summary.lastTerminal {
			return fmt.Errorf("terminal custody aggregate does not match final hop")
		}
	default:
		return fmt.Errorf("unsupported custody aggregate")
	}

	return nil
}

// validateAggregateProtectionStates correlates chain requests with their aggregate evaluation states.
func validateAggregateProtectionStates(projection Projection) error {
	if projection.Scope == ScopeCurrent {
		return nil
	}

	modifyRequested := slices.ContainsFunc(projection.Chain, func(hop Hop) bool { return hop.DoNotModify })
	explodeRequested := slices.ContainsFunc(projection.Chain, func(hop Hop) bool { return hop.DoNotExplode })

	if (projection.DoNotModifyState == StateNotRequested) == modifyRequested {
		return fmt.Errorf("do-not-modify aggregate contradicts chain flags")
	}

	if (projection.DoNotExplodeState == StateNotRequested) == explodeRequested {
		return fmt.Errorf("do-not-explode aggregate contradicts chain flags")
	}

	return nil
}

// validateEnvironmentFacts validates Rspamd observations and returns the exact SMTP peer.
func validateEnvironmentFacts(facts map[string]pluginapi.DecisionFactView) (netip.Addr, error) {
	enums := []enumFactSpecification{
		{id: FactScanAction, allowed: RspamdScanActions},
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
	if err != nil || len(signals) > 32 || !SortedUniqueStrings(signals) || !allStringsAllowed(signals, allowedRspamdSignal) {
		return fmt.Errorf("invalid normalized Rspamd signals")
	}

	recipients, err := requireStrings(facts, "environment.rspamd.recipient_classes")
	if err != nil || len(recipients) > 16 || !SortedUniqueStrings(recipients) || !allStringsAllowed(recipients, allowedRecipientClass) {
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
func decodeVerifierHops(list pluginapi.DecisionRecordList) ([]Hop, error) {
	records := list.Records()
	if len(records) == 0 || len(records) > maximumHops {
		return nil, fmt.Errorf("chain must contain between one and %d records", maximumHops)
	}

	result := make([]Hop, 0, len(records))
	bindings := make(map[string]struct{}, len(records))

	for index, record := range records {
		hop, err := decodeVerifierHop(record)
		if err != nil {
			return nil, fmt.Errorf("chain record %d: %w", index, err)
		}

		expectedSequence := int64(index + 1)
		if hop.Sequence != expectedSequence {
			return nil, fmt.Errorf("chain record %d has a noncontiguous sequence", index)
		}

		bindingKey := string(hop.HopBinding)
		if _, exists := bindings[bindingKey]; exists {
			return nil, fmt.Errorf("chain record %d repeats a hop binding", index)
		}

		bindings[bindingKey] = struct{}{}

		result = append(result, hop)
	}

	if result[0].CustodyTransition != CustodyOrigin {
		return nil, fmt.Errorf("first chain record must be the origin")
	}

	for index := 1; index < len(result); index++ {
		if result[index].CustodyTransition == CustodyOrigin {
			return nil, fmt.Errorf("chain record %d repeats origin custody", index)
		}
	}

	return result, nil
}

// decodeVerifierHop validates one exact closed verifier record.
//
//nolint:funlen,gocyclo // Keeping the closed record decoder together makes field auditing explicit.
func decodeVerifierHop(record pluginapi.DecisionRecord) (Hop, error) {
	fields, err := indexRecordFields(record)
	if err != nil {
		return Hop{}, err
	}

	required := HopInputFields()
	if len(fields) != len(required) {
		return Hop{}, fmt.Errorf("record has unknown or missing fields")
	}

	for _, field := range required {
		if _, exists := fields[field.Name]; !exists {
			return Hop{}, fmt.Errorf("required field %s is missing", field.Name)
		}
	}

	Sequence, err := recordPositiveInteger(fields, FieldSequence)
	if err != nil {
		return Hop{}, err
	}

	instance, err := recordPositiveInteger(fields, FieldMessageInstance)
	if err != nil {
		return Hop{}, err
	}

	HopBinding, err := recordDigest(fields, FieldHopBinding)
	if err != nil {
		return Hop{}, err
	}

	domain, err := recordString(fields, "signer_domain")
	if err != nil || !CanonicalDomain(domain) {
		return Hop{}, fmt.Errorf("signer_domain is not canonical")
	}

	algorithms, err := recordStrings(fields, "signature_algorithms")
	if err != nil || len(algorithms) == 0 || len(algorithms) > 4 || !SortedUniqueStrings(algorithms) || !allStringsAllowed(algorithms, allowedSignatureAlgorithm) {
		return Hop{}, fmt.Errorf("signature_algorithms is invalid")
	}

	SignatureState, err := recordStringIn(fields, "signature_state", "pass")
	if err != nil {
		return Hop{}, err
	}

	custody, err := recordStringIn(fields, "custody_transition", CustodyOrigin, CustodyOrdinary, CustodyNextDomain, CustodyTerminal)
	if err != nil {
		return Hop{}, err
	}

	RecipeMode, err := recordStringIn(fields, "recipe_mode", "unchanged", "applied")
	if err != nil {
		return Hop{}, err
	}

	RecipeBodyMode, err := recordStringIn(fields, "recipe_body_mode", RecipeBodyAbsent, "steps", StateUnavailable)
	if err != nil {
		return Hop{}, err
	}

	RecipeDigest, err := recordDigest(fields, "recipe_digest")
	if err != nil {
		return Hop{}, err
	}

	changes, err := recordStrings(fields, "change_classes")
	if err != nil || len(changes) > 2 || !SortedUniqueStrings(changes) || !allStringsAllowed(changes, AllowedChangeClass) {
		return Hop{}, fmt.Errorf("change_classes is invalid")
	}

	headers, err := recordStrings(fields, "affected_headers")
	if err != nil || len(headers) > 128 || !SortedUniqueStrings(headers) || !allStringsAllowed(headers, canonicalHeaderName) {
		return Hop{}, fmt.Errorf("affected_headers is invalid")
	}

	historyHeader, err := recordStringIn(fields, "history_header_state", HistoryMatched, "mismatch", StateUnavailable, "unsupported")
	if err != nil {
		return Hop{}, err
	}

	historyBody, err := recordStringIn(fields, "history_body_state", HistoryMatched, "mismatch", StateUnavailable, "unsupported")
	if err != nil {
		return Hop{}, err
	}

	BodyAvailability, err := recordStringIn(fields, "body_availability", "known", StateUnavailable)
	if err != nil {
		return Hop{}, err
	}

	if (BodyAvailability == StateUnavailable) != (historyBody == StateUnavailable) {
		return Hop{}, fmt.Errorf("body availability does not match history body state")
	}

	ChangeCount, err := recordNonnegativeInteger(fields, "change_count")
	if err != nil || ChangeCount != int64(len(changes)) {
		return Hop{}, fmt.Errorf("change_count does not match change_classes")
	}

	headerCount, err := recordNonnegativeInteger(fields, "affected_header_count")
	if err != nil || headerCount != int64(len(headers)) {
		return Hop{}, fmt.Errorf("affected_header_count does not match affected_headers")
	}

	hasHeaders, err := recordBoolean(fields, "recipe_has_header_changes")
	if err != nil || hasHeaders != (len(headers) > 0) || hasHeaders != slices.Contains(changes, "header.rewrite") {
		return Hop{}, fmt.Errorf("recipe header projection is incoherent")
	}

	if slices.Contains(changes, "body.rewrite") != (RecipeBodyMode != RecipeBodyAbsent) {
		return Hop{}, fmt.Errorf("recipe body projection is incoherent")
	}

	if RecipeMode == "unchanged" && (len(changes) != 0 || len(headers) != 0 || RecipeBodyMode != RecipeBodyAbsent) {
		return Hop{}, fmt.Errorf("unchanged Recipe contains changes")
	}

	if RecipeMode == "applied" && len(changes) == 0 {
		return Hop{}, fmt.Errorf("applied Recipe contains no changes")
	}

	DoNotModify, err := recordBoolean(fields, "do_not_modify")
	if err != nil {
		return Hop{}, err
	}

	DoNotExplode, err := recordBoolean(fields, "do_not_explode")
	if err != nil {
		return Hop{}, err
	}

	Feedback, err := recordBoolean(fields, "feedback")
	if err != nil {
		return Hop{}, err
	}

	FeedHere, err := recordBoolean(fields, "feed_here")
	if err != nil {
		return Hop{}, err
	}

	Exploded, err := recordBoolean(fields, "exploded")
	if err != nil {
		return Hop{}, err
	}

	return Hop{
		SignerDomain: domain, SignatureAlgorithms: algorithms, HopBinding: HopBinding, RecipeDigest: RecipeDigest, ChangeClasses: changes,
		AffectedHeaders: headers, SignatureState: SignatureState, CustodyTransition: custody, RecipeMode: RecipeMode,
		RecipeBodyMode: RecipeBodyMode, HistoryHeaderState: historyHeader, HistoryBodyState: historyBody,
		BodyAvailability: BodyAvailability, Sequence: Sequence, MessageInstance: instance, ChangeCount: ChangeCount,
		AffectedHeaderCount: headerCount, DoNotModify: DoNotModify, DoNotExplode: DoNotExplode, Feedback: Feedback,
		FeedHere: FeedHere, Exploded: Exploded, RecipeHasHeaders: hasHeaders,
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
	if err != nil || address.Zone() != "" || address.String() != value || address.Is4In6() || address.IsUnspecified() ||
		address.IsMulticast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return netip.Addr{}, fmt.Errorf("smtp_client_ip must be a canonical unicast IPv4 or IPv6 address")
	}

	return address, nil
}

// CanonicalDomain validates an exact lower-case ASCII DNS name without a root dot.
//
//nolint:gocyclo // DNS label syntax is clearer as direct byte predicates.
func CanonicalDomain(value string) bool {
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

// SortedUniqueStrings enforces the v1 byte-lexical list canonicalization.
func SortedUniqueStrings(values []string) bool {
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

// AllowedChangeClass reports the conservative Recipe descriptor vocabulary.
func AllowedChangeClass(value string) bool {
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
