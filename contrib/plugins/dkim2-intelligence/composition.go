package main

import (
	projection "github.com/croessner/nauthilus/v4/contrib/plugins/internal/dkim2projection"
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"slices"
)

type composition struct {
	chain []pluginapi.DecisionRecord
	peer  pluginapi.DecisionRecord
}

// compose builds both complete immutable views before allowing the provider to emit either one.
func (c *configuration) compose(source projection.Projection, subjects correlatedSubjects, geo geographicEvidence) (composition, error) {
	if len(source.Chain) < 1 || len(source.Chain) > maximumChainRecords || len(source.Chain) != len(subjects.signers) {
		return composition{}, errCorrelation
	}

	result := composition{chain: make([]pluginapi.DecisionRecord, 0, len(source.Chain))}
	targetContract := identityResult{valueUnavailable, valueNone}
	size := 0

	for index, hop := range source.Chain {
		target := hop.Sequence == source.TargetSequence && hop.MessageInstance == source.TargetMessageInstance

		identity := c.matchIdentity(hop.SignerDomain, target, source.ClientIP, geo.asn, geo.hasASN)
		if target {
			targetContract = identity
		}

		builder := hopRecordBuilder(hop, target, identity)
		builder.tuple(valueSigner, subjects.signers[index])
		builder.strings(valueViolationClasses, compositionViolations(source, index, subjects, identity))

		record, err := builder.record(chainFields(), maximumChainBytes)
		if err != nil {
			return composition{}, err
		}

		size += composedRecordBytes(record)
		if size > maximumChainBytes {
			return composition{}, errCorrelation
		}

		result.chain = append(result.chain, record)
	}

	builder := peerRecordBuilder(c.raw.DecisionProfile, subjects.peers, geo, targetContract)

	peer, err := builder.record(peerFields(), maximumPeerBytes)
	if err != nil {
		return composition{}, err
	}

	result.peer = peer

	return result, nil
}

// hopRecordBuilder projects only the admitted privacy-minimized semantic fields and exact hop binding.
func hopRecordBuilder(hop projection.Hop, target bool, identity identityResult) *recordBuilder {
	b := newRecordBuilder()
	b.integer(valueSequence, hop.Sequence)
	b.integer(valueMessageInstance, hop.MessageInstance)
	b.add(valueHopBinding, pluginapi.DecisionValueInput{Bytes: hop.HopBinding})
	b.boolean(valueIsTarget, target)
	b.text(valueSignerDomain, hop.SignerDomain)
	b.text(valueSignatureState, hop.SignatureState)
	b.text(valueCustodyTransition, hop.CustodyTransition)
	b.boolean(valueDoNotModify, hop.DoNotModify)
	b.boolean(valueDoNotExplode, hop.DoNotExplode)
	b.boolean(valueFeedback, hop.Feedback)
	b.boolean(valueFeedHere, hop.FeedHere)
	b.boolean(valueExploded, hop.Exploded)
	b.text(valueRecipeMode, hop.RecipeMode)
	b.text(valueRecipeBodyMode, hop.RecipeBodyMode)
	b.strings(valueChangeClasses, hop.ChangeClasses)
	b.strings(valueAffectedHeaders, hop.AffectedHeaders)
	b.integer(valueChangeCount, hop.ChangeCount)
	b.integer(valueAffectedHeaderCount, hop.AffectedHeaderCount)
	b.text(valueHistoryHeaderState, hop.HistoryHeaderState)
	b.text(valueHistoryBodyState, hop.HistoryBodyState)
	b.text(valueBodyAvailability, hop.BodyAvailability)
	b.text(valueIdentityContractState, identity.state)
	b.text(valueIdentityContractStrength, identity.strength)

	return b
}

// peerRecordBuilder retains each subject tuple and includes geographic detail only for evaluated evidence.
func peerRecordBuilder(profile string, peers map[string]view.Tuple, geo geographicEvidence, identity identityResult) *recordBuilder {
	b := newRecordBuilder()
	b.text(valueReputationProfile, profile)

	for _, role := range []string{valueIP, valueNetwork, valueAsn} {
		b.tuple(role, peers[role])
	}

	b.text(valueGeoipState, geo.state)

	if geo.state == valueFresh || geo.state == valueStale {
		b.integer(valueGeoipAgeSeconds, geo.age)

		if geo.country != "" {
			b.text(valueCountryIso, geo.country)
		}

		if geo.hasASN {
			b.integer(valueAsn, geo.asn)
		}

		if geo.org != "" {
			b.text(valueAsnOrg, geo.org)
		}

		if geo.prefix != "" {
			b.text(valueAsnPrefix, geo.prefix)
		}
	}

	b.text(valueTargetContractState, identity.state)
	b.text(valueTargetContractStrength, identity.strength)

	return b
}

// compositionViolations reports established semantic conflicts without deciding Recipe authorization or Policy outcomes.
func compositionViolations(source projection.Projection, index int, subjects correlatedSubjects, identity identityResult) []string {
	hop := source.Chain[index]
	target := hop.Sequence == source.TargetSequence && hop.MessageInstance == source.TargetMessageInstance
	flags := map[string]bool{
		"body_unavailable":    hop.BodyAvailability == valueUnavailable,
		"history_not_matched": hop.HistoryHeaderState != valueMatched || hop.HistoryBodyState != valueMatched,
		"contract_missing":    identity.state == valueMissing, "contract_mismatch": identity.state == valueMismatch,
		"identity_unavailable":    identity.state == valueUnavailable,
		"authentication_not_pass": target && source.AuthenticationState != "PASS",
		"upstream_nonpermittable": target && source.Disposition != "accept" && source.Disposition != "continue",
	}
	applyPriorHopViolations(flags, source.Chain, index)
	tuples := []view.Tuple{subjects.signers[index]}

	if target {
		for _, kind := range []string{valueIP, valueNetwork, valueAsn} {
			tuples = append(tuples, subjects.peers[kind])
		}
	}

	for _, tuple := range tuples {
		applyReputationViolations(flags, tuple)
	}

	result := make([]string, 0, len(flags))
	for name, active := range flags {
		if active {
			result = append(result, name)
		}
	}

	slices.Sort(result)

	return result
}

// composedRecordBytes conservatively counts the same bounded leaf payloads across the complete chain.
func composedRecordBytes(record pluginapi.DecisionRecord) int {
	size := 0
	for _, field := range record.Fields() {
		size += len(field.Name()) + 16 + composedValueBytes(field.Value().Value())
	}

	return size
}

// composedValueBytes counts scalar and string-list payloads without depending on JSON escaping or field order.
func composedValueBytes(value pluginapi.DecisionValue) int {
	switch value.Kind() {
	case pluginapi.DecisionValueKindString:
		text, _ := value.StringValue()
		return len(text)
	case pluginapi.DecisionValueKindBytes:
		bytes, _ := value.Bytes()
		return len(bytes)
	case pluginapi.DecisionValueKindStrings:
		values, _ := value.Strings()

		count := 0
		for _, text := range values {
			count += len(text) + 8
		}

		return count
	default:
		return 8
	}
}

// applyPriorHopViolations compares protection flags only with the immediately preceding hop.
func applyPriorHopViolations(flags map[string]bool, chain []projection.Hop, index int) {
	if index == 0 {
		return
	}

	previous, hop := chain[index-1], chain[index]
	flags["do_not_modify_violated"] = previous.DoNotModify && len(hop.ChangeClasses) > 0
	flags["do_not_explode_violated"] = previous.DoNotExplode && hop.Exploded
}

// applyReputationViolations accumulates independent blocked and unavailable evidence without a Policy decision.
func applyReputationViolations(flags map[string]bool, tuple view.Tuple) {
	flags[valueReputationBlocked] = flags[valueReputationBlocked] || tuple.Band == view.Blocked
	flags[valueReputationUnavailable] = flags[valueReputationUnavailable] || tuple.State == view.Unavailable
}
