// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"net/netip"
	"slices"
)

const (
	contractMatched      = "matched"
	contractMissing      = "missing"
	contractPeerMismatch = "peer_mismatch"
	recipePermitted      = "permitted"
	recipeDenied         = "denied"
	recipeUncontracted   = "uncontracted"
)

// assessProjection derives deterministic reputation facts without making a Policy decision.
func assessProjection(config *assessmentConfig, projection verifierProjection) []hopAssessment {
	clientReputation := config.clientReputation(projection.clientIP)
	result := make([]hopAssessment, 0, len(projection.chain))

	for index, hop := range projection.chain {
		isTarget := hop.sequence == projection.targetSequence && hop.messageInstance == projection.targetMessageInstance
		assessment := hopAssessment{
			hop:                hop,
			domainReputation:   config.domainReputation(hop.signerDomain),
			clientIPReputation: clientReputation,
			assessmentComplete: true,
		}

		contract, exists := config.contracts[hop.signerDomain]
		assessment.contractState = assessContractState(contract, exists, projection.clientIP, isTarget)
		assessment.recipeAuthorization = assessRecipeAuthorization(contract, exists, hop.changeClasses)
		assessment.violations = projectionViolations(projection, assessment, index)
		assessment.acceptable = len(assessment.violations) == 0
		result = append(result, assessment)
	}

	return result
}

// domainReputation returns the exact configured classification or unknown.
func (c *assessmentConfig) domainReputation(domain string) string {
	if reputation, exists := c.domains[domain]; exists {
		return reputation
	}

	return reputationUnknown
}

// clientReputation applies deterministic longest-prefix classification.
func (c *assessmentConfig) clientReputation(address netip.Addr) string {
	for _, network := range c.networks {
		if network.prefix.Contains(address) {
			return network.reputation
		}
	}

	return reputationUnknown
}

// assessContractState binds one signer contract to the exact SMTP peer address.
func assessContractState(contract domainContract, exists bool, clientIP netip.Addr, enforcePeer bool) string {
	if !exists {
		return contractMissing
	}

	if !enforcePeer {
		return contractMatched
	}

	for _, prefix := range contract.allowedPeers {
		if prefix.Contains(clientIP) {
			return contractMatched
		}
	}

	return contractPeerMismatch
}

// assessRecipeAuthorization checks every conservative change class against one matched contract.
func assessRecipeAuthorization(contract domainContract, exists bool, changes []string) string {
	if !exists {
		return recipeUncontracted
	}

	for _, change := range changes {
		if _, allowed := contract.allowedChanges[change]; !allowed {
			return recipeDenied
		}
	}

	return recipePermitted
}

// projectionViolations returns a stable policy-facing explanation set for one hop.
//
//nolint:funlen,gocyclo // Each branch maps one independent closed assessment dimension.
func projectionViolations(projection verifierProjection, assessment hopAssessment, index int) []string {
	violations := make([]string, 0, 8)
	isTarget := assessment.hop.sequence == projection.targetSequence &&
		assessment.hop.messageInstance == projection.targetMessageInstance

	switch assessment.domainReputation {
	case reputationUnknown:
		violations = append(violations, "signer_reputation_unknown")
	case reputationBlocked:
		violations = append(violations, "signer_reputation_blocked")
	}

	if isTarget {
		switch assessment.clientIPReputation {
		case reputationUnknown:
			violations = append(violations, "smtp_peer_reputation_unknown")
		case reputationBlocked:
			violations = append(violations, "smtp_peer_reputation_blocked")
		}
	}

	switch assessment.contractState {
	case contractMissing:
		violations = append(violations, "contract_missing")
	case contractPeerMismatch:
		violations = append(violations, "contract_peer_mismatch")
	}

	if assessment.recipeAuthorization != recipePermitted {
		violations = append(violations, "recipe_not_authorized")
	}

	if isTarget && projection.authenticationState != "PASS" {
		violations = append(violations, "authentication_not_pass")
	}

	if isTarget && projection.disposition != verdictAccept && projection.disposition != verdictContinue {
		violations = append(violations, "upstream_nonpermittable")
	}

	if assessment.hop.custodyTransition == "terminal_next_domain" {
		violations = append(violations, "terminal_oob_required")
	}

	if assessment.hop.historyHeaderState != historyMatched || assessment.hop.historyBodyState != historyMatched {
		violations = append(violations, "history_not_matched")
	}

	if assessment.hop.bodyAvailability == stateUnavailable {
		violations = append(violations, "body_unavailable")
	}

	if index > 0 {
		previous := projection.chain[index-1]
		if previous.doNotModify && len(assessment.hop.changeClasses) > 0 {
			violations = append(violations, "do_not_modify_violated")
		}

		if previous.doNotExplode && assessment.hop.exploded {
			violations = append(violations, "do_not_explode_violated")
		}
	}

	slices.Sort(violations)

	return slices.Compact(violations)
}
