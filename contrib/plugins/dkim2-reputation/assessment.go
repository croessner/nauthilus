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
	clientReputation := config.clientReputation(projection.ClientIP)
	result := make([]hopAssessment, 0, len(projection.Chain))

	for index, hop := range projection.Chain {
		isTarget := hop.Sequence == projection.TargetSequence && hop.MessageInstance == projection.TargetMessageInstance
		assessment := hopAssessment{
			hop:                hop,
			domainReputation:   config.domainReputation(hop.SignerDomain),
			clientIPReputation: clientReputation,
			assessmentComplete: true,
		}

		contract, exists := config.contracts[hop.SignerDomain]
		assessment.contractState = assessContractState(contract, exists, projection.ClientIP, isTarget)
		assessment.recipeAuthorization = assessRecipeAuthorization(contract, exists, hop.ChangeClasses)
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
func assessContractState(contract domainContract, exists bool, ClientIP netip.Addr, enforcePeer bool) string {
	if !exists {
		return contractMissing
	}

	if !enforcePeer {
		return contractMatched
	}

	for _, prefix := range contract.allowedPeers {
		if prefix.Contains(ClientIP) {
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
	isTarget := assessment.hop.Sequence == projection.TargetSequence &&
		assessment.hop.MessageInstance == projection.TargetMessageInstance

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

	if isTarget && projection.AuthenticationState != "PASS" {
		violations = append(violations, "authentication_not_pass")
	}

	if isTarget && projection.Disposition != verdictAccept && projection.Disposition != verdictContinue {
		violations = append(violations, "upstream_nonpermittable")
	}

	if assessment.hop.CustodyTransition == "terminal_next_domain" {
		violations = append(violations, "terminal_oob_required")
	}

	if assessment.hop.HistoryHeaderState != historyMatched || assessment.hop.HistoryBodyState != historyMatched {
		violations = append(violations, "history_not_matched")
	}

	if assessment.hop.BodyAvailability == stateUnavailable {
		violations = append(violations, "body_unavailable")
	}

	if index > 0 {
		previous := projection.Chain[index-1]
		if previous.DoNotModify && len(assessment.hop.ChangeClasses) > 0 {
			violations = append(violations, "do_not_modify_violated")
		}

		if previous.DoNotExplode && assessment.hop.Exploded {
			violations = append(violations, "do_not_explode_violated")
		}
	}

	slices.Sort(violations)

	return slices.Compact(violations)
}
