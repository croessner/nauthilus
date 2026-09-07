// Copyright (C) 2026 Christian Roessner
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import projection "github.com/croessner/nauthilus/v4/contrib/plugins/internal/dkim2projection"

// Projection helpers delegate to the single shared semantic validator.
var (
	allowedChangeClass              = projection.AllowedChangeClass
	calculateBoundHopBinding        = projection.CalculateBoundHopBinding
	calculateHopContentDigest       = projection.CalculateHopContentDigest
	calculateProjectionBinding      = projection.CalculateProjectionBinding
	calculateRecipeDescriptorDigest = projection.CalculateRecipeDescriptorDigest
	canonicalDomain                 = projection.CanonicalDomain
	decodeVerifierProjection        = projection.Decode
	sortedUniqueStrings             = projection.SortedUniqueStrings
	validProjectionBindings         = projection.ValidProjectionBindings
	exactTarget                     = projection.ExactTarget
	rspamdScanActions               = projection.RspamdScanActions
)

const (
	custodyLinksEvaluated    = projection.CustodyLinksEvaluated
	custodyNextDomain        = projection.CustodyNextDomain
	custodyOrdinary          = projection.CustodyOrdinary
	custodyOrigin            = projection.CustodyOrigin
	custodyTerminal          = projection.CustodyTerminal
	custodyTerminalRequires  = projection.CustodyTerminalRequires
	draftVersion             = projection.DraftVersion
	factCustodyStructure     = projection.FactCustodyStructure
	factDoNotExplodeState    = projection.FactDoNotExplodeState
	factDoNotModifyState     = projection.FactDoNotModifyState
	factHistoricalContent    = projection.FactHistoricalContent
	factHistoricalSignatures = projection.FactHistoricalSignatures
	factProjectionSchema     = projection.FactProjectionSchema
	factScanAction           = projection.FactScanAction
	factScope                = projection.FactScope
	fieldHopBinding          = projection.FieldHopBinding
	fieldMessageInstance     = projection.FieldMessageInstance
	fieldSequence            = projection.FieldSequence
	historyMatched           = projection.HistoryMatched
	projectionSchema         = projection.ProjectionSchema
	recipeBodyAbsent         = projection.RecipeBodyAbsent
	scopeCurrent             = projection.ScopeCurrent
	stateIndeterminate       = projection.StateIndeterminate
	stateNotEvaluated        = projection.StateNotEvaluated
	stateNotRequested        = projection.StateNotRequested
	stateUnavailable         = projection.StateUnavailable
	verdictAccept            = projection.VerdictAccept
	verdictContinue          = projection.VerdictContinue
)
