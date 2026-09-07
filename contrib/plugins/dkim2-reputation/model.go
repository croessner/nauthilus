// Copyright (C) 2026 Christian Roessner
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import projection "github.com/croessner/nauthilus/v4/contrib/plugins/internal/dkim2projection"

type verifierProjection = projection.Projection
type verifierHop = projection.Hop

type hopAssessment struct {
	hop                 verifierHop
	violations          []string
	domainReputation    string
	clientIPReputation  string
	contractState       string
	recipeAuthorization string
	assessmentComplete  bool
	acceptable          bool
}
