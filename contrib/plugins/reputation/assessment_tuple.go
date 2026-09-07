package main

import view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"

const (
	assessmentFresh       = view.Fresh
	assessmentStale       = view.Stale
	assessmentMissing     = view.NotFound
	assessmentUnavailable = view.Unavailable
	bandUnknown           = view.Unknown
	bandTrusted           = view.Trusted
	bandPositive          = view.Positive
	bandNeutral           = view.Neutral
	bandSuspicious        = view.Suspicious
	bandBlocked           = view.Blocked
	overrideNone          = view.NoOverride
)

var errAssessment = view.ErrAssessment

type assessmentTuple view.Tuple
type assessmentDetails = view.Details

// validate delegates the common conditional tuple contract to its single owner.
func (a assessmentTuple) validate() error { return view.Tuple(a).Validate() }

// profileName recognizes the common compiled decay dimensions.
func profileName(value string) bool { return view.ValidProfile(value) }

// overrideBand recognizes only the common explicit operator override vocabulary.
func overrideBand(value string) bool { return view.ValidOverride(value) }
