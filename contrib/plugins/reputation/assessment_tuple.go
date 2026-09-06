package main

import "errors"

const (
	assessmentFresh       = "fresh"
	assessmentStale       = "stale"
	assessmentMissing     = "not_found"
	assessmentUnavailable = "unavailable"
	bandUnknown           = "unknown"
	bandTrusted           = "trusted"
	bandPositive          = "positive"
	bandNeutral           = "neutral"
	bandSuspicious        = "suspicious"
	bandBlocked           = "blocked"
	overrideNone          = "none"
)

var errAssessment = errors.New("invalid reputation assessment")

type assessmentTuple struct {
	Details  *assessmentDetails
	State    string
	Profile  string
	Band     string
	Override string
}

type assessmentDetails struct {
	Risk       float64
	Trust      float64
	Confidence float64
	Samples    float64
	Diversity  int
	AgeSeconds int64
}

// validate enforces the complete conditional tuple before any decision-visible record is published.
func (a assessmentTuple) validate() error {
	if !profileName(a.Profile) || !overrideBand(a.Override) || !learnedBand(a.Band) {
		return errAssessment
	}

	if err := a.validateEvidence(); err != nil {
		return err
	}

	if a.State == assessmentUnavailable {
		if a.Band != assessmentUnavailable || a.Override != overrideNone {
			return errAssessment
		}
	} else if a.Override != overrideNone {
		if a.Band != a.Override {
			return errAssessment
		}
	} else if a.State == assessmentMissing && a.Band != bandUnknown {
		return errAssessment
	}

	return nil
}

// validateEvidence enforces which states may contain measured numeric details.
func (a assessmentTuple) validateEvidence() error {
	switch a.State {
	case assessmentUnavailable, assessmentMissing:
		if a.Details != nil {
			return errAssessment
		}
	case assessmentFresh, assessmentStale:
		if a.Details == nil || a.Band == assessmentUnavailable || a.Details.validate() != nil {
			return errAssessment
		}
	default:
		return errAssessment
	}

	return nil
}

// validate rejects non-finite, out-of-range or contradictory measured details.
func (d assessmentDetails) validate() error {
	if !nonnegativeBound(d.Risk, 1) || !nonnegativeBound(d.Trust, 1) || !nonnegativeBound(d.Confidence, 1) ||
		!nonnegativeBound(d.Samples, 1e9) || d.Diversity < 0 || d.Diversity > 8 ||
		d.AgeSeconds < 0 || d.AgeSeconds > 31536000 || (d.Risk > 0 && d.Trust > 0) {
		return errAssessment
	}

	return nil
}

// profileName recognizes only compiled decay dimensions.
func profileName(value string) bool {
	return value == profileFast || value == profileOperational || value == profileBaseline
}

// overrideBand keeps operator authority restricted to its exact closed vocabulary.
func overrideBand(value string) bool {
	return value == overrideNone || value == bandTrusted || value == bandNeutral || value == bandBlocked
}

// learnedBand validates all decision-visible assessment bands, including unavailable.
func learnedBand(value string) bool {
	switch value {
	case bandUnknown, bandTrusted, bandPositive, bandNeutral, bandSuspicious, bandBlocked, assessmentUnavailable:
		return true
	}

	return false
}
