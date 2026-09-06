package main

import "math"

// mergeAssessments combines required successful slots conservatively without summing any evidence.
func mergeAssessments(left, right assessmentTuple) assessmentTuple {
	if left.State == assessmentUnavailable || right.State == assessmentUnavailable {
		return emptyAssessment(assessmentUnavailable, left.Profile)
	}

	override := strongerOverride(left.Override, right.Override)

	result := left
	switch {
	case left.State == assessmentMissing:
		result = right
	case right.State == assessmentMissing:
	case left.Details != nil && right.Details != nil:
		a, b := left.Details, right.Details
		result.Details = &assessmentDetails{Risk: math.Max(a.Risk, b.Risk), Trust: math.Min(a.Trust, b.Trust), Confidence: math.Min(a.Confidence, b.Confidence),
			Samples: math.Min(a.Samples, b.Samples), Diversity: min(a.Diversity, b.Diversity), AgeSeconds: max(a.AgeSeconds, b.AgeSeconds)}
		result.Band = conservativeBand(left.Band, right.Band)
	}

	result.Override = override
	if override != overrideNone {
		result.Band = override
	}

	return result
}

// strongerOverride implements the exact operator precedence across independently read tag versions.
func strongerOverride(left, right string) string {
	for _, value := range []string{bandBlocked, bandTrusted, bandNeutral} {
		if left == value || right == value {
			return value
		}
	}

	return overrideNone
}

// conservativeBand keeps the less trusting result while retaining risk from either history.
func conservativeBand(left, right string) string {
	for _, band := range []string{assessmentUnavailable, bandBlocked, bandSuspicious, bandUnknown, bandNeutral, bandPositive, bandTrusted} {
		if left == band || right == band {
			return band
		}
	}

	return assessmentUnavailable
}
