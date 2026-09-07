package reputationview

import (
	"errors"
	"math"
)

// Assessment states, bands and override values form a closed common vocabulary.
const (
	Fresh       = "fresh"
	Stale       = "stale"
	NotFound    = "not_found"
	Unavailable = "unavailable"
	Unknown     = "unknown"
	Trusted     = "trusted"
	Positive    = "positive"
	Neutral     = "neutral"
	Suspicious  = "suspicious"
	Blocked     = "blocked"
	NoOverride  = "none"
)

// ErrAssessment rejects malformed or contradictory common assessment tuples.
var ErrAssessment = errors.New("invalid reputation assessment")

// Tuple is the closed common assessment contract shared by producers and composers.
type Tuple struct {
	Details  *Details
	State    string
	Profile  string
	Band     string
	Override string
}

// Details contains measured evidence and is absent for missing or unavailable state.
type Details struct {
	Risk       float64
	Trust      float64
	Confidence float64
	Samples    float64
	Diversity  int
	AgeSeconds int64
}

// Validate enforces the complete conditional tuple before any decision-visible record is published.
func (a Tuple) Validate() error {
	if !ValidProfile(a.Profile) || !ValidOverride(a.Override) || !ValidBand(a.Band) {
		return ErrAssessment
	}

	if err := a.validateEvidence(); err != nil {
		return err
	}

	if a.State == Unavailable {
		if a.Band != Unavailable || a.Override != NoOverride {
			return ErrAssessment
		}
	} else if a.Override != NoOverride {
		if a.Band != a.Override {
			return ErrAssessment
		}
	} else if a.State == NotFound && a.Band != Unknown {
		return ErrAssessment
	}

	return nil
}

// validateEvidence enforces which states may contain measured numeric details.
func (a Tuple) validateEvidence() error {
	switch a.State {
	case Unavailable, NotFound:
		if a.Details != nil {
			return ErrAssessment
		}
	case Fresh, Stale:
		if a.Details == nil || a.Band == Unavailable || a.Details.validate() != nil {
			return ErrAssessment
		}
	default:
		return ErrAssessment
	}

	return nil
}

// validate rejects non-finite, out-of-range or contradictory measured details.
func (d Details) validate() error {
	if !nonnegativeBound(d.Risk, 1) || !nonnegativeBound(d.Trust, 1) || !nonnegativeBound(d.Confidence, 1) ||
		!nonnegativeBound(d.Samples, 1e9) || d.Diversity < 0 || d.Diversity > 8 ||
		d.AgeSeconds < 0 || d.AgeSeconds > 31536000 || (d.Risk > 0 && d.Trust > 0) {
		return ErrAssessment
	}

	return nil
}

// ValidProfile recognizes only compiled decay dimensions.
func ValidProfile(value string) bool {
	return value == "fast" || value == "operational" || value == "baseline"
}

// ValidOverride keeps operator authority restricted to its exact closed vocabulary.
func ValidOverride(value string) bool {
	return value == NoOverride || value == Trusted || value == Neutral || value == Blocked
}

// ValidBand validates all decision-visible assessment bands, including unavailable.
func ValidBand(value string) bool {
	switch value {
	case Unknown, Trusted, Positive, Neutral, Suspicious, Blocked, Unavailable:
		return true
	}

	return false
}

// nonnegativeBound rejects non-finite values outside the closed tuple range.
func nonnegativeBound(value, maximum float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= maximum
}
