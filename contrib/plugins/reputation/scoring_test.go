package main

import (
	"math"
	"testing"
)

// TestScoreGoldenVectors freezes the signed Bayesian-shaped transform independently of storage.
func TestScoreGoldenVectors(t *testing.T) {
	cases := []struct{ risk, trust, confidence, riskScore, trustScore float64 }{
		{0, 0, 0, 0, 0},
		{20, 20, 0.8646647167633873, 0, 0},
		{40, 0, 0.8646647167633873, 0.8353229200862778, 0},
		{0, 40, 0.8646647167633873, 0, 0.8353229200862778},
	}
	for _, tt := range cases {
		actual := scoreMass(profileMass{Risk: tt.risk, Trust: tt.trust}, scoreConfig{Alpha: 2, Saturation: 20, Temperature: 1.5})
		for _, pair := range [][2]float64{{actual.Confidence, tt.confidence}, {actual.Risk, tt.riskScore}, {actual.Trust, tt.trustScore}} {
			if math.Abs(pair[0]-pair[1]) > 1e-12 {
				t.Fatalf("score mismatch: got %.16f expected %.16f", pair[0], pair[1])
			}
		}
	}
}

// TestAssessmentTupleRejectsInventedEvidence keeps unavailable and missing state distinct from measured neutrality.
func TestAssessmentTupleRejectsInventedEvidence(t *testing.T) {
	cases := []struct {
		name  string
		tuple assessmentTuple
		valid bool
	}{
		{"missing", assessmentTuple{State: "not_found", Profile: "operational", Band: "unknown", Override: "none"}, true},
		{"failure", assessmentTuple{State: "unavailable", Profile: "operational", Band: "unavailable", Override: "none"}, true},
		{"missing override", assessmentTuple{State: "not_found", Profile: "operational", Band: "blocked", Override: "blocked"}, true},
		{"invented neutral", assessmentTuple{State: "not_found", Profile: "operational", Band: "neutral", Override: "none"}, false},
		{"failure override", assessmentTuple{State: "unavailable", Profile: "operational", Band: "trusted", Override: "trusted"}, false},
		{"missing numbers", assessmentTuple{State: "fresh", Profile: "operational", Band: "unknown", Override: "none"}, false},
		{"invented numbers", assessmentTuple{State: "not_found", Profile: "operational", Band: "unknown", Override: "none", Details: &assessmentDetails{}}, false},
		{"negative age", assessmentTuple{State: "fresh", Profile: "operational", Band: "neutral", Override: "none", Details: &assessmentDetails{AgeSeconds: -1}}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if (tt.tuple.validate() == nil) != tt.valid {
				t.Fatal("invalid tuple contract")
			}
		})
	}
}

// TestBandRequiresCurrentDiversityAndProtectsAgainstSevereRisk bounds learned blocking and trust promotion.
func TestBandRequiresCurrentDiversityAndProtectsAgainstSevereRisk(t *testing.T) {
	cfg := testConfig(t)
	policy := cfg.raw.Bands
	policy.LearnedBlocked = true

	strongRisk := profileScore{Risk: 0.9, Confidence: 0.9, Samples: 100, RiskDiversity: 1}
	if learnedAssessmentBand(strongRisk, strongRisk, false, false, policy) != bandSuspicious {
		t.Fatal("single source created learned block")
	}

	strongRisk.RiskDiversity = 2
	if learnedAssessmentBand(strongRisk, strongRisk, false, false, policy) != bandBlocked {
		t.Fatal("current independent diversity did not satisfy block")
	}

	strongRisk.RiskDiversity = 1
	if learnedAssessmentBand(strongRisk, strongRisk, true, false, policy) != bandBlocked {
		t.Fatal("authoritative risk did not satisfy configured block")
	}

	policy.LearnedBlocked = false
	if learnedAssessmentBand(strongRisk, strongRisk, true, false, policy) == bandBlocked {
		t.Fatal("disabled learned blocking activated")
	}

	trust := profileScore{Trust: 0.9, Confidence: 0.9, Samples: 100}
	if learnedAssessmentBand(profileScore{}, trust, false, false, policy) != bandTrusted {
		t.Fatal("qualified trust was not recognized")
	}

	if learnedAssessmentBand(profileScore{}, trust, false, true, policy) == bandTrusted {
		t.Fatal("recent severe risk allowed full trust")
	}
}

// TestBandGoldenVectors keeps every learned band deterministic under the explicit operator calibration.
func TestBandGoldenVectors(t *testing.T) {
	policy := testConfig(t).raw.Bands

	cases := []struct {
		name              string
		fast, operational profileScore
		band              string
	}{
		{name: "empty", band: bandUnknown},
		{name: "balanced", operational: profileScore{Confidence: 0.3, Samples: 4}, band: bandNeutral},
		{name: "positive", operational: profileScore{Trust: 0.4, Confidence: 0.5, Samples: 10}, band: bandPositive},
		{name: "trusted", operational: profileScore{Trust: 0.7, Confidence: 0.8, Samples: 30}, band: bandTrusted},
		{name: "fast risk", fast: profileScore{Risk: 0.7, Confidence: 0.8, Samples: 10}, band: bandSuspicious},
		{name: "operational risk", operational: profileScore{Risk: 0.65, Confidence: 0.8, Samples: 10}, band: bandSuspicious},
		{name: "insufficient samples", operational: profileScore{Trust: 0.9, Confidence: 0.9, Samples: 1}, band: bandUnknown},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if learnedAssessmentBand(tt.fast, tt.operational, false, false, policy) != tt.band {
				t.Fatal("band differs from calibrated vector")
			}
		})
	}
}
