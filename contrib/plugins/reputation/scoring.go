package main

import "math"

type profileMass struct {
	RiskDiversity int     `json:"risk_diversity"`
	Name          string  `json:"name"`
	Risk          float64 `json:"risk"`
	Trust         float64 `json:"trust"`
	Samples       float64 `json:"samples"`
	Diversity     int     `json:"diversity"`
}

type profileScore struct {
	RiskDiversity int
	Risk          float64
	Trust         float64
	Confidence    float64
	Samples       float64
	Diversity     int
}

// scoreMass transforms one atomic, already-decayed mass snapshot without introducing new evidence.
func scoreMass(mass profileMass, cfg scoreConfig) profileScore {
	logOdds := math.Log((mass.Risk + cfg.Alpha) / (mass.Trust + cfg.Alpha))
	confidence := -math.Expm1(-(mass.Risk + mass.Trust) / cfg.Saturation)
	signed := math.Tanh(logOdds/cfg.Temperature) * confidence

	return profileScore{RiskDiversity: mass.RiskDiversity, Risk: math.Max(0, signed), Trust: math.Max(0, -signed), Confidence: confidence, Samples: mass.Samples, Diversity: mass.Diversity}
}
