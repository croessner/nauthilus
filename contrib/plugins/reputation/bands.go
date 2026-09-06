package main

import "time"

type evidenceThreshold struct {
	Score      float64 `mapstructure:"score"`
	Confidence float64 `mapstructure:"confidence"`
	Samples    float64 `mapstructure:"samples"`
}

type bandConfig struct {
	AuthoritativeRiskMaxAge   string            `mapstructure:"authoritative_risk_max_age"`
	SevereRiskMaxAge          string            `mapstructure:"severe_risk_max_age"`
	Trusted                   evidenceThreshold `mapstructure:"trusted"`
	Positive                  evidenceThreshold `mapstructure:"positive"`
	SuspiciousFast            evidenceThreshold `mapstructure:"suspicious_fast"`
	SuspiciousOperational     evidenceThreshold `mapstructure:"suspicious_operational"`
	Blocked                   evidenceThreshold `mapstructure:"blocked"`
	MinimumConfidence         float64           `mapstructure:"minimum_confidence"`
	MinimumSamples            float64           `mapstructure:"minimum_samples"`
	DiversityMassFloor        float64           `mapstructure:"diversity_mass_floor"`
	SevereRiskScore           float64           `mapstructure:"severe_risk_score"`
	MinimumBlockSourceClasses int               `mapstructure:"minimum_block_source_classes"`
	LearnedBlocked            bool              `mapstructure:"learned_blocked"`
}

// validateBands compiles read-time thresholds independently of immutable ingestion semantics.
func (c *configuration) validateBands() error {
	b := c.raw.Bands
	if err := b.validateEvidence(); err != nil {
		return err
	}

	for _, threshold := range []evidenceThreshold{b.Trusted, b.Positive, b.SuspiciousFast, b.SuspiciousOperational, b.Blocked} {
		if !positiveBound(threshold.Score, 1) || !positiveBound(threshold.Confidence, 1) || !positiveBound(threshold.Samples, 1e9) {
			return errConfiguration
		}
	}

	if b.Trusted.Score < b.Positive.Score || b.Blocked.Score < b.SuspiciousOperational.Score {
		return errConfiguration
	}

	for _, age := range []string{b.AuthoritativeRiskMaxAge, b.SevereRiskMaxAge} {
		if _, err := durationBound(age, maximumRetention, false); err != nil {
			return err
		}
	}

	return nil
}

// matches requires score and independent evidence together at every promotion threshold.
func (t evidenceThreshold) matches(score float64, profile profileScore) bool {
	return score >= t.Score && profile.Confidence >= t.Confidence && profile.Samples >= t.Samples
}

// learnedAssessmentBand applies risk precedence and configuration-owned evidence gates without making an enforcement decision.
func learnedAssessmentBand(fast, operational profileScore, authoritative, severe bool, cfg bandConfig) string {
	if cfg.LearnedBlocked && cfg.Blocked.matches(operational.Risk, operational) &&
		(authoritative || operational.RiskDiversity >= cfg.MinimumBlockSourceClasses) {
		return bandBlocked
	}

	if cfg.SuspiciousFast.matches(fast.Risk, fast) || cfg.SuspiciousOperational.matches(operational.Risk, operational) {
		return bandSuspicious
	}

	if !severe && cfg.Trusted.matches(operational.Trust, operational) {
		return bandTrusted
	}

	if cfg.Positive.matches(operational.Trust, operational) {
		return bandPositive
	}

	if operational.Confidence >= cfg.MinimumConfidence && operational.Samples >= cfg.MinimumSamples {
		return bandNeutral
	}

	return bandUnknown
}

// riskEvidenceRecent uses only the atomic Redis snapshot clock and a previously compiled duration.
func riskEvidenceRecent(now, observed float64, maximum string) bool {
	duration, err := time.ParseDuration(maximum)
	return err == nil && observed > 0 && observed <= now && now-observed <= duration.Seconds()
}

// validateEvidence requires bounded independent evidence and source-diversity thresholds.
func (b bandConfig) validateEvidence() error {
	if !positiveBound(b.MinimumConfidence, 1) || !positiveBound(b.MinimumSamples, 1e9) ||
		!positiveBound(b.DiversityMassFloor, 1e6) || !positiveBound(b.SevereRiskScore, 1) ||
		b.MinimumBlockSourceClasses < 2 || b.MinimumBlockSourceClasses > 8 {
		return errConfiguration
	}

	return nil
}
