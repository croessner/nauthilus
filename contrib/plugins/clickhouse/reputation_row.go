// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// maxReputationAssessments bounds the per-row projection of assessment records.
const maxReputationAssessments = 64

// reputationAssessmentRow is one named tuple of the reputation_assessments Array(Tuple(...)) column. Measured fields
// are nil for not_found and unavailable assessments, so ClickHouse stores NULL instead of an invented zero.
type reputationAssessmentRow struct {
	RiskScore       *float64 `json:"risk_score"`
	TrustScore      *float64 `json:"trust_score"`
	Confidence      *float64 `json:"confidence"`
	Samples         *float64 `json:"samples"`
	SourceDiversity *int64   `json:"source_diversity"`
	AgeSeconds      *int64   `json:"age_seconds"`
	Fact            string   `json:"fact"`
	Role            string   `json:"role"`
	Kind            string   `json:"kind"`
	State           string   `json:"state"`
	Profile         string   `json:"profile"`
	Band            string   `json:"band"`
	Override        string   `json:"override"`
}

// applyReputationAssessments projects every record fact that decodes as reputation assessments, one tuple per
// record, without reducing profiles or subjects to one score.
func applyReputationAssessments(row *clickHouseRow, facts []pluginapi.PolicyFact, trimmed bool) {
	row.ReputationAssessments = []reputationAssessmentRow{}
	row.ReputationTruncated = trimmed

	for _, fact := range facts {
		records, ok := fact.Value.(pluginapi.DecisionRecordList)
		if !ok {
			continue
		}

		for _, record := range records.Records() {
			assessment, err := view.DecodeSubjectRecord(record)
			if err != nil {
				break
			}

			if len(row.ReputationAssessments) >= maxReputationAssessments {
				row.ReputationTruncated = true

				return
			}

			row.ReputationAssessments = append(row.ReputationAssessments, newReputationAssessmentRow(fact.Attribute, assessment))
		}
	}
}

// newReputationAssessmentRow maps one decoded assessment onto the named tuple.
func newReputationAssessmentRow(fact string, assessment view.SubjectAssessment) reputationAssessmentRow {
	tuple := assessment.Tuple
	output := reputationAssessmentRow{
		Fact: fact, Role: assessment.Role, Kind: assessment.Kind, State: tuple.State,
		Profile: tuple.Profile, Band: tuple.Band, Override: tuple.Override,
	}

	if details := tuple.Details; details != nil {
		diversity := int64(details.Diversity)
		output.RiskScore = &details.Risk
		output.TrustScore = &details.Trust
		output.Confidence = &details.Confidence
		output.Samples = &details.Samples
		output.SourceDiversity = &diversity
		output.AgeSeconds = &details.AgeSeconds
	}

	return output
}
