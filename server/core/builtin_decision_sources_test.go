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

package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v4/pluginapi/v1/exchange"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
)

// TestTriggeredBuiltinControlsPublishDecisionSources pins that a triggered RBL threshold or brute-force bucket
// publishes the standard exchange feature marker, so native analytics plugins report it in decision_sources.
func TestTriggeredBuiltinControlsPublishDecisionSources(t *testing.T) {
	tests := []struct {
		name     string
		controls []string
		want     []string
	}{
		{name: "rbl", controls: []string{definitions.ControlRBL}, want: []string{exchange.FeatureRBL}},
		{name: "brute force", controls: []string{definitions.ControlBruteForce}, want: []string{exchange.FeatureBruteForce}},
		{name: "both in exchange order", controls: []string{definitions.ControlBruteForce, definitions.ControlRBL},
			want: []string{exchange.FeatureRBL, exchange.FeatureBruteForce}},
		{name: "other controls publish no source", controls: []string{definitions.ControlTLSEncryption, definitions.ControlRelayDomains}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &AuthState{}
			auth.Runtime.Context = lualib.NewContext()

			for _, control := range test.controls {
				auth.updateLuaContext(control)
			}

			got := exchange.NewSnapshotFromValues(auth.Runtime.Context.Snapshot(), nil).DecisionSources()
			if !slices.Equal(got, test.want) {
				t.Fatalf("decision sources = %#v, want %#v", got, test.want)
			}
		})
	}
}

// rblDecisionSourceTestService returns a fixed RBL policy fact and error.
type rblDecisionSourceTestService struct {
	err  error
	fact RBLPolicyFact
}

// Score returns the fixed score.
func (s rblDecisionSourceTestService) Score(*gin.Context, *StateView) (int, error) {
	return s.fact.Score, s.err
}

// ScoreWithFacts returns the fixed fact.
func (s rblDecisionSourceTestService) ScoreWithFacts(*gin.Context, *StateView) (RBLPolicyFact, error) {
	return s.fact, s.err
}

// TestRBLEvaluationPublishesDecisionSourceOnlyAtThreshold pins that the RBL marker follows the threshold gate while
// matched lists stay visible below the threshold and on lookup errors.
func TestRBLEvaluationPublishesDecisionSourceOnlyAtThreshold(t *testing.T) {
	matched := []string{"zen.example.test", "bl.example.test"}

	tests := []struct {
		err         error
		name        string
		score       int
		wantMarker  bool
		wantMatched bool
	}{
		{name: "threshold reached", score: 10, wantMarker: true, wantMatched: true},
		{name: "below threshold", score: 5, wantMatched: true},
		{name: "lookup error", score: 10, err: errors.New("dns failure"), wantMatched: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &AuthState{deps: AuthDeps{
				Cfg: &config.FileSettings{RBLs: &config.RBLSection{Threshold: 10}},
				HostServices: AuthnHostServices{rbl: rblDecisionSourceTestService{err: test.err,
					fact: RBLPolicyFact{Score: test.score, MatchedLists: matched, MatchedCount: len(matched)}}},
			}}
			auth.Runtime.Context = lualib.NewContext()

			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

			triggered, _ := auth.evaluateRBLService(ctx, trace.SpanFromContext(context.Background()))
			_, marker := auth.Runtime.Context.GetExists(exchange.FeatureKey(exchange.FeatureRBL))

			if triggered != test.wantMarker || marker != test.wantMarker {
				t.Fatalf("triggered/marker = %v/%v, want %v", triggered, marker, test.wantMarker)
			}

			if got := slices.Equal(auth.Runtime.RBLPolicy.MatchedLists, matched); got != test.wantMatched {
				t.Fatalf("matched lists = %#v, want present=%v", auth.Runtime.RBLPolicy.MatchedLists, test.wantMatched)
			}
		})
	}
}
