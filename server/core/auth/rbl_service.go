// Copyright (C) 2024-2025 Christian Rößner
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

package auth

import (
	"sync"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/gin-gonic/gin"
)

// DefaultRBLService implements the parallel RBL checks analogous to the previous logic in environment.go.
//
//goland:nointerface
type DefaultRBLService struct{}

// Score provides the exported Score method.
func (DefaultRBLService) Score(ctx *gin.Context, view *core.StateView) (int, error) {
	fact, err := DefaultRBLService{}.ScoreWithFacts(ctx, view)
	if err != nil {
		return 0, err
	}

	return fact.Score, nil
}

// ScoreWithFacts computes the aggregated RBL score and request-local policy facts.
func (DefaultRBLService) ScoreWithFacts(ctx *gin.Context, view *core.StateView) (core.RBLPolicyFact, error) {
	auth := view.Auth()

	rbls := auth.Cfg().GetRBLs()
	if rbls == nil {
		return core.RBLPolicyFact{}, nil
	}

	fact := newRBLPolicyFact(rbls)
	if fact.ListCount == 0 {
		return fact, nil
	}

	fact.Lists = collectRBLListFacts(ctx, view, auth, rbls.GetLists())
	aggregateRBLPolicyFact(auth, &fact)

	if fact.EffectiveError {
		return fact, errors.ErrDNSResolver
	}

	return fact, nil
}

// newRBLPolicyFact starts the request-local RBL fact; collectRBLListFacts allocates the per-list facts.
func newRBLPolicyFact(rbls *config.RBLSection) core.RBLPolicyFact {
	return core.RBLPolicyFact{
		Threshold: rbls.GetThreshold(),
		ListCount: len(rbls.GetLists()),
	}
}

func collectRBLListFacts(
	ctx *gin.Context,
	view *core.StateView,
	auth *core.AuthState,
	rblLists []config.RBL,
) []core.RBLListPolicyFact {
	facts := make([]core.RBLListPolicyFact, len(rblLists))

	var wg sync.WaitGroup

	for index, rbl := range rblLists {
		wg.Go(func() {
			listFact, rblErr := core.RBLPolicyLookup(ctx, view, &rbl)
			if rblErr != nil {
				logRBLPolicyError(ctx, auth, rblErr, listFact)
			}

			// Each lookup owns its slot, so the facts keep configuration order without further locking.
			facts[index] = listFact
		})
	}

	wg.Wait()

	return facts
}

func logRBLPolicyError(ctx *gin.Context, auth *core.AuthState, rblErr error, fact core.RBLListPolicyFact) {
	if fact.ReasonCode == rblReasonDNSSuchHost {
		util.DebugModuleWithCfg(ctx.Request.Context(), auth.Cfg(), auth.Logger(), definitions.DbgRBL, definitions.LogKeyGUID, auth.Runtime.GUID, definitions.LogKeyMsg, rblErr)

		return
	}

	_ = level.Error(auth.Logger()).Log(
		definitions.LogKeyGUID, auth.Runtime.GUID,
		definitions.LogKeyMsg, "RBL check failed",
		definitions.LogKeyError, rblErr,
	)
}

func aggregateRBLPolicyFact(auth *core.AuthState, fact *core.RBLPolicyFact) {
	for _, listFact := range fact.Lists {
		if listFact.Error {
			switch {
			case listFact.ReasonCode == rblReasonDNSSuchHost:
			case listFact.AllowFailure:
				fact.AllowFailureErrorCount++
			default:
				fact.EffectiveError = true
			}
		}

		if !listFact.Listed {
			continue
		}

		stats.GetMetrics().GetRblRejected().WithLabelValues(listFact.Name).Inc()
		auth.Runtime.AdditionalLogs = append(auth.Runtime.AdditionalLogs, "rbl "+listFact.Name)
		auth.Runtime.AdditionalLogs = append(auth.Runtime.AdditionalLogs, listFact.Weight)
		fact.Score += listFact.Weight
		fact.MatchedCount++
		fact.MatchedLists = append(fact.MatchedLists, listFact.Name)
	}
}
