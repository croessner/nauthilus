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
	"strings"
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

// DefaultRBLService implements the parallel RBL checks analogous to the previous logic in features.go.
//
//goland:nointerface
type DefaultRBLService struct{}

func (DefaultRBLService) Threshold() int {
	r := config.GetFile().GetRBLs()
	if r == nil {
		return 0
	}
	return r.GetThreshold()
}

func (DefaultRBLService) Score(ctx *gin.Context, view *core.StateView) (int, error) {
	a := view.Auth()

	rbls := config.GetFile().GetRBLs()
	if rbls == nil {
		return 0, nil
	}

	var dnsResolverErr atomic.Bool
	dnsResolverErr.Store(false)

	rblLists := rbls.GetLists()
	numberOfRBLs := len(rblLists)
	if numberOfRBLs == 0 {
		return 0, nil
	}

	rblChan := make(chan int, numberOfRBLs)
	var wg sync.WaitGroup

	for _, rbl := range rblLists {
		r := rbl
		wg.Add(1)
		go func() {
			defer wg.Done()

			listed, rblName, rblErr := core.RBLIsListed(ctx, view, &r)
			if rblErr != nil {
				if strings.Contains(rblErr.Error(), "no such host") {
					util.DebugModule(definitions.DbgRBL, definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, rblErr)
				} else {
					if !r.IsAllowFailure() {
						dnsResolverErr.Store(true)
					}

					level.Error(log.Logger).Log(
						definitions.LogKeyGUID, a.GUID,
						definitions.LogKeyMsg, "RBL check failed",
						definitions.LogKeyError, rblErr,
					)
				}

				rblChan <- 0
				return
			}

			if listed {
				stats.GetMetrics().GetRblRejected().WithLabelValues(rblName).Inc()
				a.AdditionalLogs = append(a.AdditionalLogs, "rbl "+rblName)
				a.AdditionalLogs = append(a.AdditionalLogs, r.Weight)
				rblChan <- r.Weight
				return
			}

			rblChan <- 0
		}()
	}

	wg.Wait()

	if dnsResolverErr.Load() {
		return 0, errors.ErrDNSResolver
	}

	total := 0
	for i := 0; i < numberOfRBLs; i++ {
		total += <-rblChan
	}

	return total, nil
}
