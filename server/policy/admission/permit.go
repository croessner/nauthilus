// Copyright (C) 2026 Christian Rößner
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

package admission

import (
	"sync"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

var _ policyruntime.AdmissionPermit = (*permit)(nil)

type permit struct {
	concurrency chan struct{}
	facts       decision.FactSet
	release     sync.Once
}

// Facts returns the immutable admitted caller and trusted fact set.
func (p *permit) Facts() decision.FactSet {
	if p == nil {
		facts, _ := decision.NewFactSet(nil)

		return facts
	}

	return p.facts
}

// Release idempotently returns the profile concurrency slot.
func (p *permit) Release() {
	if p == nil {
		return
	}

	p.release.Do(func() {
		<-p.concurrency
	})
}
