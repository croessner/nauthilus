// Copyright (C) 2024 Christian Rößner
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

//go:build !linux

package stats

import (
	"github.com/mackerelio/go-osstat/cpu"
)

func setNewStats(oldCpu, newCpu *cpu.Stats, total float64) {
	cpuUserUsage.Set(float64(newCpu.User-oldCpu.User) / total * 100)
	cpuSystemUsage.Set(float64(newCpu.System-oldCpu.System) / total * 100)

	idlePercent := float64(newCpu.Idle-oldCpu.Idle) / total * 100
	cpuIdleUsage.Set(idlePercent)
	currentCPUIdleUsage = idlePercent
}
