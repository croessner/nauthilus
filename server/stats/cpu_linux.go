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

//go:build linux

package stats

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var cpuNiceUsage = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "cpu_nice_usage_percent",
	Help: "CPU nice usage in percent",
})

var cpuIowaitUsage = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "cpu_iowait_usage_percent",
	Help: "CPU iowait usage in percent",
})

var cpuIRQUsage = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "cpu_irq_usage_percent",
	Help: "CPU irq usage in percent",
})

var cpuSoftIRQUsage = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "cpu_softirq_usage_percent",
	Help: "CPU softirq usage in percent",
})

var cpuStealUsage = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "cpu_steal_usage_percent",
	Help: "CPU steal usage in percent",
})

func setNewStats(oldCpu, newCpu *cpu.Stats, total float64) {
	cpuUserUsage.Set(float64(newCpu.User-oldCpu.User) / total * 100)
	cpuSystemUsage.Set(float64(newCpu.System-oldCpu.System) / total * 100)
	cpuIdleUsage.Set(float64(newCpu.Idle-oldCpu.Idle) / total * 100)

	cpuIowaitUsage.Set(float64(newCpu.Iowait-oldCpu.Iowait) / total * 100)
	cpuIRQUsage.Set(float64(newCpu.IRQ-oldCpu.IRQ) / total * 100)
	cpuSoftIRQUsage.Set(float64(newCpu.SoftIRQ-oldCpu.SoftIRQ) / total * 100)
	cpuStealUsage.Set(float64(newCpu.Steal-oldCpu.Steal) / total * 100)
}
