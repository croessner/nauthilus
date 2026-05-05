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

// Package policyschedule adapts policy script schedules to Lua execution plans.
package policyschedule

import (
	"github.com/croessner/nauthilus/server/lualib/pipeline"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
)

// BuildPlan creates a Lua execution plan from a request-local policy script schedule.
func BuildPlan(nodes []pipeline.Node, scriptPlan policycollection.ScriptSchedulePlan, mode pipeline.ModeMask) (pipeline.Plan, error) {
	return pipeline.BuildPlan(pipeline.ApplySchedule(nodes, pipelineSchedules(scriptPlan.Schedules), mode), mode)
}

func pipelineSchedules(schedules []policycollection.ScriptSchedule) []pipeline.Schedule {
	converted := make([]pipeline.Schedule, 0, len(schedules))

	for _, schedule := range schedules {
		converted = append(converted, pipeline.Schedule{
			Name:      schedule.Name,
			DependsOn: append([]string(nil), schedule.After...),
		})
	}

	return converted
}
