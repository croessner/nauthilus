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

package pluginregistry

import "github.com/croessner/nauthilus/v3/server/lualib/pipeline"

// BuildSourcePlan derives the shared dependency and registration-order execution plan.
func BuildSourcePlan(components []Component, mode pipeline.ModeMask) (pipeline.Plan, error) {
	nodes := make([]pipeline.Node, 0, len(components))
	for index, component := range components {
		dependencies := append([]string(nil), component.SourceDescriptor.Requires...)
		dependencies = append(dependencies, component.SourceDescriptor.After...)
		nodes = append(nodes, pipeline.Node{
			Name:      component.QualifiedName,
			DependsOn: dependencies,
			Index:     index,
			Modes:     pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth,
			Value:     component,
		})
	}

	return pipeline.BuildPlan(nodes, mode)
}
