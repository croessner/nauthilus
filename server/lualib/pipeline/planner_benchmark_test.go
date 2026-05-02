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

package pipeline

import (
	"fmt"
	"testing"
)

func BenchmarkBuildPlanFeatureGraphs(b *testing.B) {
	benchmarkBuildPlanGraphs(b, "feature", []graphCase{
		{name: "flat_8", nodes: flatGraph("feature", 8)},
		{name: "layered_8", nodes: layeredGraph("feature", 8, 2)},
		{name: "flat_32", nodes: flatGraph("feature", 32)},
		{name: "layered_32", nodes: layeredGraph("feature", 32, 4)},
	})
}

func BenchmarkBuildPlanFilterGraphs(b *testing.B) {
	benchmarkBuildPlanGraphs(b, "filter", []graphCase{
		{name: "flat_8", nodes: flatGraph("filter", 8)},
		{name: "layered_8", nodes: layeredGraph("filter", 8, 2)},
		{name: "flat_32", nodes: flatGraph("filter", 32)},
		{name: "layered_32", nodes: layeredGraph("filter", 32, 4)},
	})
}

type graphCase struct {
	name  string
	nodes []Node
}

func benchmarkBuildPlanGraphs(b *testing.B, prefix string, cases []graphCase) {
	b.Helper()

	for _, tc := range cases {
		b.Run(prefix+"/"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				plan, err := BuildPlan(tc.nodes, ModeAuthenticated)
				if err != nil {
					b.Fatalf("BuildPlan returned error: %v", err)
				}

				if len(plan.Levels) == 0 {
					b.Fatal("BuildPlan returned no levels")
				}
			}
		})
	}
}

func flatGraph(prefix string, count int) []Node {
	nodes := make([]Node, 0, count)

	for index := range count {
		nodes = append(nodes, Node{
			Name:  fmt.Sprintf("%s_%02d", prefix, index),
			Index: index,
			Modes: ModeAuthenticated | ModeUnauthenticated,
		})
	}

	return nodes
}

func layeredGraph(prefix string, count int, fanIn int) []Node {
	nodes := flatGraph(prefix, count)

	for index := fanIn; index < count; index++ {
		dependencies := make([]string, 0, fanIn)
		for dependencyIndex := index - fanIn; dependencyIndex < index; dependencyIndex++ {
			dependencies = append(dependencies, nodes[dependencyIndex].Name)
		}

		nodes[index].DependsOn = dependencies
	}

	return nodes
}
