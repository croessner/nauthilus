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

// Package pipeline plans deterministic dependency levels for request-local Lua execution.
package pipeline

import (
	"fmt"
	"sort"
	"strings"
)

// ModeMask describes the request modes in which a pipeline node may run.
type ModeMask uint8

const (
	// ModeAuthenticated means the node may run after successful authentication.
	ModeAuthenticated ModeMask = 1 << iota

	// ModeUnauthenticated means the node may run before successful authentication.
	ModeUnauthenticated

	// ModeNoAuth means the node may run in no-auth request paths.
	ModeNoAuth
)

// Node describes one configured script in a dependency graph.
type Node struct {
	Name      string
	DependsOn []string
	Index     int
	Modes     ModeMask
	Value     any
}

// PlannedNode is a runnable node in a dependency level.
type PlannedNode struct {
	Name      string
	DependsOn []string
	Index     int
	Value     any
}

// Plan contains dependency levels that can be executed sequentially.
type Plan struct {
	Levels [][]PlannedNode
}

type graphState struct {
	byName     map[string]Node
	inDegree   map[string]int
	dependents map[string][]string
}

// ValidateStatic checks name uniqueness, dependency references, mode compatibility, and cycles.
func ValidateStatic(nodes []Node) error {
	if err := validateNames(nodes); err != nil {
		return err
	}

	byName := nodesByName(nodes)

	for _, node := range nodes {
		for _, dependencyName := range node.DependsOn {
			dependency, ok := byName[dependencyName]
			if !ok {
				return fmt.Errorf("%s: unknown dependency %q", node.Name, dependencyName)
			}

			if dependencyName == node.Name {
				return fmt.Errorf("%s: self dependency is not allowed", node.Name)
			}

			if node.Modes&^dependency.Modes != 0 {
				return fmt.Errorf("%s: dependency %q is not runnable in all modes required by dependent", node.Name, dependencyName)
			}
		}
	}

	if _, err := buildLevels(nodes); err != nil {
		return err
	}

	return nil
}

// BuildPlan returns deterministic execution levels for nodes runnable in the given mode.
func BuildPlan(nodes []Node, mode ModeMask) (Plan, error) {
	if err := ValidateStatic(nodes); err != nil {
		return Plan{}, err
	}

	runnable := make([]Node, 0, len(nodes))
	for _, node := range nodes {
		if node.Modes&mode != 0 {
			runnable = append(runnable, node)
		}
	}

	levels, err := buildLevels(runnable)
	if err != nil {
		return Plan{}, err
	}

	return Plan{Levels: levels}, nil
}

func validateNames(nodes []Node) error {
	seen := make(map[string]Node, len(nodes))

	for _, node := range nodes {
		if node.Name == "" {
			return fmt.Errorf("script at index %d has empty name", node.Index)
		}

		if previous, ok := seen[node.Name]; ok {
			return fmt.Errorf("%s: duplicate script name also used at index %d", node.Name, previous.Index)
		}

		seen[node.Name] = node
	}

	return nil
}

func buildLevels(nodes []Node) ([][]PlannedNode, error) {
	graph, err := newGraphState(nodes)
	if err != nil {
		return nil, err
	}

	ready := initialReadyNodes(nodes, graph.inDegree)
	sortNodes(ready)

	levels := make([][]PlannedNode, 0)
	visited := 0

	for len(ready) > 0 {
		levelNodes := make([]Node, len(ready))
		copy(levelNodes, ready)
		ready = ready[:0]

		level := make([]PlannedNode, 0, len(levelNodes))
		for _, node := range levelNodes {
			visited++
			level = append(level, PlannedNode{
				Name:      node.Name,
				DependsOn: append([]string(nil), node.DependsOn...),
				Index:     node.Index,
				Value:     node.Value,
			})

			for _, dependentName := range graph.dependents[node.Name] {
				graph.inDegree[dependentName]--
				if graph.inDegree[dependentName] == 0 {
					ready = append(ready, graph.byName[dependentName])
				}
			}
		}

		sort.Slice(level, func(i, j int) bool {
			return level[i].Index < level[j].Index
		})
		sortNodes(ready)

		levels = append(levels, level)
	}

	if visited != len(nodes) {
		return nil, fmt.Errorf("dependency cycle detected: %s", cyclePath(nodes))
	}

	return levels, nil
}

func newGraphState(nodes []Node) (graphState, error) {
	graph := graphState{
		byName:     nodesByName(nodes),
		inDegree:   make(map[string]int, len(nodes)),
		dependents: make(map[string][]string, len(nodes)),
	}

	for _, node := range nodes {
		graph.inDegree[node.Name] = 0
	}

	for _, node := range nodes {
		for _, dependencyName := range node.DependsOn {
			if _, ok := graph.byName[dependencyName]; !ok {
				return graphState{}, fmt.Errorf("%s: unknown dependency %q", node.Name, dependencyName)
			}

			graph.inDegree[node.Name]++
			graph.dependents[dependencyName] = append(graph.dependents[dependencyName], node.Name)
		}
	}

	return graph, nil
}

func initialReadyNodes(nodes []Node, inDegree map[string]int) []Node {
	ready := make([]Node, 0)

	for _, node := range nodes {
		if inDegree[node.Name] == 0 {
			ready = append(ready, node)
		}
	}

	return ready
}

func nodesByName(nodes []Node) map[string]Node {
	byName := make(map[string]Node, len(nodes))

	for _, node := range nodes {
		byName[node.Name] = node
	}

	return byName
}

func sortNodes(nodes []Node) {
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Index < nodes[j].Index
	})
}

func cyclePath(nodes []Node) string {
	byName := nodesByName(nodes)
	visiting := make(map[string]bool, len(nodes))
	visited := make(map[string]bool, len(nodes))
	stack := make([]string, 0, len(nodes))

	var walk func(string) []string
	walk = func(name string) []string {
		if visiting[name] {
			for index, stackName := range stack {
				if stackName == name {
					return append(append([]string(nil), stack[index:]...), name)
				}
			}

			return []string{name, name}
		}

		if visited[name] {
			return nil
		}

		visiting[name] = true
		stack = append(stack, name)

		node := byName[name]
		for _, dependencyName := range node.DependsOn {
			if _, ok := byName[dependencyName]; !ok {
				continue
			}

			if path := walk(dependencyName); len(path) > 0 {
				return path
			}
		}

		stack = stack[:len(stack)-1]
		visiting[name] = false
		visited[name] = true

		return nil
	}

	ordered := append([]Node(nil), nodes...)
	sortNodes(ordered)

	for _, node := range ordered {
		if path := walk(node.Name); len(path) > 0 {
			return strings.Join(path, " -> ")
		}
	}

	return "unknown"
}
