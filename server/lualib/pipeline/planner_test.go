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
	"reflect"
	"strings"
	"testing"
)

func TestPlannerBuildsDeterministicLevels(t *testing.T) {
	nodes := []Node{
		{Name: "geoip", Index: 0, DependsOn: nil, Modes: ModeAuthenticated},
		{Name: "metrics", Index: 1, DependsOn: nil, Modes: ModeAuthenticated},
		{Name: "routing", Index: 2, DependsOn: []string{"geoip", "metrics"}, Modes: ModeAuthenticated},
	}

	plan, err := BuildPlan(nodes, ModeAuthenticated)
	if err != nil {
		t.Fatalf("BuildPlan returned error: %v", err)
	}

	if len(plan.Levels) != 2 {
		t.Fatalf("expected 2 levels, got %d", len(plan.Levels))
	}

	assertLevelNames(t, plan.Levels[0], "geoip", "metrics")
	assertLevelNames(t, plan.Levels[1], "routing")
}

func TestPlannerRejectsCycles(t *testing.T) {
	nodes := []Node{
		{Name: "a", Index: 0, DependsOn: []string{"c"}, Modes: ModeAuthenticated},
		{Name: "b", Index: 1, DependsOn: []string{"a"}, Modes: ModeAuthenticated},
		{Name: "c", Index: 2, DependsOn: []string{"b"}, Modes: ModeAuthenticated},
	}

	_, err := BuildPlan(nodes, ModeAuthenticated)
	if err == nil {
		t.Fatal("expected cycle error")
	}

	if !strings.Contains(err.Error(), "dependency cycle detected") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

func TestPlannerRejectsModeIncompatibleDependencies(t *testing.T) {
	nodes := []Node{
		{Name: "base", Index: 0, Modes: ModeAuthenticated},
		{Name: "dependent", Index: 1, DependsOn: []string{"base"}, Modes: ModeAuthenticated | ModeUnauthenticated},
	}

	err := ValidateStatic(nodes)
	if err == nil {
		t.Fatal("expected mode compatibility error")
	}

	if !strings.Contains(err.Error(), "not runnable in all modes") {
		t.Fatalf("expected mode compatibility error, got %v", err)
	}
}

func TestPlannerRejectsUnknownDependency(t *testing.T) {
	nodes := []Node{
		{Name: "dependent", Index: 0, DependsOn: []string{"missing"}, Modes: ModeAuthenticated},
	}

	err := ValidateStatic(nodes)
	if err == nil {
		t.Fatal("expected unknown dependency error")
	}

	if !strings.Contains(err.Error(), "unknown dependency") {
		t.Fatalf("expected unknown dependency error, got %v", err)
	}
}

func assertLevelNames(t *testing.T, level []PlannedNode, expected ...string) {
	t.Helper()

	if len(level) != len(expected) {
		t.Fatalf("expected level length %d, got %d", len(expected), len(level))
	}

	for index, name := range expected {
		if level[index].Name != name {
			t.Fatalf("expected level[%d] name %q, got %q", index, name, level[index].Name)
		}
	}
}

func TestSingleNodePlansMatchTheDependencyGraph(t *testing.T) {
	allModes := ModeAuthenticated | ModeUnauthenticated | ModeNoAuth
	nodes := map[string]Node{
		"all modes":          {Name: "source", Index: 0, Modes: allModes, Value: "payload"},
		"one mode":           {Name: "source", Index: 3, Modes: ModeNoAuth},
		"two modes":          {Name: "source", Index: 1, Modes: ModeAuthenticated | ModeUnauthenticated},
		"no mode":            {Name: "source", Index: 0},
		"empty dependencies": {Name: "source", Index: 0, Modes: allModes, DependsOn: []string{}},
		"empty name":         {Index: 7, Modes: allModes},
		"unknown dependency": {Name: "source", Modes: allModes, DependsOn: []string{"other"}},
		"self dependency":    {Name: "source", Modes: allModes, DependsOn: []string{"source"}},
		"unknown then self":  {Name: "source", Modes: allModes, DependsOn: []string{"other", "source"}},
		"self then unknown":  {Name: "source", Modes: allModes, DependsOn: []string{"source", "other"}},
	}

	for name, node := range nodes {
		t.Run(name, func(t *testing.T) {
			want, wantErr := buildGraphPlans([]Node{node})
			got, gotErr := BuildPlans([]Node{node})

			if (wantErr == nil) != (gotErr == nil) || (wantErr != nil && wantErr.Error() != gotErr.Error()) {
				t.Fatalf("expected error %v, got %v", wantErr, gotErr)
			}

			if !reflect.DeepEqual(want, got) {
				t.Fatalf("expected plans %#v, got %#v", want, got)
			}
		})
	}
}

func TestSingleNodePlansAvoidTheDependencyGraph(t *testing.T) {
	nodes := []Node{{Name: "source", Modes: ModeAuthenticated | ModeNoAuth}}

	allocations := testing.AllocsPerRun(100, func() {
		if _, err := BuildPlans(nodes); err != nil {
			t.Fatal(err)
		}
	})

	if allocations > 4 {
		t.Fatalf("expected at most 4 allocations for a single node, got %v", allocations)
	}
}
