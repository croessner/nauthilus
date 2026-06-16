// Copyright (C) 2026 Christian Roessner
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

package pluginapi

import (
	"os"
	"os/exec"
	"testing"
)

func TestExternalStylePluginFixtureCompiles(t *testing.T) {
	cmd := exec.Command("go", "test", "./testdata/sampleplugin")
	cmd.Env = goTestEnv()

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile fixture: %v\n%s", err, output)
	}
}

// goTestEnv returns the required Go experiment setting for nested fixture compilation.
func goTestEnv() []string {
	env := append([]string{}, os.Environ()...)
	env = append(env, "GOEXPERIMENT=runtimesecret")

	if os.Getenv("GOCACHE") == "" {
		env = append(env, "GOCACHE=/tmp/nauthilus-go-cache")
	}

	return env
}
