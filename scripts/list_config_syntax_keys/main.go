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

// Package main prints the known configuration syntax keys as JSON.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/croessner/nauthilus/server/config"
)

type syntaxKeys struct {
	Roots  []string `json:"roots"`
	Level2 []string `json:"level2"`
	Level3 []string `json:"level3"`
}

func main() {
	roots, level2, level3, err := config.KnownConfigSyntaxKeys()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	payload, err := json.MarshalIndent(syntaxKeys{
		Roots:  roots,
		Level2: level2,
		Level3: level3,
	}, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(string(payload))
}
