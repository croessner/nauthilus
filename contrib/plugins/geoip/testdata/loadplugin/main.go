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

package main

import (
	"fmt"
	"os"
	stdplugin "plugin"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

// main opens a compiled plugin artifact and verifies the public factory contract.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: loadplugin <artifact.so>")
		os.Exit(2)
	}

	handle, err := stdplugin.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin.Open: %v\n", err)
		os.Exit(1)
	}

	symbol, err := handle.Lookup("NauthilusPlugin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Lookup(NauthilusPlugin): %v\n", err)
		os.Exit(1)
	}

	factory, ok := symbol.(func() (pluginapi.Plugin, error))
	if !ok {
		fmt.Fprintf(os.Stderr, "factory type = %T\n", symbol)
		os.Exit(1)
	}

	pluginObject, err := factory()
	if err != nil {
		fmt.Fprintf(os.Stderr, "factory: %v\n", err)
		os.Exit(1)
	}

	if pluginObject.Metadata().APIVersion != pluginapi.APIVersion {
		fmt.Fprintf(os.Stderr, "api version = %q\n", pluginObject.Metadata().APIVersion)
		os.Exit(1)
	}
}
