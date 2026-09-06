// Command nativebundle checks actual native build compatibility without starting plugin services.
package main

import (
	"fmt"
	"os"
	"plugin"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
)

// main checks every artifact before invoking a factory and reports only bounded product metadata.
func main() {
	for _, path := range os.Args[1:] {
		if err := check(path); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

// check exercises both the repository preflight and Go runtime package compatibility gate.
func check(path string) error {
	if err := pluginloader.VerifyNativeArtifactCompatibility(path); err != nil {
		return err
	}

	handle, err := plugin.Open(path)
	if err != nil {
		return err
	}

	symbol, err := handle.Lookup("NauthilusPlugin")
	if err != nil {
		return err
	}

	factory, ok := symbol.(func() (pluginapi.Plugin, error))
	if !ok {
		return fmt.Errorf("invalid native factory contract")
	}

	instance, err := factory()
	if err != nil {
		return err
	}

	metadata := instance.Metadata()
	if metadata.Build.ArtifactIdentity != pluginapi.NativeArtifactIdentity() {
		return fmt.Errorf("native metadata identity mismatch")
	}
	if err := pluginapi.ValidateMetadata(metadata); err != nil {
		return err
	}

	fmt.Printf("compatible native artifact: %s\n", metadata.Name)
	return nil
}
