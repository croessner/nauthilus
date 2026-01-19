package core

import "github.com/croessner/nauthilus/server/config"

// Test-only default environment.
//
// Runtime code sets the default at the boundary. Unit tests may call core
// helpers (e.g. header/registration/debug paths) which depend on `DevMode`.
func init() {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: true})
}
