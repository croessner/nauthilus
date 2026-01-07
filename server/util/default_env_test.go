package util

import "github.com/croessner/nauthilus/server/config"

// Test-only default environment.
//
// Some unit tests exercise helpers (e.g. hashing) that depend on a deterministic
// environment flag (`DevMode`). Runtime code sets the default at the boundary.
func init() {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: true})
}
