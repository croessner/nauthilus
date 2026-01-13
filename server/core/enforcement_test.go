package core

import (
	"testing"

	"github.com/croessner/nauthilus/server/util"
)

func TestEnforcement(t *testing.T) {
	// Only check specific migrated files in server/core
	// We use the file-based check by appending the filename to the package path in our helper
	// Actually, let's update the helper to support file patterns.
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/core/http.go")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/core/jwt.go")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/core/auth_hydra.go")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/core/hydra.go")
}
