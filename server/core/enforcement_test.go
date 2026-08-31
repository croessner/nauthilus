package core

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/util"
)

func TestEnforcement(t *testing.T) {
	// Check the entire server/ directory recursively, excluding config and log packages
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/v4/server/backend")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/v4/server/bruteforce")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/v4/server/core")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/v4/server/lualib")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/v4/server/handler/deps")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/v4/server/handler/auth")
}
