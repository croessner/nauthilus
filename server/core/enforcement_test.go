package core

import (
	"testing"

	"github.com/croessner/nauthilus/server/util"
)

func TestEnforcement(t *testing.T) {
	// Check the entire server/ directory recursively, excluding config and log packages
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/backend")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/bruteforce")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/core")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/lualib")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/handler/deps")
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/handler/auth")
}
