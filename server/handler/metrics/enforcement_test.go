// Package metrics provides metrics functionality.
package metrics

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/util"
)

func TestEnforcement(t *testing.T) {
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/v3/server/handler/metrics/handler.go")
}
