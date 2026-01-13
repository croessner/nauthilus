package metrics

import (
	"testing"

	"github.com/croessner/nauthilus/server/util"
)

func TestEnforcement(t *testing.T) {
	util.AssertNoForbiddenSymbols(t, "github.com/croessner/nauthilus/server/handler/metrics/handler.go")
}
