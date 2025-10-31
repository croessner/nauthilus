package bruteforce_test

import (
	"os"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	apilog "github.com/croessner/nauthilus/server/log"
)

// TestMain initializes global logging exactly once for this package before tests run.
func TestMain(m *testing.M) {
	apilog.SetupLogging(definitions.LogLevelNone, false, false, false, "test")
	os.Exit(m.Run())
}
