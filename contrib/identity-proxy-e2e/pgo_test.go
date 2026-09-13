package identityproxye2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPGOCaptureRejectsInvalidProfiles exercises failures under the smoke runner's conditional invocation.
func TestPGOCaptureRejectsInvalidProfiles(t *testing.T) {
	for _, operation := range []string{"-proto", "-top"} {
		t.Run(operation, func(t *testing.T) {
			script, err := os.ReadFile(runScript)
			if err != nil {
				t.Fatal(err)
			}

			definitions, _, found := strings.Cut(string(script), "command=\"${1:-}\"")
			if !found {
				t.Fatal("runner dispatch boundary is missing")
			}

			body := definitions + `
REPO_DIR="$TEST_PGO_DIR"
PGO_DIR="$TEST_PGO_DIR"
NAUTHILUS_E2E_PGO=1
# Supply one successful capture process before exercising the profile tools.
true &
PGO_PIDS=("$!")
go() {
  if [[ "$3" == "$TEST_PGO_FAILURE" ]]; then return 42; fi
  printf 'profile'
}
status=0
finish_pgo_capture || status=$?
exit "$status"
`

			path := filepath.Join(t.TempDir(), "runner.sh")
			if err = os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}

			command := exec.Command("bash", path)

			command.Env = append(os.Environ(), "TEST_PGO_DIR="+t.TempDir(), "TEST_PGO_FAILURE="+operation)

			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("profile tool failure was accepted: %s", output)
			}

			if command.ProcessState.ExitCode() != 42 {
				t.Fatalf("unexpected runner failure: %v: %s", err, output)
			}
		})
	}
}
