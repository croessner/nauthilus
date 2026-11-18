package identityproxye2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pgoCaptureHarness runs finish_pgo_capture of the smoke runner with a stubbed go tool. The stub fails the pprof
// operation named by TEST_PGO_FAILURE and otherwise reports TEST_PGO_SAMPLES CPU samples.
const pgoCaptureHarness = `
REPO_DIR="$TEST_PGO_DIR"
PGO_DIR="$TEST_PGO_DIR"
NAUTHILUS_E2E_PGO=1
# Supply one successful capture process before exercising the profile tools.
true &
PGO_PIDS=("$!")
go() {
  if [[ "$3" == "$TEST_PGO_FAILURE" ]]; then return 42; fi
  printf 'Duration: 30s, Total samples = %s \n' "$TEST_PGO_SAMPLES"
}
status=0
finish_pgo_capture || status=$?
exit "$status"
`

// TestPGOCaptureGatesCandidates exercises the candidate validation of the smoke runner: failing profile tools and
// sample-poor candidates (the 1-5 sample profiles release runs produced before the dedicated workload) are refused,
// and only a dense candidate is published.
func TestPGOCaptureGatesCandidates(t *testing.T) {
	script, err := os.ReadFile(runScript)
	if err != nil {
		t.Fatal(err)
	}

	definitions, _, found := strings.Cut(string(script), "command=\"${1:-}\"")
	if !found {
		t.Fatal("runner dispatch boundary is missing")
	}

	for name, tc := range map[string]struct {
		failure   string
		samples   string
		exitCode  int
		published bool
	}{
		"merge fails":          {failure: "-proto", samples: "5000", exitCode: 42},
		"validation fails":     {failure: "-top", samples: "5000", exitCode: 42},
		"idle release profile": {samples: "2", exitCode: 1},
		"dense profile":        {samples: "5000", published: true},
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(t.TempDir(), "runner.sh")

			if err = os.WriteFile(path, []byte(definitions+pgoCaptureHarness), 0600); err != nil {
				t.Fatal(err)
			}

			command := exec.Command("bash", path)

			command.Env = append(os.Environ(), "TEST_PGO_DIR="+directory, "TEST_PGO_FAILURE="+tc.failure,
				"TEST_PGO_SAMPLES="+tc.samples)

			output, _ := command.CombinedOutput()
			if command.ProcessState.ExitCode() != tc.exitCode {
				t.Fatalf("exit code %d, want %d: %s", command.ProcessState.ExitCode(), tc.exitCode, output)
			}

			_, statErr := os.Stat(filepath.Join(directory, "candidate.pgo"))
			if published := statErr == nil; published != tc.published {
				t.Fatalf("candidate published=%v, want %v: %s", published, tc.published, output)
			}
		})
	}
}
