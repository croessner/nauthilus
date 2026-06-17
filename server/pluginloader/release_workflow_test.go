package pluginloader

import (
	"os"
	"strings"
	"testing"
)

// TestBuildStableReleaseNotesCoverApprovedPrefixes prevents release notes from omitting valid commit prefixes.
func TestBuildStableReleaseNotesCoverApprovedPrefixes(t *testing.T) {
	content, err := os.ReadFile("../../.github/workflows/build-stable.yaml")
	if err != nil {
		t.Fatalf("read build-stable workflow: %v", err)
	}

	workflow := string(content)
	expectedSections := map[string]string{
		`append_section "Added" "Add:"`:               "Add",
		`append_section "Changed" "Change:"`:          "Change",
		`append_section "Fixed" "Fix:"`:               "Fix",
		`append_section "Removed" "Remove:"`:          "Remove",
		`append_section "Refactored" "Refactor:"`:     "Refactor",
		`append_section "Tests" "Test:"`:              "Test",
		`append_section "Documentation" "Docs:"`:      "Docs",
		`append_section "Build And CI" "(Build|Ci):"`: "Build/Ci",
		`append_section "Security" "Security:"`:       "Security",
		`append_section "Dependencies" "Vendor:"`:     "Vendor",
		`append_section "Chores" "Chore:"`:            "Chore",
	}

	for expected, prefix := range expectedSections {
		if !strings.Contains(workflow, expected) {
			t.Fatalf("build-stable release notes must include %s commits", prefix)
		}
	}

	if !strings.Contains(workflow, "--extended-regexp --regexp-ignore-case") {
		t.Fatalf("build-stable release notes must use extended regular expressions for grouped prefixes")
	}
}
