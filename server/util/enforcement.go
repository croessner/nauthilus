package util

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// ForbiddenSymbols defines a list of symbols that should not be used in certain packages.
var ForbiddenSymbols = []string{
	"github.com/croessner/nauthilus/server/config.GetFile",
	"github.com/croessner/nauthilus/server/config.GetEnvironment",
	"github.com/croessner/nauthilus/server/rediscli.GetClient",
	"github.com/croessner/nauthilus/server/log.Logger",
}

// AssertNoForbiddenSymbols checks if the given package (identified by its import path)
// uses any of the forbidden symbols.
// Note: This relies on 'go tool nm' and might not catch all dynamic usages,
// but it's a good compile-time check for direct references.
func AssertNoForbiddenSymbols(t *testing.T, targetPath string) {
	t.Helper()

	// If targetPath ends with .go, it's a file, otherwise it's a package.
	pkgPath := targetPath
	isFile := false
	if strings.HasSuffix(targetPath, ".go") {
		isFile = true
		pkgPath = strings.Join(strings.Split(targetPath, "/")[:len(strings.Split(targetPath, "/"))-1], "/")
	}

	cmd := exec.Command("go", "list", "-f", "{{.Imports}}", pkgPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to list imports for %s: %v", pkgPath, err)
	}

	imports := out.String()

	// Check if forbidden packages are even imported
	forbiddenPkgs := []string{
		"github.com/croessner/nauthilus/server/config",
		"github.com/croessner/nauthilus/server/rediscli",
		"github.com/croessner/nauthilus/server/log",
	}

	for _, fp := range forbiddenPkgs {
		if strings.Contains(imports, fp) {
			if isFile {
				checkFileUsage(t, targetPath, fp)
			} else {
				checkUsage(t, pkgPath, fp)
			}
		}
	}
}

func checkFileUsage(t *testing.T, targetPath, forbiddenPkg string) {
	// Map path to local file
	file := strings.TrimPrefix(targetPath, "github.com/croessner/nauthilus/")

	rootCmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}")
	rootOut, _ := rootCmd.Output()
	root := strings.TrimSpace(string(rootOut))
	fullPath := root + "/" + file

	// Forbidden patterns
	patterns := map[string][]string{
		"github.com/croessner/nauthilus/server/config":   {"GetFile()", "GetEnvironment()"},
		"github.com/croessner/nauthilus/server/rediscli": {"GetClient()"},
		"github.com/croessner/nauthilus/server/log":      {"Logger"},
	}

	pkgParts := strings.Split(forbiddenPkg, "/")
	pkgName := pkgParts[len(pkgParts)-1]

	for _, pattern := range patterns[forbiddenPkg] {
		fullPattern := fmt.Sprintf("%s.%s", pkgName, pattern)
		// Use a more specific regex to avoid matching *slog.Logger when we look for log.Logger
		// We want to match "log.Logger" but not "*slog.Logger" or "slog.Logger"
		regex := fmt.Sprintf(`\b%s\.%s\b`, pkgName, strings.ReplaceAll(pattern, "()", `\(\)`))
		cmd := exec.Command("grep", "-E", "-n", regex, fullPath)
		output, _ := cmd.CombinedOutput()

		hits := strings.TrimSpace(string(output))
		if hits != "" {
			t.Errorf("Forbidden symbol %s used in %s:\n%s", fullPattern, targetPath, hits)
		}
	}
}

func checkUsage(t *testing.T, pkgPath, forbiddenPkg string) {
	// Map package path to directory (simplified)
	dir := strings.TrimPrefix(pkgPath, "github.com/croessner/nauthilus/")

	// If the test is running from a subdirectory (like server/core), we might need to adjust the path
	// but normally go test runs from the package directory.
	// Let's find the project root.
	rootCmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}")
	rootOut, err := rootCmd.Output()
	if err != nil {
		t.Fatalf("failed to find project root: %v", err)
	}
	root := strings.TrimSpace(string(rootOut))
	fullDir := root + "/" + dir

	// Forbidden patterns
	patterns := map[string][]string{
		"github.com/croessner/nauthilus/server/config":   {"GetFile()", "GetEnvironment()"},
		"github.com/croessner/nauthilus/server/rediscli": {"GetClient()"},
		"github.com/croessner/nauthilus/server/log":      {"Logger"},
	}

	pkgParts := strings.Split(forbiddenPkg, "/")
	pkgName := pkgParts[len(pkgParts)-1]

	for _, pattern := range patterns[forbiddenPkg] {
		fullPattern := fmt.Sprintf("%s.%s", pkgName, pattern)
		// Use grep to find usage in the directory, excluding tests
		cmd := exec.Command("grep", "-r", "-l", fullPattern, fullDir)
		output, _ := cmd.CombinedOutput()

		files := strings.Split(strings.TrimSpace(string(output)), "\n")
		var actualHits []string
		for _, file := range files {
			if file == "" || strings.HasSuffix(file, "_test.go") || strings.Contains(file, "vendor/") {
				continue
			}
			// Get the actual line for reporting
			lineCmd := exec.Command("grep", "-n", fullPattern, file)
			lineOut, _ := lineCmd.CombinedOutput()
			actualHits = append(actualHits, strings.TrimSpace(string(lineOut)))
		}

		if len(actualHits) > 0 {
			t.Errorf("Forbidden symbol %s used in %s:\n%s", fullPattern, pkgPath, strings.Join(actualHits, "\n"))
		}
	}
}
