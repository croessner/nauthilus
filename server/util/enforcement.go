package util

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

const (
	rootModulePrefix  = "github.com/croessner/nauthilus/v3/"
	forbiddenConfig   = rootModulePrefix + "server/config"
	forbiddenRedis    = rootModulePrefix + "server/rediscli"
	forbiddenLog      = rootModulePrefix + "server/log"
	forbiddenGetFile  = "GetFile()"
	forbiddenGetEnv   = "GetEnvironment()"
	forbiddenGetRedis = "GetClient()"
	forbiddenLogger   = "Logger"
)

var forbiddenPackages = []string{
	forbiddenConfig,
	forbiddenRedis,
	forbiddenLog,
}

var forbiddenSymbolPatterns = map[string][]string{
	forbiddenConfig: {forbiddenGetFile, forbiddenGetEnv},
	forbiddenRedis:  {forbiddenGetRedis},
	forbiddenLog:    {forbiddenLogger},
}

// ForbiddenSymbols defines a list of symbols that should not be used in certain packages.
var ForbiddenSymbols = []string{
	forbiddenConfig + ".GetFile",
	forbiddenConfig + ".GetEnvironment",
	forbiddenRedis + ".GetClient",
	forbiddenLog + ".Logger",
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

	// Check if forbidden packages are even imported.
	for _, fp := range forbiddenPackages {
		if strings.Contains(imports, fp) {
			if isFile {
				checkFileUsage(t, targetPath, fp)
			} else {
				checkUsage(t, pkgPath, fp)
			}
		}
	}
}

// checkFileUsage scans one source file for direct forbidden symbol references.
func checkFileUsage(t *testing.T, targetPath, forbiddenPkg string) {
	// Map path to local file
	file := strings.TrimPrefix(targetPath, rootModulePrefix)

	root := projectRoot(t)
	fullPath := root + "/" + file

	pkgParts := strings.Split(forbiddenPkg, "/")
	pkgName := pkgParts[len(pkgParts)-1]

	for _, pattern := range forbiddenSymbolPatterns[forbiddenPkg] {
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

// checkUsage scans a package directory for direct forbidden symbol references.
func checkUsage(t *testing.T, pkgPath, forbiddenPkg string) {
	// Map package path to directory (simplified)
	dir := strings.TrimPrefix(pkgPath, rootModulePrefix)

	// If the test is running from a subdirectory (like server/core), we might need to adjust the path
	// but normally go test runs from the package directory.
	// Let's find the project root.
	root := projectRoot(t)
	fullDir := root + "/" + dir

	pkgParts := strings.Split(forbiddenPkg, "/")
	pkgName := pkgParts[len(pkgParts)-1]

	for _, pattern := range forbiddenSymbolPatterns[forbiddenPkg] {
		fullPattern := fmt.Sprintf("%s.%s", pkgName, pattern)
		// Use a more specific regex to avoid matching *slog.Logger when we look for log.Logger.
		// Also avoid matching comments.
		regex := fmt.Sprintf(`^[^/]*\b%s\.%s\b`, pkgName, strings.ReplaceAll(pattern, "()", `\(\)`))
		// Use grep -E to find usage in the directory, excluding tests and vendor
		cmd := exec.Command("grep", "-r", "-E", "-n", regex, fullDir)
		output, _ := cmd.CombinedOutput()

		lines := strings.Split(strings.TrimSpace(string(output)), "\n")

		var actualHits []string

		for _, line := range lines {
			if line == "" {
				continue
			}

			parts := strings.SplitN(line, ":", 2)

			file := parts[0]
			if strings.HasSuffix(file, "_test.go") || strings.Contains(file, "vendor/") || strings.Contains(file, "server/config/") || strings.Contains(file, "server/log/") {
				continue
			}

			actualHits = append(actualHits, line)
		}

		if len(actualHits) > 0 {
			t.Errorf("Forbidden symbol %s used in %s:\n%s", fullPattern, pkgPath, strings.Join(actualHits, "\n"))
		}
	}
}

// projectRoot returns the module root used to convert import paths to filesystem paths.
func projectRoot(t *testing.T) string {
	t.Helper()

	rootCmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}")

	rootOut, err := rootCmd.Output()
	if err != nil {
		t.Fatalf("failed to find project root: %v", err)
	}

	return strings.TrimSpace(string(rootOut))
}
