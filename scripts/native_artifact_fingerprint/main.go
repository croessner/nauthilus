// Command native_artifact_fingerprint binds native builds to exact source and toolchain inputs.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// main emits one linker assignment or fails without publishing an incomplete identity.
func main() {
	tags := flag.String("tags", "", "native build tags")

	flag.Parse()

	identity, err := fingerprint(*tags)
	if err != nil {
		fmt.Fprintln(os.Stderr, "native artifact fingerprint failed:", err)
		os.Exit(1)
	}

	fmt.Printf("-X github.com/croessner/nauthilus/v4/pluginapi/v1.nativeArtifactIdentity=nauthilus-native-artifact-v1:%s:end-native-artifact\n", identity)
}

// fingerprint hashes canonical build settings and all admitted compiler inputs in repository order.
func fingerprint(tags string) (string, error) {
	root, files, err := repositoryCompilerInputs(tags)
	if err != nil {
		return "", err
	}

	settings, err := exec.Command("go", "env", "GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED", "GOEXPERIMENT", "GOFLAGS", "GOAMD64", "GOARM64", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS", "CC", "CXX").Output()
	if err != nil {
		return "", err
	}

	digest := sha256.New()
	frame(digest, []byte("nauthilus-native-build-v1"))
	frame(digest, settings)

	normalizedTags := strings.FieldsFunc(tags, func(character rune) bool { return character == ',' || character == ' ' })
	sort.Strings(normalizedTags)
	frame(digest, []byte(strings.Join(normalizedTags, ",")))

	for _, name := range files {
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return "", fmt.Errorf("compiler input unavailable: %s", name)
		}

		frame(digest, []byte(filepath.ToSlash(name)))
		frame(digest, content)
	}

	return hex.EncodeToString(digest.Sum(nil)), nil
}

// repositoryCompilerInputs includes source, dependency locks, and actual embedded build resources.
func repositoryCompilerInputs(tags string) (string, []string, error) {
	rootBytes, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", nil, err
	}

	root := strings.TrimSpace(string(rootBytes))
	command := exec.Command("git", "ls-files", "--cached", "--others", "--exclude-standard", "--deduplicate", "-z")
	command.Dir = root

	names, err := command.Output()
	if err != nil {
		return "", nil, err
	}

	selected := make(map[string]struct{})

	for _, name := range strings.Split(strings.TrimRight(string(names), "\x00"), "\x00") {
		if compilerInput(name) {
			selected[name] = struct{}{}
		}
	}

	if err := includeEmbeddedInputs(root, tags, selected); err != nil {
		return "", nil, err
	}

	files := make([]string, 0, len(selected))
	for name := range selected {
		files = append(files, name)
	}

	sort.Strings(files)

	return root, files, nil
}

// includeEmbeddedInputs lets the Go compiler enumerate exact non-Go resources rather than guessing extensions.
func includeEmbeddedInputs(root, tags string, selected map[string]struct{}) error {
	command := exec.Command("go", "list", "-mod=vendor", "-deps", "-tags", tags, "-f", `{{range .EmbedFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}`, "./server", "./contrib/plugins/...", "./pluginapi/v1/testdata/sampleplugin")
	command.Dir = root

	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("enumerate embedded compiler inputs: %w", err)
	}

	for _, path := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if path == "" {
			continue
		}

		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			selected[relative] = struct{}{}
		}
	}

	return nil
}

// compilerInput includes code and dependency locks while excluding runtime configuration and credentials.
func compilerInput(path string) bool {
	if path == "go.mod" || path == "go.sum" || path == "vendor/modules.txt" {
		return true
	}

	switch filepath.Ext(path) {
	case ".go", ".c", ".h", ".s", ".S", ".cc", ".cpp", ".syso":
		return true
	default:
		return false
	}
}

// frame separates each name and content by an unambiguous length prefix.
func frame(digest hash.Hash, value []byte) {
	length := binary.BigEndian.AppendUint64(nil, uint64(len(value)))
	_, _ = digest.Write(length)
	_, _ = digest.Write(value)
}
