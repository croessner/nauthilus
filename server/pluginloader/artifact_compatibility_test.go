package pluginloader

import (
	"os"
	"strings"
	"testing"
)

// TestNativeArtifactCompatibilityRejectsStaleMixedAndUnmarkedBundles gates native code before activation.
func TestNativeArtifactCompatibilityRejectsStaleMixedAndUnmarkedBundles(t *testing.T) {
	expected := "nauthilus-native-artifact-v1:" + strings.Repeat("a", 64) + ":end-native-artifact"

	stale := "nauthilus-native-artifact-v1:" + strings.Repeat("b", 64) + ":end-native-artifact"
	for _, test := range []struct {
		name, artifact, host string
		valid                bool
	}{
		{"coherent", expected, expected, true},
		{"stale", stale, expected, false},
		{"mixed", expected + stale, expected, false},
		{"unmarked", "ordinary bytes", expected, false},
		{"unbound host", expected, "", false},
		{"malformed host", expected, "unversioned", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateNativeArtifactIdentity([]byte(test.artifact), test.host); (err == nil) != test.valid {
				t.Fatalf("compatible=%t, want %t", err == nil, test.valid)
			}
		})
	}
}

// TestDockerNativeArtifactsShareBuildIdentity prevents container builds from skipping required preflight metadata.
func TestDockerNativeArtifactsShareBuildIdentity(t *testing.T) {
	for _, path := range []string{"../../Dockerfile", "../../Dockerfile.debug"} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		text := string(content)
		if strings.Count(text, `./scripts/native_artifact_fingerprint -tags="netgo ${BUILD_TAGS}"`) != 2 ||
			strings.Count(text, `-ldflags="${NATIVE_ARTIFACT_LDFLAGS}`) != 2 {
			t.Fatalf("%s does not bind host and plugins to the same source/toolchain identity", path)
		}
	}
}
