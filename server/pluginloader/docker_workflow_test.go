package pluginloader

import (
	"os"
	"strings"
	"testing"
)

// TestDockerBuildPushUsesNativeRunnersForDefaultMultiarch prevents slow QEMU-only release image builds.
func TestDockerBuildPushUsesNativeRunnersForDefaultMultiarch(t *testing.T) {
	content, err := os.ReadFile("../../.github/workflows/docker-build-push.yaml")
	if err != nil {
		t.Fatalf("read docker-build-push workflow: %v", err)
	}

	workflow := string(content)
	expectedSnippets := map[string]string{
		"ubuntu-24.04-arm":                                             "arm64 hosted runner",
		"platform: linux/arm64":                                        "arm64 platform",
		"platform: linux/amd64":                                        "amd64 platform",
		"push-by-digest=true":                                          "per-platform digest push",
		"docker buildx imagetools create":                              "manifest merge",
		"inputs.platforms == 'linux/amd64,linux/arm64'":                "default multiarch guard",
		"inputs.platforms != 'linux/amd64,linux/arm64'":                "legacy fallback guard",
		"actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f":   "pinned digest upload",
		"actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3": "pinned digest download",
	}

	for expected, label := range expectedSnippets {
		if !strings.Contains(workflow, expected) {
			t.Fatalf("docker-build-push workflow must include %s", label)
		}
	}
}
