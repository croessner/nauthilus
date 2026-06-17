package pluginloader

import (
	"os"
	"strings"
	"testing"
)

const dockerWorkflowPluginSigningSecret = "NAUTHILUS_PLUGIN_SIGNING_KEY_B64"

// TestDockerBuildPushUsesNativeRunnersForDefaultMultiarch prevents slow QEMU-only release image builds.
func TestDockerBuildPushUsesNativeRunnersForDefaultMultiarch(t *testing.T) {
	content, err := os.ReadFile("../../.github/workflows/docker-build-push.yaml")
	if err != nil {
		t.Fatalf("read docker-build-push workflow: %v", err)
	}

	workflow := string(content)
	expectedSnippets := map[string]string{
		"ubuntu-24.04-arm":                                                   "arm64 hosted runner",
		"platform: linux/arm64":                                              "arm64 platform",
		"platform: linux/amd64":                                              "amd64 platform",
		"push-by-digest=true":                                                "per-platform digest push",
		"docker buildx imagetools create":                                    "manifest merge",
		"build_args":                                                         "reusable build args input",
		"build-args: ${{ inputs.build_args }}":                               "docker action build args forwarding",
		dockerWorkflowPluginSigningSecret:                                    "plugin signing secret input",
		"plugin_signing_private_key=PLUGIN_SIGNING_PRIVATE_KEY":              "plugin signing BuildKit secret mapping",
		"index:${annotation#index,manifest:}":                                "index-only annotation normalization",
		"inputs.platforms == 'linux/amd64,linux/arm64'":                      "default multiarch guard",
		"inputs.platforms != 'linux/amd64,linux/arm64'":                      "legacy fallback guard",
		"actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f":   "pinned digest upload",
		"actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3": "pinned digest download",
	}

	for expected, label := range expectedSnippets {
		if !strings.Contains(workflow, expected) {
			t.Fatalf("docker-build-push workflow must include %s", label)
		}
	}
}

// TestDockerStableBuildRequiresSignedPlugins prevents publishing unsigned bundled release plugins.
func TestDockerStableBuildRequiresSignedPlugins(t *testing.T) {
	content, err := os.ReadFile("../../.github/workflows/docker-stable-build.yaml")
	if err != nil {
		t.Fatalf("read docker-stable-build workflow: %v", err)
	}

	workflow := string(content)
	expectedSnippets := map[string]string{
		dockerWorkflowPluginSigningSecret: "required signing key secret",
		"required: true":                  "required workflow secret",
		"build_args: |":                   "stable build args",
		"REQUIRE_PLUGIN_SIGNATURE=true":   "stable signature enforcement build arg",
	}

	for expected, label := range expectedSnippets {
		if !strings.Contains(workflow, expected) {
			t.Fatalf("docker-stable-build workflow must include %s", label)
		}
	}
}

// TestDockerFeaturesBuildRequiresSignedPlugins keeps the debug image verifier-compatible.
func TestDockerFeaturesBuildRequiresSignedPlugins(t *testing.T) {
	content, err := os.ReadFile("../../.github/workflows/docker-features.yaml")
	if err != nil {
		t.Fatalf("read docker-features workflow: %v", err)
	}

	workflow := string(content)
	expectedSnippets := map[string]string{
		"dockerfile_path: Dockerfile.debug": "debug Dockerfile selection",
		"build_args: |":                     "debug build args",
		"REQUIRE_PLUGIN_SIGNATURE=true":     "debug signature enforcement build arg",
	}

	for expected, label := range expectedSnippets {
		if !strings.Contains(workflow, expected) {
			t.Fatalf("docker-features workflow must include %s", label)
		}
	}
}
