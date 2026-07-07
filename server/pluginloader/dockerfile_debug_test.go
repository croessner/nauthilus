package pluginloader

import (
	"os"
	"strings"
	"testing"
)

const (
	dockerfilePluginSignatureBuildArg      = "ARG REQUIRE_PLUGIN_SIGNATURE=false"
	dockerfilePluginBuildTagsArg           = `ARG BUILD_TAGS=""`
	dockerfileBundledNativePluginsArg      = `ARG BUNDLED_NATIVE_PLUGINS="geoip clickhouse haveibeenpwnd"`
	dockerfilePluginSigningSecretMount     = "--mount=type=secret,id=plugin_signing_private_key"
	dockerfilePluginSigningSecretCheck     = "test -s /run/secrets/plugin_signing_private_key"
	dockerfilePluginSigningCommand         = "./server/pluginloader/cmd/nauthilus-plugin-sign sign"
	dockerfileSignatureEnforcementBuildArg = "signature enforcement build arg"
	dockerfileBuildTagsArgLabel            = "plugin build tags arg"
	dockerfileBundledNativePluginsArgLabel = "bundled native plugin list"
	dockerfileBuildKitSigningSecretMount   = "BuildKit signing secret mount"
	dockerfileRequiredPluginSigningSecret  = "required secret check"
	dockerfileRepoOwnedPluginSigner        = "repo-owned plugin signer"
	dockerfileRuntimePluginCopy            = `COPY --from=builder ["/usr/local/lib/nauthilus/plugins/", "/usr/local/lib/nauthilus/plugins/"]`
)

var dockerfileBundledNativePlugins = []string{"geoip", "clickhouse", "haveibeenpwnd"}

// TestDockerfileDebugBuildsPluginsWithServerTags prevents debug image plugin ABI drift.
func TestDockerfileDebugBuildsPluginsWithServerTags(t *testing.T) {
	content, err := os.ReadFile("../../Dockerfile.debug")
	if err != nil {
		t.Fatalf("read Dockerfile.debug: %v", err)
	}

	dockerfile := string(content)
	if !strings.Contains(dockerfile, `# syntax=docker/dockerfile:1.7`) {
		t.Fatalf("Dockerfile.debug must opt into BuildKit syntax for secret-mounted plugin signing")
	}

	if !strings.Contains(dockerfile, `cd server && go build -mod=vendor -tags="netgo ${BUILD_TAGS}"`) {
		t.Fatalf("Dockerfile.debug server build must use the netgo tag set")
	}

	assertDockerfileBuildsBundledPlugins(t, dockerfile, "Dockerfile.debug", "go build -mod=vendor -tags=\"netgo ${BUILD_TAGS}\" -buildmode=plugin")

	expectedSigningSnippets := map[string]string{
		dockerfilePluginSignatureBuildArg:                                   dockerfileSignatureEnforcementBuildArg,
		dockerfilePluginBuildTagsArg:                                        dockerfileBuildTagsArgLabel,
		dockerfileBundledNativePluginsArg:                                   dockerfileBundledNativePluginsArgLabel,
		dockerfilePluginSigningSecretMount:                                  dockerfileBuildKitSigningSecretMount,
		dockerfilePluginSigningSecretCheck:                                  dockerfileRequiredPluginSigningSecret,
		dockerfilePluginSigningCommand:                                      dockerfileRepoOwnedPluginSigner,
		"--artifact /usr/local/lib/nauthilus/plugins/${plugin}.so":          "bundled plugin artifact signing input",
		"--signature /usr/local/lib/nauthilus/plugins/${plugin}.so.minisig": "bundled plugin signature output",
		"chmod 0644 /usr/local/lib/nauthilus/plugins/${plugin}.so":          "runtime-readable bundled plugin artifact",
		"chmod 0644 /usr/local/lib/nauthilus/plugins/${plugin}.so.minisig":  "runtime-readable bundled plugin signature",
		dockerfileRuntimePluginCopy:                                         "runtime plugin copy",
	}

	for expected, label := range expectedSigningSnippets {
		if !strings.Contains(dockerfile, expected) {
			t.Fatalf("Dockerfile.debug must include %s", label)
		}
	}
}

// TestDockerfileStableBuildsPluginCapableImage prevents release images without native plugin support.
func TestDockerfileStableBuildsPluginCapableImage(t *testing.T) {
	content, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}

	dockerfile := string(content)
	if !strings.Contains(dockerfile, `# syntax=docker/dockerfile:1.7`) {
		t.Fatalf("Dockerfile must opt into BuildKit syntax for secret-mounted plugin signing")
	}

	if !strings.Contains(dockerfile, `FROM --platform=$TARGETPLATFORM golang:1.26-alpine3.24 AS builder`) {
		t.Fatalf("Dockerfile builder must run on the target platform so CGO plugin builds are native")
	}

	if !strings.Contains(dockerfile, "ENV CGO_ENABLED=1") {
		t.Fatalf("Dockerfile must enable CGO so plugin.Open is available in release images")
	}

	if strings.Contains(dockerfile, "FROM scratch") {
		t.Fatalf("Dockerfile release runtime must not be scratch because Go plugins require the dynamic runtime")
	}

	serverBuild := `cd server && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -tags="netgo ${BUILD_TAGS}"`
	if !strings.Contains(dockerfile, serverBuild) {
		t.Fatalf("Dockerfile server build must use the netgo tag set")
	}

	assertDockerfileBuildsBundledPlugins(t, dockerfile, "Dockerfile", "GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -tags=\"netgo ${BUILD_TAGS}\" -buildmode=plugin")

	expectedSigningSnippets := map[string]string{
		dockerfilePluginSignatureBuildArg:                                   dockerfileSignatureEnforcementBuildArg,
		dockerfileBundledNativePluginsArg:                                   dockerfileBundledNativePluginsArgLabel,
		dockerfilePluginSigningSecretMount:                                  dockerfileBuildKitSigningSecretMount,
		dockerfilePluginSigningSecretCheck:                                  dockerfileRequiredPluginSigningSecret,
		dockerfilePluginSigningCommand:                                      dockerfileRepoOwnedPluginSigner,
		"--artifact /usr/local/lib/nauthilus/plugins/${plugin}.so":          "bundled plugin artifact signing input",
		"--signature /usr/local/lib/nauthilus/plugins/${plugin}.so.minisig": "bundled plugin signature output",
		"chmod 0644 /usr/local/lib/nauthilus/plugins/${plugin}.so":          "runtime-readable bundled plugin artifact",
		"chmod 0644 /usr/local/lib/nauthilus/plugins/${plugin}.so.minisig":  "runtime-readable bundled plugin signature",
	}

	for expected, label := range expectedSigningSnippets {
		if !strings.Contains(dockerfile, expected) {
			t.Fatalf("Dockerfile must include %s", label)
		}
	}

	if !strings.Contains(dockerfile, dockerfileRuntimePluginCopy) {
		t.Fatalf("Dockerfile must copy native plugins into the release image")
	}
}

// assertDockerfileBuildsBundledPlugins verifies the Dockerfile keeps every bundled plugin on the server tag set.
func assertDockerfileBuildsBundledPlugins(t *testing.T, dockerfile string, dockerfileName string, buildCommand string) {
	t.Helper()

	if !strings.Contains(dockerfile, "for plugin in ${BUNDLED_NATIVE_PLUGINS}; do") {
		t.Fatalf("%s must build bundled native plugins through the explicit plugin list", dockerfileName)
	}

	if !strings.Contains(dockerfile, buildCommand) {
		t.Fatalf("%s plugin build must use the same tag set as the server build", dockerfileName)
	}

	for _, plugin := range dockerfileBundledNativePlugins {
		expectedArtifact := "/usr/local/lib/nauthilus/plugins/" + plugin + ".so"
		expectedSignature := expectedArtifact + ".minisig"

		if !strings.Contains(dockerfile, plugin) {
			t.Fatalf("%s must include bundled native plugin %q", dockerfileName, plugin)
		}

		if strings.Contains(dockerfile, expectedArtifact) || strings.Contains(dockerfile, expectedSignature) {
			t.Fatalf("%s must not hard-code %s outside the bundled plugin loop", dockerfileName, plugin)
		}
	}
}
