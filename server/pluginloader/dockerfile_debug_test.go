package pluginloader

import (
	"os"
	"strings"
	"testing"
)

// TestDockerfileDebugBuildsPluginsWithServerTags prevents debug image plugin ABI drift.
func TestDockerfileDebugBuildsPluginsWithServerTags(t *testing.T) {
	content, err := os.ReadFile("../../Dockerfile.debug")
	if err != nil {
		t.Fatalf("read Dockerfile.debug: %v", err)
	}

	dockerfile := string(content)
	if !strings.Contains(dockerfile, `cd server && go build -mod=vendor -tags="netgo"`) {
		t.Fatalf("Dockerfile.debug server build must use the netgo tag")
	}

	pluginBuild := `cd contrib/plugins/geoip && go build -mod=vendor -tags="netgo" -buildmode=plugin`
	if !strings.Contains(dockerfile, pluginBuild) {
		t.Fatalf("Dockerfile.debug GeoIP plugin build must use the same netgo tag as the server build")
	}
}

// TestDockerfileStableBuildsPluginCapableImage prevents release images without native plugin support.
func TestDockerfileStableBuildsPluginCapableImage(t *testing.T) {
	content, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}

	dockerfile := string(content)
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

	pluginBuild := `cd contrib/plugins/geoip && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -tags="netgo ${BUILD_TAGS}" -buildmode=plugin`
	if !strings.Contains(dockerfile, pluginBuild) {
		t.Fatalf("Dockerfile GeoIP plugin build must use the same tag set as the server build")
	}

	if !strings.Contains(dockerfile, `COPY --from=builder ["/usr/local/lib/nauthilus/plugins/", "/usr/local/lib/nauthilus/plugins/"]`) {
		t.Fatalf("Dockerfile must copy native plugins into the release image")
	}
}
