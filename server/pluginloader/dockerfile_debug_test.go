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
