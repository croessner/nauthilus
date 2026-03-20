package adminui

import (
	"os"
	pathpkg "path/filepath"
	"strings"
	"testing"
)

func TestFrontendTemplatesContainRequiredAdminControls(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		filePath  string
		mustMatch []string
	}{
		{
			name:     "bruteforce partial wiring",
			filePath: "../../../static/templates/partials_bruteforce.html",
			mustMatch: []string{
				`data-api-list-url="{{ .AdminBasePath }}/api/bruteforce/list"`,
				`data-api-free-ip-url="{{ .AdminBasePath }}/api/bruteforce/free-ip"`,
				`data-api-free-user-url="{{ .AdminBasePath }}/api/bruteforce/free-user"`,
				`data-label-free-ip="{{ .AdminBruteForceFreeIP }}"`,
				`data-label-free-user="{{ .AdminBruteForceFreeUser }}"`,
			},
		},
		{
			name:     "clickhouse pagination controls",
			filePath: "../../../static/templates/partials_clickhouse.html",
			mustMatch: []string{
				`data-clickhouse-prev`,
				`data-clickhouse-next`,
				`data-clickhouse-page-size`,
				`id="admin-clickhouse-page-indicator"`,
			},
		},
		{
			name:     "hooktester error panel",
			filePath: "../../../static/templates/partials_hooktester.html",
			mustMatch: []string{
				`id="admin-hooktester-error"`,
				`class="alert alert-error hidden text-xs"`,
				`data-api-send-url="{{ .AdminBasePath }}/api/hooktester/send"`,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content := readAssetFixture(t, tt.filePath)

			for _, needle := range tt.mustMatch {
				if !strings.Contains(content, needle) {
					t.Fatalf("template %s is missing expected snippet %q", tt.filePath, needle)
				}
			}
		})
	}
}

func TestFrontendScriptContainsRequiredInteractionHooks(t *testing.T) {
	t.Parallel()

	content := readAssetFixture(t, "../../../static/js/admin_ui.js")

	requiredSnippets := []string{
		"function bindClickhousePaginationControls(",
		"function updateClickhousePaginationControls()",
		"function normalizeHookTesterEndpoint(",
		`showHookTesterError(errorNode, "Transport error: " + String(err));`,
		`sendButton.classList.add("loading");`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("script is missing expected snippet %q", snippet)
		}
	}
}

func readAssetFixture(t *testing.T, relativePath string) string {
	t.Helper()

	path := pathpkg.Clean(relativePath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("unable to read %s: %v", path, err)
	}

	return string(data)
}
