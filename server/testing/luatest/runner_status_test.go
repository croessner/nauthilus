package luatest

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}

	return path
}

func TestStatusMessageNotContainIsEnforced(t *testing.T) {
	tmpDir := t.TempDir()

	scriptPath := writeTempFile(t, tmpDir, "script.lua", `
function nauthilus_call_action(request)
    nauthilus_builtin.status_message_set("Denied")
    return true
end
`)

	mockPath := writeTempFile(t, tmpDir, "mock.json", `{
  "expected_output": {
    "status_message_not_contain": ["Denied"],
    "error_expected": false
  }
}`)

	runner, err := NewTestRunner(scriptPath, "action", mockPath)
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Success {
		t.Fatalf("expected status_message_not_contain mismatch to fail the test")
	}
}
