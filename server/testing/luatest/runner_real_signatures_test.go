package luatest

import "testing"

func TestFilterRunnerSupportsProductionReturnSignature(t *testing.T) {
	tmpDir := t.TempDir()

	scriptPath := writeTempLuaTestFile(t, tmpDir, "filter.lua", `
function nauthilus_call_filter(request)
    return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
end
`)

	runner, err := NewTestRunner(scriptPath, "filter", "")
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected production filter signature to pass, got errors: %v", result.Errors)
	}

	if result.FilterAction == nil || !*result.FilterAction {
		t.Fatalf("expected filter action=true, got %#v", result.FilterAction)
	}

	if result.FilterResult == nil || *result.FilterResult != 0 {
		t.Fatalf("expected filter result code 0, got %#v", result.FilterResult)
	}
}

func TestFeatureRunnerCapturesProductionReturnSignature(t *testing.T) {
	tmpDir := t.TempDir()

	scriptPath := writeTempLuaTestFile(t, tmpDir, "feature.lua", `
function nauthilus_call_feature(request)
    return nauthilus_builtin.FEATURE_TRIGGER_YES,
        nauthilus_builtin.FEATURES_ABORT_YES,
        nauthilus_builtin.FEATURE_RESULT_OK
end
`)

	runner, err := NewTestRunner(scriptPath, "feature", "")
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected production feature signature to pass, got errors: %v", result.Errors)
	}

	if result.FeatureResult == nil || !*result.FeatureResult {
		t.Fatalf("expected feature trigger=true, got %#v", result.FeatureResult)
	}

	if result.FeatureAbort == nil || !*result.FeatureAbort {
		t.Fatalf("expected feature abort=true, got %#v", result.FeatureAbort)
	}

	if result.FeatureStatus == nil || *result.FeatureStatus != 0 {
		t.Fatalf("expected feature status 0, got %#v", result.FeatureStatus)
	}
}

func TestBackendRunnerSupportsProductionReturnSignature(t *testing.T) {
	tmpDir := t.TempDir()

	scriptPath := writeTempLuaTestFile(t, tmpDir, "backend.lua", `
local backend_result = require("nauthilus_backend_result")

function nauthilus_backend_verify_password(request)
    local result = backend_result.new()
    result.authenticated = true
    result.user_found = true
    result.account_field = "account"
    result.display_name = "Demo User"
    result.unique_user_id = "uid-1"

    return nauthilus_builtin.BACKEND_RESULT_OK, result
end
`)

	runner, err := NewTestRunner(scriptPath, "backend", "")
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected production backend signature to pass, got errors: %v", result.Errors)
	}

	if result.BackendReturnCode == nil || *result.BackendReturnCode != 0 {
		t.Fatalf("expected backend return code 0, got %#v", result.BackendReturnCode)
	}

	if result.BackendResult == nil || !*result.BackendResult {
		t.Fatalf("expected backend result=true, got %#v", result.BackendResult)
	}

	if result.BackendAuthenticated == nil || !*result.BackendAuthenticated {
		t.Fatalf("expected backend authenticated=true, got %#v", result.BackendAuthenticated)
	}

	if result.BackendAccountField == nil || *result.BackendAccountField != "account" {
		t.Fatalf("expected backend account field 'account', got %#v", result.BackendAccountField)
	}
}
