package luatest

import "testing"

func TestSubjectRunnerSupportsProductionReturnSignature(t *testing.T) {
	tmpDir := t.TempDir()

	scriptPath := writeTempLuaTestFile(t, tmpDir, "subject.lua", `
function nauthilus_call_subject(request)
    return nauthilus_builtin.SUBJECT_REJECT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)

	runner, err := NewTestRunner(scriptPath, "subject", "")
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected production subject signature to pass, got errors: %v", result.Errors)
	}

	if result.SubjectRejected == nil || !*result.SubjectRejected {
		t.Fatalf("expected subject rejected=true, got %#v", result.SubjectRejected)
	}

	if result.SubjectResult == nil || *result.SubjectResult != 0 {
		t.Fatalf("expected subject result code 0, got %#v", result.SubjectResult)
	}
}

func TestEnvironmentRunnerCapturesProductionReturnSignature(t *testing.T) {
	tmpDir := t.TempDir()

	scriptPath := writeTempLuaTestFile(t, tmpDir, "environment.lua", `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES,
        nauthilus_builtin.ENVIRONMENT_ABORT_YES,
        nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)

	runner, err := NewTestRunner(scriptPath, "environment", "")
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected production environment signature to pass, got errors: %v", result.Errors)
	}

	if result.EnvironmentTriggered == nil || !*result.EnvironmentTriggered {
		t.Fatalf("expected environment trigger=true, got %#v", result.EnvironmentTriggered)
	}

	if result.EnvironmentAbort == nil || !*result.EnvironmentAbort {
		t.Fatalf("expected environment abort=true, got %#v", result.EnvironmentAbort)
	}

	if result.EnvironmentResult == nil || *result.EnvironmentResult != 0 {
		t.Fatalf("expected environment status 0, got %#v", result.EnvironmentResult)
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
