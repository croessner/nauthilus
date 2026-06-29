// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package luatest

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBundledLuaMySQLBackendUsesPreparedLookupForInjectionUsername(t *testing.T) {
	script := bundledMySQLBackendWrapper(t, "")
	mock := `{
  "context": {
    "username": "alice\" OR 1=1 --",
    "password": "ignored",
    "service": "imap",
    "protocol": "plain",
    "session": "mysql-injection-test",
    "no_auth": true
  },
  "db": {
    "expected_calls": [
      {"method": "open"},
      {"method": "stmt", "query_contains": "WHERE username = ? OR account = ?"},
      {
        "method": "query",
        "query_contains": "WHERE username = ? OR account = ?",
        "columns": ["account", "password", "totp_secret", "uniqueid", "display_name"],
        "rows": []
      }
    ]
  },
  "expected_output": {
    "backend_result": true,
    "backend_return_code": 0,
    "backend_authenticated": false,
    "backend_user_found": false,
    "error_expected": false
  }
}`

	_, result := runLuaMockFixture(t, "bundled_mysql_backend_injection.lua", "backend", script, mock)
	requireLuaMockSuccess(t, result)
}

func TestBundledLuaMySQLBackendMutationsUsePreparedStatements(t *testing.T) {
	script := bundledMySQLBackendWrapper(t, bundledMySQLMutationWrapperSuffix())
	mock := bundledMySQLMutationMock()

	_, result := runLuaMockFixture(t, "bundled_mysql_backend_positive.lua", "backend", script, mock)
	requireLuaMockSuccess(t, result)
}

// bundledMySQLMutationWrapperSuffix exercises bundled backend mutation functions.
func bundledMySQLMutationWrapperSuffix() string {
	return `
local bundled_verify_password = nauthilus_backend_verify_password

function nauthilus_backend_verify_password(request)
    local code, result = bundled_verify_password(request)

    nauthilus_backend_add_totp({
        username = request.username,
        totp_secret = "totp-safe",
    })
    nauthilus_backend_delete_totp(request)
    nauthilus_backend_add_totp_recovery_codes({
        username = request.username,
        totp_recovery_codes = { "recovery-1", "recovery-2" },
    })
    nauthilus_backend_delete_totp_recovery_codes(request)
    nauthilus_backend_get_webauthn_credentials(request)
    nauthilus_backend_save_webauthn_credential({
        username = request.username,
        webauthn_credential = "{\"id\":\"new\"}",
    })
    nauthilus_backend_delete_webauthn_credential({
        username = request.username,
        webauthn_credential = "{\"id\":\"new\"}",
    })
    nauthilus_backend_update_webauthn_credential({
        username = request.username,
        webauthn_credential = "{\"id\":\"new\"}",
        webauthn_old_credential = "{\"id\":\"old\"}",
    })

    return code, result
end`
}

// bundledMySQLMutationMock returns DB expectations for parameterized mutation calls.
func bundledMySQLMutationMock() string {
	return `{
  "context": {
    "username": "alice@example.com",
    "password": "ignored",
    "service": "imap",
    "protocol": "oidc",
    "session": "mysql-positive-test",
    "no_auth": true
  },
  "db": {
    "expected_calls": [
      {"method": "open"},
      {"method": "stmt", "query_contains": "WHERE username = ? OR account = ?"},
      {
        "method": "query",
        "query_contains": "WHERE username = ? OR account = ?",
        "columns": ["account", "password", "totp_secret", "uniqueid", "display_name"],
        "rows": [["alice@example.com", "hash", "", "uid-1", "Alice Example"]]
      },
      {"method": "open"},
      {"method": "stmt", "query_contains": "UPDATE nauthilus SET totp_secret = ? WHERE username = ?"},
      {"method": "exec", "query_contains": "UPDATE nauthilus SET totp_secret = ? WHERE username = ?"},
      {"method": "open"},
      {"method": "stmt", "query_contains": "UPDATE nauthilus SET totp_secret = NULL WHERE username = ?"},
      {"method": "exec", "query_contains": "UPDATE nauthilus SET totp_secret = NULL WHERE username = ?"},
      {"method": "open"},
      {"method": "stmt", "query_contains": "UPDATE nauthilus SET totp_recovery_codes = ? WHERE username = ?"},
      {"method": "exec", "query_contains": "UPDATE nauthilus SET totp_recovery_codes = ? WHERE username = ?"},
      {"method": "open"},
      {"method": "stmt", "query_contains": "UPDATE nauthilus SET totp_recovery_codes = NULL WHERE username = ?"},
      {"method": "exec", "query_contains": "UPDATE nauthilus SET totp_recovery_codes = NULL WHERE username = ?"},
      {"method": "open"},
      {"method": "stmt", "query_contains": "SELECT credential FROM nauthilus_webauthn WHERE username = ?"},
      {"method": "query", "query_contains": "SELECT credential FROM nauthilus_webauthn WHERE username = ?", "columns": ["credential"], "rows": []},
      {"method": "open"},
      {"method": "stmt", "query_contains": "INSERT INTO nauthilus_webauthn (username, credential) VALUES (?, ?)"},
      {"method": "exec", "query_contains": "INSERT INTO nauthilus_webauthn (username, credential) VALUES (?, ?)"},
      {"method": "open"},
      {"method": "stmt", "query_contains": "DELETE FROM nauthilus_webauthn WHERE username = ? AND credential = ?"},
      {"method": "exec", "query_contains": "DELETE FROM nauthilus_webauthn WHERE username = ? AND credential = ?"},
      {"method": "open"},
      {"method": "stmt", "query_contains": "UPDATE nauthilus_webauthn SET credential = ? WHERE username = ? AND credential = ?"},
      {"method": "exec", "query_contains": "UPDATE nauthilus_webauthn SET credential = ? WHERE username = ? AND credential = ?"}
    ]
  },
  "expected_output": {
    "backend_result": true,
    "backend_return_code": 0,
    "backend_authenticated": false,
    "backend_user_found": true,
    "backend_account_field": "account",
    "backend_display_name": "display_name",
    "backend_unique_user_id": "uniqueid",
    "error_expected": false
  }
}`
}

// bundledMySQLBackendWrapper loads the bundled backend and appends optional test code.
func bundledMySQLBackendWrapper(t *testing.T, suffix string) string {
	t.Helper()

	return fmt.Sprintf("dofile(%q)\n%s", bundledMySQLBackendPath(t), suffix)
}

// bundledMySQLBackendPath resolves the repository-local bundled MySQL backend.
func bundledMySQLBackendPath(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current test file path")
	}

	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../lua-plugins.d/backend/backend.lua"))
}
