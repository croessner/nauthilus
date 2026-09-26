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

package pluginruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/secret"

	jsoniter "github.com/json-iterator/go"
)

const redactionTestPassword = "obligation-redaction-password"

func TestCredentialAccessRequiresCapability(t *testing.T) {
	provider := NewCredentialProvider(context.Background(), secret.New("pw"), nil)

	if _, ok := provider.Password(context.Background()); ok {
		t.Fatal("Password() returned credentials without the credentials capability")
	}

	if concrete, ok := provider.(*credentialProvider); !ok || !concrete.password.IsZero() {
		t.Fatal("unauthorized credential provider retained request password material")
	}
}

// TestCredentialMaterialIsRedactedFromDiagnostics proves granted credentials never render through formatting or encoding.
func TestCredentialMaterialIsRedactedFromDiagnostics(t *testing.T) {
	provider := NewCredentialProvider(
		context.Background(), secret.New(redactionTestPassword), []pluginapi.Capability{pluginapi.CapabilityCredentials},
	)

	credential, ok := provider.Password(context.Background())
	if !ok {
		t.Fatal("Password() did not return granted credentials")
	}

	request := pluginapi.ObligationRequest{
		Snapshot: pluginapi.RequestSnapshot{Username: "redaction-user"}, Credentials: provider,
	}

	for name, rendered := range credentialDiagnosticRenderings(t, request, provider, credential) {
		assertNoPasswordMaterial(t, name, rendered)
	}
}

// credentialDiagnosticRenderings renders credential owners through every common diagnostic sink.
func credentialDiagnosticRenderings(
	t *testing.T,
	request pluginapi.ObligationRequest,
	provider pluginapi.CredentialProvider,
	credential pluginapi.Secret,
) map[string]string {
	t.Helper()

	renderings := make(map[string]string)

	for index, value := range []any{request, &request, provider, credential} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
			renderings[fmt.Sprintf("value %d fmt %s", index, verb)] = fmt.Sprintf(verb, value)
		}

		standard, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(value %d) error = %v", index, err)
		}

		fast, err := jsoniter.ConfigFastest.Marshal(value)
		if err != nil {
			t.Fatalf("jsoniter.Marshal(value %d) error = %v", index, err)
		}

		renderings[fmt.Sprintf("value %d json", index)] = string(standard)
		renderings[fmt.Sprintf("value %d jsoniter", index)] = string(fast)
		renderings[fmt.Sprintf("value %d plugin log field", index)] = renderCredentialLog(t, value)
		renderings[fmt.Sprintf("value %d trace attribute", index)] = traceAttributes([]pluginapi.TraceAttribute{
			{Key: "credential", Value: value},
		})[0].Value.String()
	}

	return renderings
}

// renderCredentialLog renders one plugin log field through the host logger with both structured slog handlers.
func renderCredentialLog(t *testing.T, value any) string {
	t.Helper()

	var output bytes.Buffer

	for _, handler := range []slog.Handler{slog.NewJSONHandler(&output, nil), slog.NewTextHandler(&output, nil)} {
		logger := scopedLogger{logger: slog.New(handler), moduleName: "redaction", scope: "checkpw"}
		logger.Info(t.Context(), "credential", pluginapi.LogField{Key: "credential", Value: value})
	}

	return output.String()
}

// assertNoPasswordMaterial rejects plaintext, byte-list, and hex renderings of the test password.
func assertNoPasswordMaterial(t *testing.T, name, rendered string) {
	t.Helper()

	raw := []byte(redactionTestPassword)
	byteList := strings.Trim(fmt.Sprintf("%d", raw), "[]")

	for _, forbidden := range []string{redactionTestPassword, byteList, fmt.Sprintf("%x", raw)} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("%s leaked credential material: %s", name, rendered)
		}
	}
}

func TestCredentialAccessIsRequestScoped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	provider := NewCredentialProvider(ctx, secret.New("pw"), []pluginapi.Capability{pluginapi.CapabilityCredentials})

	credential, ok := provider.Password(context.Background())
	if !ok {
		t.Fatal("Password() did not return credentials before request context cancellation")
	}

	var got string

	if err := credential.WithBytes(func(value []byte) error {
		got = string(value)

		return nil
	}); err != nil {
		t.Fatalf("WithBytes() error = %v", err)
	}

	if got != "pw" {
		t.Fatalf("Password() bytes = %q, want pw", got)
	}

	cancel()

	if _, ok := provider.Password(context.Background()); ok {
		t.Fatal("Password() returned credentials after request context cancellation")
	}
}
