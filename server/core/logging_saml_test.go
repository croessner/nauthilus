package core

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

const testExternalSessionID = "external-session-1"

func TestLogLineTemplateIncludesSAMLEntityID(t *testing.T) {
	auth := NewAuthStateFromContextWithDeps(nil, AuthDeps{
		Cfg: &config.FileSettings{
			Server: &config.ServerSection{},
		},
	}).(*AuthState)

	auth.Request.Protocol = config.NewProtocol(definitions.ProtoSAML)
	auth.Request.SAMLEntityID = "https://sp.example.com/metadata"
	auth.Runtime.GUID = "test-guid"

	keyvals := auth.LogLineTemplate("ok", "/login")

	const expectedKey = "saml_entity_id"

	value, ok := findLogValue(keyvals, expectedKey)
	if !ok {
		t.Fatalf("expected log key %q to be present", expectedKey)
	}

	if got := value.(string); got != "https://sp.example.com/metadata" {
		t.Fatalf("unexpected %s value: got=%q", expectedKey, got)
	}
}

func TestLogLineTemplateIncludesExternalSessionWhenSet(t *testing.T) {
	auth := NewAuthStateFromContextWithDeps(nil, AuthDeps{
		Cfg: &config.FileSettings{
			Server: &config.ServerSection{},
		},
	}).(*AuthState)

	auth.Runtime.GUID = "test-guid"
	auth.Request.ExternalSessionID = testExternalSessionID

	keyvals := auth.LogLineTemplate("ok", "/login")

	value, ok := findLogValue(keyvals, definitions.LogKeyExternalSession)
	if !ok {
		t.Fatalf("expected log key %q to be present", definitions.LogKeyExternalSession)
	}

	if got := value.(string); got != testExternalSessionID {
		t.Fatalf("unexpected %s value: got=%q", definitions.LogKeyExternalSession, got)
	}
}

func TestLogLineTemplateOmitsExternalSessionWhenEmpty(t *testing.T) {
	auth := NewAuthStateFromContextWithDeps(nil, AuthDeps{
		Cfg: &config.FileSettings{
			Server: &config.ServerSection{},
		},
	}).(*AuthState)

	auth.Runtime.GUID = "test-guid"

	keyvals := auth.LogLineTemplate("ok", "/login")

	if _, ok := findLogValue(keyvals, definitions.LogKeyExternalSession); ok {
		t.Fatalf("expected log key %q to be omitted", definitions.LogKeyExternalSession)
	}
}

func TestLogLineProcessingTemplateIncludesExternalSessionWhenSet(t *testing.T) {
	auth := NewAuthStateFromContextWithDeps(nil, AuthDeps{
		Cfg: &config.FileSettings{
			Server: &config.ServerSection{},
		},
	}).(*AuthState)

	auth.Runtime.GUID = "test-guid"
	auth.Request.ExternalSessionID = testExternalSessionID

	keyvals := auth.LogLineProcessingTemplate("/login")

	value, ok := findLogValue(keyvals, definitions.LogKeyExternalSession)
	if !ok {
		t.Fatalf("expected log key %q to be present", definitions.LogKeyExternalSession)
	}

	if got := value.(string); got != testExternalSessionID {
		t.Fatalf("unexpected %s value: got=%q", definitions.LogKeyExternalSession, got)
	}
}

func TestLogLineTemplatesIncludeFullStructuredRequestContext(t *testing.T) {
	auth := newStructuredLogAuthState()
	expected := expectedStructuredLogFields()

	tests := []struct {
		name    string
		keyvals []any
	}{
		{name: "final", keyvals: auth.LogLineTemplate("ok", "/login")},
		{name: "processing", keyvals: auth.LogLineProcessingTemplate("/login")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, want := range expected {
				got, ok := findLogValue(tt.keyvals, key)
				if !ok {
					t.Fatalf("expected log key %q to be present", key)
				}

				if got != want {
					t.Fatalf("unexpected %s value: got=%v want=%v", key, got, want)
				}
			}
		})
	}
}

func newStructuredLogAuthState() *AuthState {
	auth := NewAuthStateFromContextWithDeps(nil, AuthDeps{
		Cfg: &config.FileSettings{
			Server: &config.ServerSection{},
		},
	}).(*AuthState)

	auth.Runtime.GUID = "test-guid"
	populateStructuredLogRequest(&auth.Request)

	return auth
}

func populateStructuredLogRequest(request *AuthRequest) {
	request.Protocol = config.NewProtocol("smtp")
	request.OIDCCID = "oidc-client"
	request.XLocalIP = "127.0.0.1"
	request.XPort = "9444"
	request.ClientIP = "203.0.113.10"
	request.XClientPort = "43124"
	request.ClientHost = "client.example.test"
	request.Method = "PLAIN"
	request.Username = "user@example.test"
	request.UserAgent = "grpc-client/1.0"
	request.XClientID = "client-id"
	request.ExternalSessionID = testExternalSessionID
	request.XSSL = "on"
	request.XSSLSessionID = "ssl-session"
	request.XSSLClientVerify = "SUCCESS"
	request.XSSLClientDN = "CN=client,O=Example"
	request.XSSLClientCN = "client"
	request.XSSLIssuer = "CN=issuer"
	request.XSSLClientNotBefore = "2026-01-01T00:00:00Z"
	request.XSSLClientNotAfter = "2026-12-31T23:59:59Z"
	request.XSSLSubjectDN = "CN=subject"
	request.XSSLIssuerDN = "CN=issuer-dn"
	request.XSSLClientSubjectDN = "CN=client-subject"
	request.XSSLClientIssuerDN = "CN=client-issuer"
	request.XSSLProtocol = "TLSv1.3"
	request.XSSLCipher = "TLS_AES_256_GCM_SHA384"
	request.SSLSerial = "serial-1"
	request.SSLFingerprint = "aa:bb:cc"
	request.AuthLoginAttempt = 4
}

func expectedStructuredLogFields() map[string]any {
	return map[string]any{
		definitions.LogKeyOIDCCID:            "oidc-client",
		definitions.LogKeyLocalIP:            "127.0.0.1",
		definitions.LogKeyPort:               "9444",
		definitions.LogKeyClientIP:           "203.0.113.10",
		definitions.LogKeyClientPort:         "43124",
		definitions.LogKeyClientHost:         "client.example.test",
		definitions.LogKeyAuthMethod:         "PLAIN",
		definitions.LogKeyUsername:           "user@example.test",
		definitions.LogKeyUserAgent:          "grpc-client/1.0",
		definitions.LogKeyClientID:           "client-id",
		definitions.LogKeyExternalSession:    testExternalSessionID,
		definitions.LogKeyTLSSecure:          "TLSv1.3",
		definitions.LogKeyTLSCipher:          "TLS_AES_256_GCM_SHA384",
		definitions.LogKeySSL:                "on",
		definitions.LogKeySSLSessionID:       "ssl-session",
		definitions.LogKeySSLClientVerify:    "SUCCESS",
		definitions.LogKeySSLClientDN:        "CN=client,O=Example",
		definitions.LogKeySSLClientCN:        "client",
		definitions.LogKeySSLIssuer:          "CN=issuer",
		definitions.LogKeySSLClientNotBefore: "2026-01-01T00:00:00Z",
		definitions.LogKeySSLClientNotAfter:  "2026-12-31T23:59:59Z",
		definitions.LogKeySSLSubjectDN:       "CN=subject",
		definitions.LogKeySSLIssuerDN:        "CN=issuer-dn",
		definitions.LogKeySSLClientSubjectDN: "CN=client-subject",
		definitions.LogKeySSLClientIssuerDN:  "CN=client-issuer",
		definitions.LogKeySSLSerial:          "serial-1",
		definitions.LogKeySSLFingerprint:     "aa:bb:cc",
		definitions.LogKeyAuthLoginAttempt:   uint(4),
	}
}

func findLogValue(keyvals []any, key string) (any, bool) {
	for i := 0; i+1 < len(keyvals); i += 2 {
		k, ok := keyvals[i].(string)
		if !ok {
			continue
		}

		if k == key {
			return keyvals[i+1], true
		}
	}

	return nil, false
}
