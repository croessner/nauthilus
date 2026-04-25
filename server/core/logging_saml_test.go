package core

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
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
