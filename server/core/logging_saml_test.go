package core

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
)

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
