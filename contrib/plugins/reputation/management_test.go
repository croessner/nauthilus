package main

import (
	"net/http"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

func TestManagementHooksRequireAdministrativeHostAuthority(t *testing.T) {
	for _, operation := range []string{managementLookup, managementPut, managementDelete, managementAllocation} {
		hook := managementHook{plugin: NewPlugin(), operation: operation}

		descriptor := hook.Descriptor()
		if descriptor.Scope != pluginapi.HookScopeAdmin || descriptor.Auth != pluginapi.HookAuthAdmin || descriptor.MaxBodyBytes != 4096 {
			t.Fatal("management hook lacks bounded administrative admission")
		}

		response, err := hook.Serve(t.Context(), pluginapi.HookRequest{Body: []byte(`{"kind":"ip","subject":"192.0.2.8"}`)})
		requireNoError(t, err)

		if response.StatusCode != http.StatusForbidden {
			t.Fatal("unidentified caller reached management")
		}
	}
}

func TestManagementInputRejectsEnumerationAndCallerActor(t *testing.T) {
	for _, body := range []string{
		`{"kind":"ip","subject":"192.0.2.8","creator":"admin"}`,
		`{"kind":"ip","subject":"192.0.2.8"} {}`,
		`{"kind":"ip","subject":"192.0.2.8","subject":"192.0.2.9"}`,
		`{"kind":"domain","subject":"*"}`,
		`{"kind":"ip","subject":""}`,
	} {
		_, err := decodeManagementInput([]byte(body), managementLookup, testConfig(t))
		if err == nil {
			t.Fatal("invalid management input was accepted")
		}
	}
}
