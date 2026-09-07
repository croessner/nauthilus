package main

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/openapi"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/getkin/kin-openapi/openapi3"
)

// managementContract loads the shipped management schema without resolving external resources.
func managementContract(t *testing.T) *openapi3.T {
	t.Helper()

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	document, err := loader.LoadFromData(openapi.ManagementYAML())
	requireNoError(t, err)
	requireNoError(t, document.Validate(t.Context()))

	return document
}

func TestManagementOpenAPIMatchesActualRegisteredHooks(t *testing.T) {
	document := managementContract(t)
	registry := pluginregistry.NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: pluginName, Type: config.PluginModuleTypeGo, Path: "/plugins/reputation.so", Config: testConfigMap(t)})
	requireNoError(t, NewPlugin().Register(registrar))
	requireNoError(t, registrar.Commit())

	hooks := registry.Hooks()
	if len(hooks) != 4 {
		t.Fatal("management registration differs from its exact contract")
	}

	for _, component := range hooks {
		descriptor := component.HookDescriptor

		path := document.Paths.Value("/api/v1/custom" + descriptor.Path)
		if path == nil || path.GetOperation(descriptor.Method) == nil {
			t.Fatal("registered management operation missing from OpenAPI")
		}

		operation := path.GetOperation(descriptor.Method)
		if operation.Security == nil || len(*operation.Security) != 1 {
			t.Fatal("management security alternatives broadened")
		}

		if _, ok := (*operation.Security)[0]["backchannelBearer"]; !ok {
			t.Fatal("management allows non-backchannel authority")
		}
	}
}
