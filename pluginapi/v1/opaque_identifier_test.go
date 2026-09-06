package pluginapi

import (
	"reflect"
	"testing"
)

// TestHostRequiresOpaqueIdentifierTagger freezes the required service without an optional fallback.
func TestHostRequiresOpaqueIdentifierTagger(t *testing.T) {
	if _, exists := reflect.TypeFor[Host]().MethodByName("OpaqueIdentifierTagger"); !exists {
		t.Fatal("Host must provide the opaque identifier tagger service")
	}
}

// TestOpaqueTagValuesHaveNoExportedState keeps the public facade free of mutable material.
func TestOpaqueTagValuesHaveNoExportedState(t *testing.T) {
	tagType := reflect.TypeFor[OpaqueIdentifierTag]()
	for index := range tagType.NumField() {
		if tagType.Field(index).IsExported() {
			t.Fatal("opaque tag exposes mutable state")
		}
	}
}
