package backend

import (
	"github.com/go-playground/validator/v10"
	"testing"
)

func TestPluginPasswordCacheNamespaceCannotCollideWithConfiguredNames(t *testing.T) {
	generated := PluginPasswordCacheName("example.identity")

	legacy := "plugin.example.identity"
	if !IsPluginPasswordCacheName(generated) || IsPluginPasswordCacheName(legacy) {
		t.Fatal("namespace classifier accepts a printable legacy name")
	}

	validate := validator.New()
	if validate.Var(generated, "printascii") == nil {
		t.Fatal("internal namespace is allowed as an LDAP/Lua cache_name")
	}

	if err := validate.Var(legacy, "printascii"); err != nil {
		t.Fatal("legacy name unexpectedly rejected")
	}
}
