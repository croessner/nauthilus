package config

import (
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

// PluginPasswordCacheEnabled reports the operator opt-in for a qualified backend.
func PluginPasswordCacheEnabled(cfg File, name string) bool {
	if cfg == nil || cfg.GetPlugins() == nil {
		return false
	}

	moduleName, _, ok := strings.Cut(name, ".")
	if !ok {
		return false
	}

	for _, module := range cfg.GetPlugins().Modules {
		if module.Name == moduleName {
			return module.PositivePasswordCache
		}
	}

	return false
}

// pluginPasswordCacheWarnings identifies cache entries that cannot front plugin backends.
func (f *FileSettings) pluginPasswordCacheWarnings() []string {
	var warnings []string
	if f.Server == nil {
		return warnings
	}

	seenCache := false

	for _, entry := range f.GetServer().GetBackends() {
		if entry == nil {
			continue
		}

		if entry.Get() == definitions.BackendCache {
			seenCache = true
		}

		if seenCache && entry.Get() == definitions.BackendPlugin && !PluginPasswordCacheEnabled(f, entry.GetName()) {
			warnings = append(warnings, "cache before plugin("+entry.GetName()+") has no effect without plugins.modules[].positive_password_cache and the plugin cache declaration")
		}
	}

	return warnings
}

// warnPluginPasswordCache keeps existing configurations loadable while exposing disabled caching.
func (f *FileSettings) warnPluginPasswordCache() {
	for _, warning := range f.pluginPasswordCacheWarnings() {
		safeWarn("msg", warning)
	}
}
