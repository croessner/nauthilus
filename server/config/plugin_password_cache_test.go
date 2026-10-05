package config

import "testing"

func TestPluginPasswordCacheWarnings(t *testing.T) {
	for _, test := range []struct {
		name    string
		order   []string
		enabled bool
		want    int
	}{
		{name: "default off", order: []string{"cache", "plugin(example.passdb)"}, want: 1},
		{name: "opted in", order: []string{"cache", "plugin(example.passdb)"}, enabled: true},
		{name: "cache after plugin", order: []string{"plugin(example.passdb)", "cache"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &FileSettings{Server: &ServerSection{}, Plugins: &PluginsSection{Modules: []PluginModule{{Name: "example", PositivePasswordCache: test.enabled}}}}
			for _, name := range test.order {
				entry := &Backend{}
				if err := entry.Set(name); err != nil {
					t.Fatal(err)
				}

				cfg.Server.Backends = append(cfg.Server.Backends, entry)
			}

			if got := len(cfg.pluginPasswordCacheWarnings()); got != test.want {
				t.Fatalf("warnings=%d, want %d", got, test.want)
			}
		})
	}
}

func TestPluginPositiveCacheConfigLoad(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		dir := t.TempDir()
		path := pluginConfigArtifactPath(dir)
		writePluginConfigArtifact(t, path)

		cfg, err := loadPluginTestConfig(t, map[string]any{
			pluginConfigKeyAllowedDirs: []string{dir},
			pluginConfigKeyModules:     []map[string]any{{pluginConfigKeyName: pluginConfigModuleName, pluginConfigKeyPath: path, "positive_password_cache": enabled}},
		})
		if err != nil {
			t.Fatal(err)
		}

		if cfg.GetPlugins().Modules[0].PositivePasswordCache != enabled {
			t.Fatal("module cache opt-in did not survive loading")
		}
	}
}
