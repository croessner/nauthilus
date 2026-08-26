package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/spf13/viper"
)

type missingCodecFormatCase struct {
	name           string
	rootContent    string
	includeContent string
}

type removedPolicyFileCase struct {
	name     string
	content  string
	wantPath string
}

type removedPolicySettingsCase struct {
	name     string
	settings map[string]any
	wantPath string
}

type intermediatePolicyPatchCase struct {
	firstValue any
	finalValue any
	name       string
	firstOp    string
	path       string
	finalPath  string
	wantPath   string
}

var missingCodecFormatCases = []missingCodecFormatCase{
	{
		name:           "properties",
		rootContent:    "includes.required[0]=base.properties\npolicy.api.enabled=true\n",
		includeContent: "policy.api.limits.max_facts=77\n",
	},
	{
		name:           "props",
		rootContent:    "includes.required[0]=base.props\npolicy.api.enabled=true\n",
		includeContent: "policy.api.limits.max_facts=77\n",
	},
	{
		name:           "prop",
		rootContent:    "includes.required[0]=base.prop\npolicy.api.enabled=true\n",
		includeContent: "policy.api.limits.max_facts=77\n",
	},
	{
		name: "hcl",
		rootContent: "includes = { required = [\"base.hcl\"] }\n" +
			"policy { api { enabled = true } }\n",
		includeContent: "policy { api { limits { max_facts = 77 } } }\n",
	},
	{
		name: "tfvars",
		rootContent: "includes = { required = [\"base.tfvars\"] }\n" +
			"policy = { api = { enabled = true } }\n",
		includeContent: "policy = { api = { limits = { max_facts = 77 } } }\n",
	},
	{
		name: "ini",
		rootContent: "[includes]\nrequired[0]=base.ini\n" +
			"[policy.api]\nenabled=true\n",
		includeContent: "[policy.api.limits]\nmax_facts=77\n",
	},
}

var removedPolicyFileCases = []removedPolicyFileCase{
	{
		name: "removed auth policy root",
		content: `auth:
  policy:
    mode: enforce
patch:
  - op: remove
    path: auth
    value: policy
`,
		wantPath: "auth.policy",
	},
	{
		name: "legacy provider stage",
		content: `policy:
  namespaces:
    authn:
      providers:
        risk:
          kind: lua
          stage: pre_auth
patch:
  - op: remove
    path: policy.namespaces.authn.providers.risk
    value: stage
`,
		wantPath: "policy.namespaces.authn.providers.risk.stage",
	},
	{
		name: "legacy provider config ref",
		content: `policy:
  namespaces:
    authn:
      providers:
        risk:
          kind: lua
          config_ref: legacy
patch:
  - op: remove
    path: policy.namespaces.authn.providers.risk
    value: config_ref
`,
		wantPath: "policy.namespaces.authn.providers.risk.config_ref",
	},
	{
		name: "unqualified standard auth",
		content: `policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      mode: enforce
      default_policy: standard_auth
patch:
  - op: replace
    path: policy.targets
    value: []
`,
		wantPath: "policy.targets[0].default_policy",
	},
}

var removedPolicySettingsCases = []removedPolicySettingsCase{
	{
		name: "old root without patches",
		settings: map[string]any{
			"auth": map[string]any{"policy": map[string]any{"mode": "observe"}},
		},
		wantPath: "auth.policy",
	},
	{
		name: "old root removed by first patch",
		settings: map[string]any{
			"auth": map[string]any{"policy": map[string]any{"mode": "observe"}},
			"patch": []any{map[string]any{
				"op": "remove", "path": "auth", "value": "policy",
			}},
		},
		wantPath: "auth.policy",
	},
	{
		name: "case variant old root removed by first patch",
		settings: map[string]any{
			"Auth": map[string]any{"Policy.Mode": "observe"},
			"patch": []any{map[string]any{
				"op": "replace", "path": "Auth", "value": map[string]any{},
			}},
		},
		wantPath: "auth.policy",
	},
	{
		name: "legacy default removed by first patch",
		settings: map[string]any{
			"Policy": map[string]any{"targets": []any{map[string]any{
				"default_policy": "standard_auth",
			}}},
			"patch": []any{map[string]any{
				"op": "replace", "path": "Policy", "value": map[string]any{},
			}},
		},
		wantPath: "policy.targets[0].default_policy",
	},
	{
		name: "old root inside auth array removed by first patch",
		settings: map[string]any{
			"auth": []any{map[string]any{"policy": map[string]any{"mode": "observe"}}},
			"patch": []any{map[string]any{
				"op": "remove", "path": "auth", "value": map[string]any{
					"policy": map[string]any{"mode": "observe"},
				},
			}},
		},
		wantPath: "auth.policy",
	},
}

var intermediatePolicyPatchCases = []intermediatePolicyPatchCase{
	{
		name:       "auth policy payload",
		path:       "auth",
		firstValue: map[string]any{"policy": map[string]any{}},
		finalValue: map[string]any{},
		wantPath:   "auth.policy",
	},
	{
		name:       "auth dotted policy payload",
		path:       "auth",
		firstValue: map[string]any{"Policy.Mode": "observe"},
		finalValue: map[string]any{},
		wantPath:   "auth.policy",
	},
	{
		name:    "auth policy payload wrapped by add",
		firstOp: "add",
		path:    "auth",
		firstValue: map[string]any{
			"policy": map[string]any{"mode": "observe"},
		},
		finalValue: map[string]any{},
		wantPath:   "auth.policy",
	},
	{
		name: "auth policy payload in replacement array",
		path: "auth",
		firstValue: []any{map[string]any{
			"policy": map[string]any{"mode": "observe"},
		}},
		finalValue: map[string]any{},
		wantPath:   "auth.policy",
	},
	{
		name:       "auth policy path",
		path:       "auth.policy",
		firstValue: map[string]any{},
		finalPath:  "auth",
		finalValue: map[string]any{},
		wantPath:   "auth.policy",
	},
	{
		name: "unqualified standard auth",
		path: "policy.targets",
		firstValue: []any{map[string]any{
			"namespace": "authn", "action": "authenticate", "schema": "authn/authenticate/v1",
			"mode": "enforce", "default_policy": "standard_auth",
		}},
		finalValue: []any{},
		wantPath:   "policy.targets[0].default_policy",
	},
	{
		name: "provider type alias",
		path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers",
		firstValue: []any{map[string]any{
			"name": "brute_force", "use": "authn/builtin/brute_force", "type": "builtin.brute_force",
		}},
		finalValue: []any{},
		wantPath:   "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].type",
	},
	{
		name: "provider operations alias",
		path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers",
		firstValue: []any{map[string]any{
			"name": "brute_force", "use": "authn/builtin/brute_force", "operations": []any{"authenticate"},
		}},
		finalValue: []any{},
		wantPath:   "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].operations",
	},
	{
		name: "provider stage alias",
		path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers",
		firstValue: []any{map[string]any{
			"name": "brute_force", "use": "authn/builtin/brute_force", "stage": "pre_auth",
		}},
		finalValue: []any{},
		wantPath:   "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].stage",
	},
	{
		name: "provider config ref alias",
		path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers",
		firstValue: []any{map[string]any{
			"name": "brute_force", "use": "authn/builtin/brute_force", "config_ref": "auth.controls.brute_force",
		}},
		finalValue: []any{},
		wantPath:   "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0].config_ref",
	},
	{
		name:       "provider stage path",
		path:       "policy.namespaces.authn.providers.risk.stage",
		firstValue: "pre_auth",
		finalPath:  "policy",
		finalValue: map[string]any{},
		wantPath:   "policy.namespaces.authn.providers.risk.stage",
	},
	{
		name:       "rule stage alias",
		path:       "policy.namespaces.authn.policy_sets.configured.rules",
		firstValue: []any{map[string]any{"name": "deny", "stage": "pre_auth"}},
		finalValue: []any{},
		wantPath:   "policy.namespaces.authn.policy_sets.configured.rules[0].stage",
	},
	{
		name:       "rule operations alias",
		path:       "policy.namespaces.authn.policy_sets.configured.rules",
		firstValue: []any{map[string]any{"name": "deny", "operations": []any{"authenticate"}}},
		finalValue: []any{},
		wantPath:   "policy.namespaces.authn.policy_sets.configured.rules[0].operations",
	},
	{
		name:       "rule require checks alias",
		path:       "policy.namespaces.authn.policy_sets.configured.rules",
		firstValue: []any{map[string]any{"name": "deny", "require_checks": []any{"brute_force"}}},
		finalValue: []any{},
		wantPath:   "policy.namespaces.authn.policy_sets.configured.rules[0].require_checks",
	},
	{
		name: "stage control alias",
		path: "policy.namespaces.authn.policy_sets.configured.rules",
		firstValue: []any{map[string]any{
			"name": "deny",
			"then": map[string]any{"control": map[string]any{"skip_remaining_stage_checks": true}},
		}},
		finalValue: []any{},
		wantPath:   "policy.namespaces.authn.policy_sets.configured.rules[0].then.control.skip_remaining_stage_checks",
	},
	{
		name: "effect args alias",
		path: "policy.namespaces.authn.policy_sets.configured.rules",
		firstValue: []any{map[string]any{
			"name": "deny",
			"then": map[string]any{"obligations": []any{map[string]any{"id": "authn/audit", "args": map[string]any{}}}},
		}},
		finalValue: []any{},
		wantPath:   "policy.namespaces.authn.policy_sets.configured.rules[0].then.obligations[0].args",
	},
}

func TestConfigLoader_LoadFromFile_MergesIncludesAndPatches(t *testing.T) {
	root := t.TempDir()
	mainPath := writeMergedLoaderFixture(t, root)

	loader := NewConfigLoader("yaml")

	settings, err := loader.LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	assertMergedLoaderSettings(t, settings)
}

func TestConfigLoaderMissingViperCodecFormatsLoadRootAndInclude(t *testing.T) {
	for _, test := range missingCodecFormatCases {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeConfigFile(t, root, "base."+test.name, test.includeContent)
			rootPath := writeConfigFile(t, root, "root."+test.name, test.rootContent)

			settings, err := NewConfigLoader(test.name).LoadFromFile(rootPath)
			if err != nil {
				t.Fatalf("LoadFromFile() error = %v", err)
			}

			policySettings := requireMapSetting(t, settings, "policy", "policy")
			apiSettings := requireMapSetting(t, policySettings, "api", "policy.api")
			limits := requireMapSetting(t, apiSettings, "limits", "policy.api.limits")

			if enabled, ok := apiSettings["enabled"].(bool); !ok || !enabled {
				t.Fatalf("policy.api.enabled = %#v, want true", apiSettings["enabled"])
			}

			if got, want := requireInt(t, limits["max_facts"]), 77; got != want {
				t.Fatalf("policy.api.limits.max_facts = %d, want %d", got, want)
			}
		})
	}
}

func TestConfigLoaderBoundedDecoderPreservesFormatAndPath(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "duplicate.properties", "policy.api.enabled=true\npolicy.api.enabled=false\n")

	_, err := NewConfigLoader("properties").LoadFromFile(path)
	if err == nil {
		t.Fatal("LoadFromFile() error = nil, want duplicate-path rejection")
	}

	for _, expected := range []string{"as properties", "policy.api.enabled", "duplicate configuration path"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("LoadFromFile() error = %q, want %q", err, expected)
		}
	}
}

func TestConfigLoaderPreservesStructurallySignificantEmptyNodesForHardCutRejection(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "empty-shapes.yaml", `auth:
  policy: {}
policy:
  policy_sets: {}
`)

	rawSettings, err := readBoundedConfigSettings(path, "yaml")
	if err != nil {
		t.Fatalf("readBoundedConfigSettings() error = %v", err)
	}

	if _, exists := rawSettings["auth"]; !exists {
		t.Fatalf("bounded decoder dropped auth root: %#v", rawSettings)
	}

	_, err = NewConfigLoader("yaml").LoadFromFile(path)
	if err == nil {
		t.Fatal("LoadFromFile() error = nil, want empty removed-root rejection")
	}

	if !strings.Contains(err.Error(), "auth.policy") {
		t.Fatalf("LoadFromFile() error = %q, want auth.policy path", err)
	}
}

func TestViperConfigReaderDecodesTheExactBytesAcceptedByBoundedParsing(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "root.yaml", `policy:
  api:
    enabled: false
`)
	reader := &ViperConfigReader{
		configType: "yaml",
		afterSnapshot: func(string) {
			if err := os.WriteFile(path, []byte(`policy:
  api:
    enabled: true
`), 0o600); err != nil {
				t.Fatalf("mutate config after bounded parse: %v", err)
			}
		},
	}

	settings, err := reader.Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	policySettings := requireMapSetting(t, settings, "policy", "policy")

	apiSettings := requireMapSetting(t, policySettings, "api", "policy.api")
	if enabled, ok := apiSettings["enabled"].(bool); !ok || enabled {
		t.Fatalf("policy.api.enabled = %#v, want false from the accepted byte snapshot", apiSettings["enabled"])
	}
}

func TestConfigLoaderUsesOneAcceptedSnapshotForRootAndEachInclude(t *testing.T) {
	directory := t.TempDir()
	includePath := writeConfigFile(t, directory, "base.yaml", `policy:
  api:
    limits:
      max_facts: 77
`)
	rootPath := writeConfigFile(t, directory, "root.yaml", `includes:
  required:
    - base.yaml
policy:
  api:
    enabled: false
`)
	reader := &ViperConfigReader{
		configType: "yaml",
		afterSnapshot: func(path string) {
			var replacement string

			switch path {
			case rootPath:
				replacement = "policy:\n  api:\n    enabled: true\n"
			case includePath:
				replacement = "policy:\n  api:\n    limits:\n      max_facts: 999\n"
			default:
				t.Fatalf("unexpected config snapshot path %q", path)
			}

			if err := os.WriteFile(path, []byte(replacement), 0o600); err != nil {
				t.Fatalf("mutate config after snapshot: %v", err)
			}
		},
	}
	loader := NewConfigLoader("yaml")
	loader.reader = reader

	settings, err := loader.LoadFromFile(rootPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	policySettings := requireMapSetting(t, settings, "policy", "policy")
	apiSettings := requireMapSetting(t, policySettings, "api", "policy.api")

	limits := requireMapSetting(t, apiSettings, "limits", "policy.api.limits")
	if enabled, ok := apiSettings["enabled"].(bool); !ok || enabled {
		t.Fatalf("policy.api.enabled = %#v, want false from root snapshot", apiSettings["enabled"])
	}

	if got := requireInt(t, limits["max_facts"]); got != 77 {
		t.Fatalf("policy.api.limits.max_facts = %d, want 77 from include snapshot", got)
	}
}

func TestConfigLoaderRejectsRemovedPolicyShapesBeforeRootPatches(t *testing.T) {
	for _, test := range removedPolicyFileCases {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfigFile(t, t.TempDir(), "root.yaml", test.content)

			_, err := NewConfigLoader("yaml").LoadFromFile(path)
			if err == nil {
				t.Fatal("LoadFromFile() error = nil, want pre-patch hard-cut rejection")
			}

			if !strings.Contains(err.Error(), test.wantPath) {
				t.Fatalf("LoadFromFile() error = %q, want path %q", err, test.wantPath)
			}
		})
	}
}

func TestConfigLoaderLoadRejectsInitialRemovedPolicyShapes(t *testing.T) {
	for _, test := range removedPolicySettingsCases {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewConfigLoader("yaml").Load("root.yaml", test.settings)
			if err == nil {
				t.Fatal("Load() error = nil, want initial hard-cut rejection")
			}

			if !strings.Contains(err.Error(), test.wantPath) {
				t.Fatalf("Load() error = %q, want path %q", err, test.wantPath)
			}
		})
	}
}

func TestConfigLoaderLoadRejectsRemovedPolicyAliasAfterExpansion(t *testing.T) {
	t.Setenv("NAUTHILUS_TEST_DEFAULT_POLICY", "standard_auth")

	settings := map[string]any{
		"policy": map[string]any{"targets": []any{map[string]any{
			"default_policy": "${NAUTHILUS_TEST_DEFAULT_POLICY}",
		}}},
	}

	_, err := NewConfigLoader("yaml").Load("root.yaml", settings)
	if err == nil {
		t.Fatal("Load() error = nil, want post-expansion hard-cut rejection")
	}

	if !strings.Contains(err.Error(), "policy.targets[0].default_policy") {
		t.Fatalf("Load() error = %q, want expanded default_policy path", err)
	}
}

func TestConfigLoaderLoadRejectsMalformedDottedPolicyRoots(t *testing.T) {
	for _, key := range []string{"policy.", "Policy..api"} {
		t.Run(key, func(t *testing.T) {
			settings := map[string]any{
				key: map[string]any{},
				"patch": []any{map[string]any{
					"op": "remove", "path": key,
				}},
			}

			_, err := NewConfigLoader("yaml").Load("root.yaml", settings)
			if err == nil {
				t.Fatal("Load() error = nil, want malformed dotted policy-root rejection")
			}

			if !strings.Contains(err.Error(), "empty dotted-path") {
				t.Fatalf("Load() error = %q, want empty dotted-path problem", err)
			}
		})
	}
}

func TestConfigLoaderRejectsRemovedPolicyRootInIncludeBeforeRootPatch(t *testing.T) {
	directory := t.TempDir()
	writeConfigFile(t, directory, "legacy.yaml", `auth:
  policy:
    mode: enforce
`)
	rootPath := writeConfigFile(t, directory, "root.yaml", `includes:
  required:
    - legacy.yaml
patch:
  - op: remove
    path: auth
    value: policy
`)

	_, err := NewConfigLoader("yaml").LoadFromFile(rootPath)
	if err == nil {
		t.Fatal("LoadFromFile() error = nil, want included document hard-cut rejection")
	}

	for _, expected := range []string{"legacy.yaml", "auth.policy"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("LoadFromFile() error = %q, want %q", err, expected)
		}
	}
}

func TestConfigLoaderRejectsRemovedPolicyRootInsideRawAuthArrayBeforePatch(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "root.yaml", `auth:
  - policy:
      mode: observe
patch:
  - op: remove
    path: auth
    value:
      policy:
        mode: observe
`)

	_, err := NewConfigLoader("yaml").LoadFromFile(path)
	if err == nil {
		t.Fatal("LoadFromFile() error = nil, want auth-array old-root rejection")
	}

	if !strings.Contains(err.Error(), "auth.policy") {
		t.Fatalf("LoadFromFile() error = %q, want auth.policy path", err)
	}
}

func TestConfigLoaderRejectsRemovedPolicyShapesIntroducedByIntermediatePatch(t *testing.T) {
	for _, test := range intermediatePolicyPatchCases {
		t.Run(test.name, func(t *testing.T) {
			firstOp := test.firstOp
			if firstOp == "" {
				firstOp = "replace"
			}

			finalPath := test.finalPath
			if finalPath == "" {
				finalPath = test.path
			}

			document := map[string]any{"patch": []any{
				map[string]any{"op": firstOp, "path": test.path, "value": test.firstValue},
				map[string]any{"op": "replace", "path": finalPath, "value": test.finalValue},
			}}

			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("marshal patch fixture: %v", err)
			}

			path := writeConfigFile(t, t.TempDir(), "root.json", string(encoded))

			_, err = NewConfigLoader("json").LoadFromFile(path)
			if err == nil {
				t.Fatal("LoadFromFile() error = nil, want intermediate patch hard-cut rejection")
			}

			if !strings.Contains(err.Error(), test.wantPath) {
				t.Fatalf("LoadFromFile() error = %q, want path %q", err, test.wantPath)
			}
		})
	}
}

func TestViperConfigReaderRejectsExactAndDottedPolicyRootDeclarations(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		content string
	}{
		{
			name:   "yaml",
			format: "yaml",
			content: "policy:\n  api:\n    enabled: false\n" +
				"\"Policy.api.enabled\": true\n",
		},
		{
			name:    "json",
			format:  "json",
			content: `{"policy":{"api":{"enabled":false}},"Policy.api.enabled":true}`,
		},
		{
			name:   "toml",
			format: "toml",
			content: "policy = { api = { enabled = false } }\n" +
				"\"Policy.api.enabled\" = true\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfigFile(t, t.TempDir(), "root."+test.format, test.content)

			_, err := (&ViperConfigReader{configType: test.format}).Read(path)
			if err == nil {
				t.Fatal("Read() error = nil, want normalized duplicate policy-root rejection")
			}

			if !strings.Contains(err.Error(), "policy") || !strings.Contains(err.Error(), "exactly once") {
				t.Fatalf("Read() error = %q, want normalized duplicate policy-root problem", err)
			}
		})
	}
}

func TestViperConfigReaderRejectsConflictingDottedPolicyDeclarations(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "same normalized path",
			content: "\"policy.api.enabled\": false\n" +
				"\"Policy.Api.Enabled\": true\n",
		},
		{
			name: "ancestor and descendant",
			content: "\"policy.api\": {}\n" +
				"\"Policy.Api.Enabled\": true\n",
		},
		{
			name: "case variant ancestor and descendant",
			content: "\"policy.api\":\n  enabled: false\n" +
				"\"Policy.API.enabled\": true\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfigFile(t, t.TempDir(), "root.yaml", test.content)

			_, err := (&ViperConfigReader{configType: "yaml"}).Read(path)
			if err == nil {
				t.Fatal("Read() error = nil, want conflicting dotted policy declaration rejection")
			}

			if !strings.Contains(err.Error(), "policy") || !strings.Contains(err.Error(), "exactly once") {
				t.Fatalf("Read() error = %q, want normalized policy declaration conflict", err)
			}
		})
	}
}

func TestViperConfigReaderRejectsEmptyDottedPolicyAliases(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "null", value: "null"},
		{name: "empty object", value: "{}"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := "\"Policy.namespaces.authn.providers.risk.stage\": " + test.value + "\n"
			path := writeConfigFile(t, t.TempDir(), "root.yaml", content)

			_, err := (&ViperConfigReader{configType: "yaml"}).Read(path)
			if err == nil {
				t.Fatal("Read() error = nil, want empty dotted policy alias rejection")
			}

			if !strings.Contains(err.Error(), "policy.namespaces.authn.providers.risk.stage") {
				t.Fatalf("Read() error = %q, want legacy stage path", err)
			}
		})
	}
}

func TestViperConfigReaderAllowsDistinctDottedPolicyDeclarations(t *testing.T) {
	for _, format := range policyconfig.SupportedFormats() {
		t.Run(format, func(t *testing.T) {
			path := writeConfigFile(t, t.TempDir(), "root."+format, distinctDottedPolicyDocument(format))

			settings, err := (&ViperConfigReader{configType: format}).Read(path)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}

			policySettings := requireMapSetting(t, settings, "policy", "policy")
			apiSettings := requireMapSetting(t, policySettings, "api", "policy.api")

			limits := requireMapSetting(t, apiSettings, "limits", "policy.api.limits")
			if got := fmt.Sprint(limits["max_facts"]); got != "77" {
				t.Fatalf("policy.api.limits.max_facts = %q, want 77", got)
			}
		})
	}
}

func TestViperConfigReaderRejectsCaseVariantRemovedRootInEverySupportedFormat(t *testing.T) {
	assertEverySupportedFormatRejected(t, caseVariantRemovedRootDocument, "auth.policy")
}

func TestViperConfigReaderRejectsLiteralDottedRemovedRootBeforeViperNormalization(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		content string
	}{
		{name: "yaml empty", format: "yaml", content: "policy: {}\n\"auth.policy\": {}\n"},
		{name: "yaml null case variant", format: "yaml", content: "policy: {}\n\"Auth.Policy\": null\n"},
		{name: "json empty", format: "json", content: `{"policy":{},"auth.policy":{}}`},
		{name: "json null case variant", format: "json", content: `{"policy":{},"Auth.Policy":null}`},
		{name: "toml empty", format: "toml", content: "policy = {}\n\"auth.policy\" = {}\n"},
		{name: "toml case variant", format: "toml", content: "policy = {}\n\"Auth.Policy\" = { mode = \"observe\" }\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfigFile(t, t.TempDir(), "root."+test.format, test.content)

			_, err := (&ViperConfigReader{configType: test.format}).Read(path)
			if err == nil {
				t.Fatal("Read() error = nil, want literal dotted removed-root rejection")
			}

			if !strings.Contains(err.Error(), "auth.policy") {
				t.Fatalf("Read() error = %q, want auth.policy path", err)
			}
		})
	}
}

func TestViperConfigReaderRejectsDottedRemovedRootDescendantsInEverySupportedFormat(t *testing.T) {
	assertEverySupportedFormatRejected(t, dottedRemovedRootDescendantDocument, "auth.policy")
}

func TestViperConfigReaderRejectsDottedPolicyAliasesInEverySupportedFormat(t *testing.T) {
	assertEverySupportedFormatRejected(t, dottedRemovedPolicyAliasDocument, "policy.targets[0].default_policy")
}

// assertEverySupportedFormatRejected verifies one rendered invalid shape across all bounded decoders.
func assertEverySupportedFormatRejected(t *testing.T, render func(string) string, wantPath string) {
	t.Helper()

	for _, format := range policyconfig.SupportedFormats() {
		t.Run(format, func(t *testing.T) {
			path := writeConfigFile(t, t.TempDir(), "root."+format, render(format))

			_, err := (&ViperConfigReader{configType: format}).Read(path)
			if err == nil {
				t.Fatal("Read() error = nil, want hard-cut rejection")
			}

			if !strings.Contains(err.Error(), wantPath) {
				t.Fatalf("Read() error = %q, want path %q", err, wantPath)
			}
		})
	}
}

// caseVariantRemovedRootDocument renders one case-variant old root in each bounded format.
func caseVariantRemovedRootDocument(format string) string {
	switch format {
	case "yaml", "yml":
		return "policy: {}\nAuth:\n  Policy: null\n"
	case "json":
		return `{"policy":{},"Auth":{"Policy":null}}`
	case "toml":
		return "policy = {}\n[Auth.Policy]\nmode = \"observe\"\n"
	case "hcl":
		return "policy {}\nAuth { Policy { mode = \"observe\" } }\n"
	case "tfvars":
		return "policy = {}\nAuth = { Policy = { mode = \"observe\" } }\n"
	case "ini":
		return "[policy.api]\nenabled=false\n[Auth.Policy]\nmode=observe\n"
	default:
		return "policy.api.enabled=false\nAuth.Policy.mode=observe\n"
	}
}

// dottedRemovedRootDescendantDocument renders an old auth policy descendant in each bounded format.
func dottedRemovedRootDescendantDocument(format string) string {
	switch format {
	case "yaml", "yml":
		return "auth:\n  \"Policy.Mode\": observe\n"
	case "json":
		return `{"auth":{"Policy.Mode":"observe"}}`
	case "toml":
		return "[auth]\n\"Policy.Mode\" = \"observe\"\n"
	case "hcl", "tfvars":
		return "auth = { \"Policy.Mode\" = \"observe\" }\n"
	case "ini":
		return "[auth]\nPolicy.Mode=observe\n"
	default:
		return "auth.Policy.Mode=observe\n"
	}
}

// dottedRemovedPolicyAliasDocument renders a case-variant policy descendant in each bounded format.
func dottedRemovedPolicyAliasDocument(format string) string {
	switch format {
	case "yaml", "yml":
		return "\"Policy.targets.0.default_policy\": standard_auth\n"
	case "json":
		return `{"Policy.targets.0.default_policy":"standard_auth"}`
	case "toml":
		return "\"Policy.targets.0.default_policy\" = \"standard_auth\"\n"
	case "hcl", "tfvars":
		return "Policy = { targets = [{ default_policy = \"standard_auth\" }] }\n"
	case "ini":
		return "[Policy.targets.0]\ndefault_policy=standard_auth\n"
	default:
		return "Policy.targets.0.default_policy=standard_auth\n"
	}
}

// distinctDottedPolicyDocument renders non-conflicting policy fields for every bounded format.
func distinctDottedPolicyDocument(format string) string {
	switch format {
	case "yaml", "yml":
		return "\"policy.api.enabled\": true\n\"Policy.Api.Limits.Max_Facts\": 77\n"
	case "json":
		return `{"policy.api.enabled":true,"Policy.Api.Limits.Max_Facts":77}`
	case "toml":
		return "\"policy.api.enabled\" = true\n\"Policy.Api.Limits.Max_Facts\" = 77\n"
	case "hcl", "tfvars":
		return "policy = { api = { enabled = true, limits = { max_facts = 77 } } }\n"
	case "ini":
		return "[policy.api]\nenabled=true\n[Policy.Api.Limits]\nMax_Facts=77\n"
	default:
		return "policy.api.enabled=true\nPolicy.Api.Limits.Max_Facts=77\n"
	}
}

// writeMergedLoaderFixture writes the include and patch fixture files.
func writeMergedLoaderFixture(t *testing.T, root string) string {
	t.Helper()

	writeConfigFile(t, root, "base.yaml", `auth:
  backends:
    ldap:
      default:
        lookup_pool_size: 5
`)

	writeConfigFile(t, root, "dev.yaml", `patch:
  - op: add
    path: auth.backends.ldap.search
    value:
      protocol: imap
      cache_name: imap
`)

	mainPath := writeConfigFile(t, root, "main.yaml", `env: dev
includes:
  required:
    - base.yaml
  env:
    dev:
      optional:
        - dev.yaml
auth:
  backends:
    ldap:
      default:
        lookup_pool_size: 10
`)

	return mainPath
}

// assertMergedLoaderSettings verifies merged config values and stripped control keys.
func assertMergedLoaderSettings(t *testing.T, settings map[string]any) {
	t.Helper()

	auth := requireMapSetting(t, settings, "auth", "auth")
	backends := requireMapSetting(t, auth, "backends", "auth.backends")
	ldap := requireMapSetting(t, backends, "ldap", "auth.backends.ldap")

	assertMergedLoaderDefault(t, ldap)
	assertMergedLoaderSearch(t, ldap)
	assertLoaderControlKeysStripped(t, settings)
}

// assertMergedLoaderDefault verifies that main config values override includes.
func assertMergedLoaderDefault(t *testing.T, ldap map[string]any) {
	t.Helper()

	defaultConfig := requireMapSetting(t, ldap, "default", "auth.backends.ldap.default")
	if got := requireInt(t, defaultConfig["lookup_pool_size"]); got != 10 {
		t.Fatalf("expected lookup_pool_size 10, got %d", got)
	}
}

// assertMergedLoaderSearch verifies the patch-added LDAP search entry.
func assertMergedLoaderSearch(t *testing.T, ldap map[string]any) {
	t.Helper()

	search, ok := ldap["search"].([]any)
	if !ok {
		t.Fatalf("expected ldap.search slice, got %T", ldap["search"])
	}

	if len(search) != 1 {
		t.Fatalf("expected 1 ldap.search entry, got %d", len(search))
	}

	entry, ok := search[0].(map[string]any)
	if !ok {
		t.Fatalf("expected ldap.search entry map, got %T", search[0])
	}

	if entry["protocol"] != "imap" {
		t.Fatalf("expected protocol imap, got %v", entry["protocol"])
	}
}

// assertLoaderControlKeysStripped verifies that loader-only keys are removed after merging.
func assertLoaderControlKeysStripped(t *testing.T, settings map[string]any) {
	t.Helper()

	if _, ok := settings[includeKey]; ok {
		t.Fatal("includes should be stripped from merged settings")
	}

	if _, ok := settings[patchKey]; ok {
		t.Fatal("patch should be stripped from merged settings")
	}

	if _, ok := settings[envKey]; ok {
		t.Fatal("env should be stripped from merged settings")
	}
}

// requireMapSetting returns a nested settings map or fails the test with path context.
func requireMapSetting(t *testing.T, settings map[string]any, key string, path string) map[string]any {
	t.Helper()

	value, ok := settings[key].(map[string]any)
	if !ok {
		t.Fatalf("expected %s map, got %T", path, settings[key])
	}

	return value
}

func TestConfigLoader_LoadFromFile_OptionalMissing(t *testing.T) {
	root := t.TempDir()

	mainPath := writeConfigFile(t, root, "main.yaml", `includes:
  optional:
    - missing.yaml
runtime:
  instance_name: optional
`)

	loader := NewConfigLoader("yaml")

	settings, err := loader.LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if _, ok := settings["runtime"]; !ok {
		t.Fatal("expected runtime settings in merged config")
	}
}

// TestConfigLoader_LoadFromFile_EnvFromProcessEnvironment proves isolated environment selection.
func TestConfigLoader_LoadFromFile_EnvFromProcessEnvironment(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setDefaultEnvVars()

	t.Setenv("NAUTHILUS_ENV", "dev")

	root := t.TempDir()

	writeConfigFile(t, root, "dev.yaml", `runtime:
  instance_name: from-env
`)

	mainPath := writeConfigFile(t, root, "main.yaml", `includes:
  env:
    dev:
      optional:
        - dev.yaml
`)

	loader := NewConfigLoader("yaml")

	settings, err := loader.LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	runtimeSettings, ok := settings["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("expected runtime map, got %T", settings["runtime"])
	}

	if runtimeSettings["instance_name"] != "from-env" {
		t.Fatalf("expected instance_name from-env, got %v", runtimeSettings["instance_name"])
	}
}

func TestConfigLoader_LoadFromFile_RequiredMissing(t *testing.T) {
	root := t.TempDir()

	mainPath := writeConfigFile(t, root, "main.yaml", `includes:
  required:
    - missing.yaml
runtime:
  instance_name: required
`)

	loader := NewConfigLoader("yaml")

	if _, err := loader.LoadFromFile(mainPath); err == nil {
		t.Fatal("expected error for missing required include")
	}
}

func TestConfigLoader_LoadFromFile_IncludeSupportsRootExtensionsWithAnchors(t *testing.T) {
	root := t.TempDir()

	writeConfigFile(t, root, "aliases.yaml", `x-claim-email: &x-claim-email
  claim: "email"
  attribute: "mail;x-hidden"
  type: "string"
x-oc-mappings:
  mappings:
    - *x-claim-email
`)

	mainPath := writeConfigFile(t, root, "main.yaml", `includes:
  required:
    - aliases.yaml
runtime:
  instance_name: include-anchors
`)

	loader := NewConfigLoader("yaml")

	settings, err := loader.LoadFromFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	claimEmail, ok := settings["x-claim-email"].(map[string]any)
	if !ok {
		t.Fatalf("expected x-claim-email map, got %T", settings["x-claim-email"])
	}

	if claimEmail["claim"] != "email" {
		t.Fatalf("expected x-claim-email.claim email, got %v", claimEmail["claim"])
	}

	mappingsRoot, ok := settings["x-oc-mappings"].(map[string]any)
	if !ok {
		t.Fatalf("expected x-oc-mappings map, got %T", settings["x-oc-mappings"])
	}

	mappings, ok := mappingsRoot["mappings"].([]any)
	if !ok {
		t.Fatalf("expected x-oc-mappings.mappings slice, got %T", mappingsRoot["mappings"])
	}

	if len(mappings) != 1 {
		t.Fatalf("expected one mapping entry, got %d", len(mappings))
	}

	firstMapping, ok := mappings[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first mapping as map, got %T", mappings[0])
	}

	if firstMapping["claim"] != "email" {
		t.Fatalf("expected first mapping claim email, got %v", firstMapping["claim"])
	}
}

func writeConfigFile(t *testing.T, root string, name string, content string) string {
	t.Helper()

	path := filepath.Join(root, name)

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config %s: %v", name, err)
	}

	return path
}

func requireInt(t *testing.T, value any) int {
	t.Helper()

	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		t.Fatalf("expected numeric value, got %T", value)
	}

	return 0
}
