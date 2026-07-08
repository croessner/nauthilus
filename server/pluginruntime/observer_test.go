package pluginruntime

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
)

const (
	testDebugModuleLookup = "lookup"
	testDebugModuleMail   = "mail"
)

func TestOperationalObserverLogsBoundedPluginCallFields(t *testing.T) {
	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	observer := NewOperationalObserver(logger, WithOperationalObserverMetrics(nil))

	observer.ObservePluginCall(CallRecord{
		Err:            errors.New("database failed with password=secret"),
		Duration:       25 * time.Millisecond,
		ModuleName:     "geoip",
		ComponentName:  "environment",
		ExtensionPoint: "environment_source",
		Method:         "Evaluate",
	})

	line := buf.String()
	if !strings.Contains(line, `"plugin_module":"geoip"`) ||
		!strings.Contains(line, `"plugin_component":"environment"`) ||
		!strings.Contains(line, `"plugin_result":"error"`) {
		t.Fatalf("observer log did not include bounded plugin fields: %s", line)
	}

	if strings.Contains(line, "password=secret") || strings.Contains(line, "database failed") {
		t.Fatalf("observer log leaked raw plugin error: %s", line)
	}
}

func TestHostLoggerDebugRequiresPluginSelector(t *testing.T) {
	var buf bytes.Buffer

	host := NewHost(
		WithLogger(testDebugLogger(&buf)),
		WithDebugConfig(pluginDebugConfig(t)),
		WithDebugRegistry(pluginDebugRegistry(t, testRuntimeModuleName, testDebugModuleLookup)),
	)

	host.moduleHost(testRuntimeModuleName).Logger(testDebugModuleLookup).Debug(t.Context(), "plugin debug")

	if got := buf.String(); got != "" {
		t.Fatalf("Debug() logged without matching plugin selector: %s", got)
	}
}

func TestHostLoggerDebugHonorsPluginSelectors(t *testing.T) {
	tests := []struct {
		name      string
		selectors []string
	}{
		{name: "all", selectors: []string{definitions.DbgAllName}},
		{name: "plugin", selectors: []string{"plugin"}},
		{name: "module", selectors: []string{"plugin." + testRuntimeModuleName}},
		{name: "local", selectors: []string{"plugin." + testRuntimeModuleName + "." + testDebugModuleLookup}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			host := NewHost(
				WithLogger(testDebugLogger(&buf)),
				WithDebugConfig(pluginDebugConfig(t, tt.selectors...)),
				WithDebugRegistry(pluginDebugRegistry(t, testRuntimeModuleName, testDebugModuleLookup)),
			)

			host.moduleHost(testRuntimeModuleName).Logger(testDebugModuleLookup).Debug(t.Context(), "plugin debug")

			line := buf.String()
			if !strings.Contains(line, `"plugin_module":"`+testRuntimeModuleName+`"`) ||
				!strings.Contains(line, `"plugin_scope":"`+testDebugModuleLookup+`"`) ||
				!strings.Contains(line, `"debug_module":"plugin.`+testRuntimeModuleName+`.`+testDebugModuleLookup+`"`) {
				t.Fatalf("Debug() line = %s", line)
			}
		})
	}
}

func TestHostLoggerDebugLocalSelectorDoesNotEnableOtherSubmodule(t *testing.T) {
	var buf bytes.Buffer

	host := NewHost(
		WithLogger(testDebugLogger(&buf)),
		WithDebugConfig(pluginDebugConfig(t, "plugin."+testRuntimeModuleName+"."+testDebugModuleLookup)),
		WithDebugRegistry(pluginDebugRegistry(t, testRuntimeModuleName, testDebugModuleLookup, testDebugModuleMail)),
	)
	moduleHost := host.moduleHost(testRuntimeModuleName)

	moduleHost.Logger(testDebugModuleMail).Debug(t.Context(), "mail debug")
	moduleHost.Logger(testDebugModuleLookup).Debug(t.Context(), "lookup debug")

	line := buf.String()
	if strings.Contains(line, "mail debug") {
		t.Fatalf("local lookup selector enabled mail debug: %s", line)
	}

	if !strings.Contains(line, "lookup debug") {
		t.Fatalf("local lookup selector did not enable lookup debug: %s", line)
	}
}

func TestHostLoggerInfoIsNotDebugModuleGated(t *testing.T) {
	var buf bytes.Buffer

	host := NewHost(
		WithLogger(testDebugLogger(&buf)),
		WithDebugConfig(pluginDebugConfig(t)),
		WithDebugRegistry(pluginDebugRegistry(t, testRuntimeModuleName, testDebugModuleLookup)),
	)

	host.moduleHost(testRuntimeModuleName).Logger(testDebugModuleLookup).Info(t.Context(), "plugin info")

	if line := buf.String(); !strings.Contains(line, "plugin info") {
		t.Fatalf("Info() was gated by debug selectors: %s", line)
	}
}

func TestOperationalObserverSuccessLogsRequirePluginSelector(t *testing.T) {
	var buf bytes.Buffer

	observer := NewOperationalObserver(
		testDebugLogger(&buf),
		WithOperationalObserverMetrics(nil),
		WithOperationalObserverDebugConfig(
			pluginDebugConfig(t),
			pluginDebugRegistry(t, testRuntimeModuleName, testDebugModuleLookup),
		),
	)

	observer.ObservePluginCall(CallRecord{
		Duration:       25 * time.Millisecond,
		ModuleName:     testRuntimeModuleName,
		ComponentName:  testRuntimeEnvironment,
		ExtensionPoint: "environment_source",
		Method:         "Evaluate",
	})

	if got := buf.String(); got != "" {
		t.Fatalf("observer logged success without plugin debug selector: %s", got)
	}
}

func TestOperationalObserverSuccessLogsHonorPluginSelector(t *testing.T) {
	var buf bytes.Buffer

	observer := NewOperationalObserver(
		testDebugLogger(&buf),
		WithOperationalObserverMetrics(nil),
		WithOperationalObserverDebugConfig(
			pluginDebugConfig(t, "plugin."+testRuntimeModuleName),
			pluginDebugRegistry(t, testRuntimeModuleName, testDebugModuleLookup),
		),
	)

	observer.ObservePluginCall(CallRecord{
		Duration:       25 * time.Millisecond,
		ModuleName:     testRuntimeModuleName,
		ComponentName:  testDebugModuleLookup,
		ExtensionPoint: "environment_source",
		Method:         "Evaluate",
	})

	line := buf.String()
	if !strings.Contains(line, "Native plugin call completed") ||
		!strings.Contains(line, `"debug_module":"plugin.`+testRuntimeModuleName+`.`+testDebugModuleLookup+`"`) {
		t.Fatalf("observer success log = %s", line)
	}
}

func TestOperationalObserverErrorsAreNotDebugModuleGated(t *testing.T) {
	var buf bytes.Buffer

	observer := NewOperationalObserver(
		slog.New(slog.NewJSONHandler(&buf, nil)),
		WithOperationalObserverMetrics(nil),
		WithOperationalObserverDebugConfig(
			pluginDebugConfig(t),
			pluginDebugRegistry(t, testRuntimeModuleName, testDebugModuleLookup),
		),
	)

	observer.ObservePluginCall(CallRecord{
		Err:            errors.New("database failed with password=secret"),
		Duration:       25 * time.Millisecond,
		ModuleName:     testRuntimeModuleName,
		ComponentName:  testRuntimeEnvironment,
		ExtensionPoint: "environment_source",
		Method:         "Evaluate",
	})

	if line := buf.String(); !strings.Contains(line, "Native plugin call failed") {
		t.Fatalf("observer error log was gated by debug selectors: %s", line)
	}
}

func TestHostGoLogsPanicWithoutRecoveredValue(t *testing.T) {
	var buf bytes.Buffer

	host := NewHost(WithLogger(slog.New(slog.NewJSONHandler(&buf, nil))))

	ctx := t.Context()

	host.Go(ctx, "worker", func(context.Context) error {
		panic("panic contains password=secret")
	})
	host.WaitWorkers()

	line := buf.String()
	if !strings.Contains(line, "plugin worker panicked") {
		t.Fatalf("worker panic log missing: %s", line)
	}

	if strings.Contains(line, "password=secret") {
		t.Fatalf("worker panic log leaked recovered value: %s", line)
	}
}

func TestHostGoLogsWorkerErrorWithoutRawValue(t *testing.T) {
	var buf bytes.Buffer

	host := NewHost(WithLogger(slog.New(slog.NewJSONHandler(&buf, nil))))

	ctx := t.Context()

	host.Go(ctx, "worker", func(context.Context) error {
		return errors.New("worker failed with password=secret")
	})
	host.WaitWorkers()

	line := buf.String()
	if !strings.Contains(line, "plugin worker stopped with error") {
		t.Fatalf("worker error log missing: %s", line)
	}

	if strings.Contains(line, "password=secret") || strings.Contains(line, "worker failed") {
		t.Fatalf("worker error log leaked raw error: %s", line)
	}
}

func pluginDebugConfig(t *testing.T, selectors ...string) *config.FileSettings {
	t.Helper()
	ensureDebugModuleMapping(t)

	verbosity := config.Verbosity{}
	if err := verbosity.Set(definitions.LogLevelNameDebug); err != nil {
		t.Fatalf("Verbosity.Set() error = %v", err)
	}

	modules := make([]*config.DbgModule, 0, len(selectors))
	for _, selector := range selectors {
		module := &config.DbgModule{}
		if err := module.Set(selector); err != nil {
			t.Fatalf("DbgModule.Set(%q) error = %v", selector, err)
		}

		modules = append(modules, module)
	}

	return &config.FileSettings{
		Server: &config.ServerSection{
			Log: config.Log{
				Level:      verbosity,
				DbgModules: modules,
			},
		},
	}
}

func testDebugLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func ensureDebugModuleMapping(t *testing.T) {
	t.Helper()

	previous := definitions.GetDbgModuleMapping()

	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())
	t.Cleanup(func() {
		definitions.SetDbgModuleMapping(previous)
	})
}

func pluginDebugRegistry(t *testing.T, moduleName string, localNames ...string) *pluginregistry.Registry {
	t.Helper()

	registry := pluginregistry.NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: moduleName})

	for _, localName := range localNames {
		if err := registrar.RegisterDebugModule(pluginapi.DebugModuleDefinition{Name: localName}); err != nil {
			t.Fatalf("RegisterDebugModule(%q) error = %v", localName, err)
		}
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	return registry
}
