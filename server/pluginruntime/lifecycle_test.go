package pluginruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
)

const (
	testRuntimeConfigKey      = "value"
	testRuntimeEnvironment    = "environment"
	testRuntimeEventInitStart = "init_start"
	testRuntimeEventInitStop  = "init_stop"
	testRuntimeEventStart     = "plugin_start"
	testRuntimeEventStop      = "plugin_stop"
	testRuntimeModuleName     = "geoip"
	testRuntimeNewValue       = "new"
	testRuntimeOldValue       = "old"
	testRuntimePluginPath     = "/plugins/geoip.so"
	testRuntimePluginVersion  = "1.0.0"
)

func TestRunner_StartsPluginBeforeInitTasksAndStopsInReverse(t *testing.T) {
	events := make([]string, 0, 4)
	plugin := &runtimePlugin{events: &events}
	initTask := &runtimeInitTask{events: &events}
	runner := newTestRunner(t, plugin, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterInitTask(initTask)
	})

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if !runner.Ready() {
		t.Fatal("runner is not ready after successful Start()")
	}

	if got, want := events, []string{testRuntimeEventStart, testRuntimeEventInitStart}; !sameStrings(got, want) {
		t.Fatalf("events after Start() = %#v, want %#v", got, want)
	}

	if err := runner.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	if got, want := events, []string{testRuntimeEventStart, testRuntimeEventInitStart, testRuntimeEventInitStop, testRuntimeEventStop}; !sameStrings(got, want) {
		t.Fatalf("events after Stop() = %#v, want %#v", got, want)
	}
}

func TestRunner_RequestTimeComponentsUnavailableBeforeReady(t *testing.T) {
	runner := newTestRunner(t, &runtimePlugin{}, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterEnvironmentSource(runtimeEnvironmentSource{name: testRuntimeEnvironment})
	})

	_, err := runner.EvaluateEnvironment(context.Background(), testRuntimeModuleName+".environment", pluginapi.EnvironmentRequest{})
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("EvaluateEnvironment() error = %v, want ErrNotReady", err)
	}
}

func TestRunner_PanicBoundaryConvertsPanicToTechnicalError(t *testing.T) {
	observer := &recordingObserver{}
	runner := newTestRunner(
		t,
		&runtimePlugin{},
		func(registrar pluginapi.Registrar) error {
			return registrar.RegisterEnvironmentSource(runtimeEnvironmentSource{name: testRuntimeEnvironment, panicEvaluate: true})
		},
		WithObserver(observer),
	)

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	_, err := runner.EvaluateEnvironment(context.Background(), testRuntimeModuleName+".environment", pluginapi.EnvironmentRequest{})
	if !errors.Is(err, ErrPluginPanic) {
		t.Fatalf("EvaluateEnvironment() error = %v, want ErrPluginPanic", err)
	}

	if !observer.sawPanic(testRuntimeEnvironment, "Evaluate") {
		t.Fatalf("observer records = %#v, want panic for environment Evaluate", observer.records)
	}
}

func TestRunner_StopAppliesModuleStopTimeout(t *testing.T) {
	module := initialRuntimeModule(nil)
	module.StopTimeout = 20 * time.Millisecond
	runner := newTestRunnerWithModule(t, &blockingStopPlugin{}, module, nil)

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	started := time.Now()
	err := runner.Stop(stopCtx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop() error = %v, want context deadline exceeded", err)
	}

	if elapsed > 200*time.Millisecond {
		t.Fatalf("Stop() elapsed = %s, want module timeout to bound shutdown", elapsed)
	}
}

func TestRunner_StopWaitsForHostWorkers(t *testing.T) {
	serviceCtx, cancelService := context.WithCancel(context.Background())
	host := NewHost(WithServiceContext(serviceCtx))
	plugin := &workerRuntimePlugin{
		started: make(chan struct{}),
		done:    make(chan struct{}),
	}
	runner := newTestRunner(t, plugin, nil, WithHost(host))

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	<-plugin.started
	cancelService()

	stopCtx, cancelStop := context.WithTimeout(context.Background(), time.Second)
	defer cancelStop()

	if err := runner.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	select {
	case <-plugin.done:
	default:
		t.Fatal("Stop() returned before host-supervised worker exited")
	}
}

func TestRunner_StopReportsHostWorkerWaitTimeout(t *testing.T) {
	serviceCtx := t.Context()

	host := NewHost(WithServiceContext(serviceCtx))
	plugin := &workerRuntimePlugin{
		started: make(chan struct{}),
		done:    make(chan struct{}),
	}
	runner := newTestRunner(t, plugin, nil, WithHost(host))

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	<-plugin.started

	stopCtx, cancelStop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelStop()

	err := runner.Stop(stopCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop() error = %v, want context deadline exceeded", err)
	}
}

func TestRunner_ReconfigureSuccessSwapsConfig(t *testing.T) {
	plugin := &runtimePlugin{}
	runner := newTestRunnerWithModule(t, plugin, initialRuntimeModule(map[string]any{testRuntimeConfigKey: testRuntimeOldValue}), nil)
	next := nextRuntimeConfig(map[string]any{testRuntimeConfigKey: testRuntimeNewValue}, nil)

	if err := runner.Reconfigure(context.Background(), next); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	value, ok := runner.ModuleConfig(testRuntimeModuleName).Get(testRuntimeConfigKey)
	if !ok || value != testRuntimeNewValue {
		t.Fatalf("ModuleConfig() value = %#v, %v; want new", value, ok)
	}

	if got := plugin.reconfigureValues; !sameStrings(got, []string{testRuntimeNewValue}) {
		t.Fatalf("reconfigure values = %#v, want new", got)
	}
}

func TestRunner_ReconfigureFailureKeepsPreviousConfig(t *testing.T) {
	reconfigureErr := errors.New("reject config")
	plugin := &runtimePlugin{reconfigureErr: reconfigureErr}
	runner := newTestRunnerWithModule(t, plugin, initialRuntimeModule(map[string]any{testRuntimeConfigKey: testRuntimeOldValue}), nil)
	next := nextRuntimeConfig(map[string]any{testRuntimeConfigKey: testRuntimeNewValue}, nil)

	err := runner.Reconfigure(context.Background(), next)
	if !errors.Is(err, reconfigureErr) {
		t.Fatalf("Reconfigure() error = %v, want reconfigureErr", err)
	}

	value, ok := runner.ModuleConfig(testRuntimeModuleName).Get(testRuntimeConfigKey)
	if !ok || value != testRuntimeOldValue {
		t.Fatalf("ModuleConfig() value = %#v, %v; want old", value, ok)
	}
}

func TestRunner_ReconfigureRejectsRestartOnlyLoaderChanges(t *testing.T) {
	plugin := &runtimePlugin{}
	runner := newTestRunnerWithModule(t, plugin, initialRuntimeModule(map[string]any{testRuntimeConfigKey: testRuntimeOldValue}), nil)
	next := nextRuntimeConfig(map[string]any{testRuntimeConfigKey: testRuntimeNewValue}, func(module *config.PluginModule) {
		module.Path = "/plugins/other.so"
	})

	err := runner.Reconfigure(context.Background(), next)
	if !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("Reconfigure() error = %v, want ErrRestartRequired", err)
	}

	value, ok := runner.ModuleConfig(testRuntimeModuleName).Get(testRuntimeConfigKey)
	if !ok || value != testRuntimeOldValue {
		t.Fatalf("ModuleConfig() value = %#v, %v; want old", value, ok)
	}

	if len(plugin.reconfigureValues) != 0 {
		t.Fatalf("reconfigure was called despite restart-only change: %#v", plugin.reconfigureValues)
	}
}

func newTestRunner(t *testing.T, plugin pluginapi.Plugin, register func(pluginapi.Registrar) error, options ...Option) *Runner {
	t.Helper()

	return newTestRunnerWithModule(t, plugin, initialRuntimeModule(nil), register, options...)
}

func newTestRunnerWithModule(
	t *testing.T,
	plugin pluginapi.Plugin,
	module config.PluginModule,
	register func(pluginapi.Registrar) error,
	options ...Option,
) *Runner {
	t.Helper()

	registry := pluginregistry.NewRegistry()

	var capabilities []pluginapi.Capability
	if register != nil {
		registrar := registry.NewRegistrar(module)
		if err := register(registrar); err != nil {
			t.Fatalf("register test components: %v", err)
		}

		if err := registrar.Commit(); err != nil {
			t.Fatalf("commit test components: %v", err)
		}

		capabilities = registrar.Capabilities()
	}

	instances := []pluginloader.ModuleInstance{
		{
			Plugin:       plugin,
			Module:       module,
			ModuleName:   module.Name,
			Status:       pluginloader.ModuleStatusRegistered,
			Capabilities: capabilities,
		},
	}
	options = append(options, WithPluginConfig(&config.PluginsSection{Modules: []config.PluginModule{module}}))

	return NewRunnerFromInstances(registry, instances, options...)
}

func initialRuntimeModule(moduleConfig map[string]any) config.PluginModule {
	return config.PluginModule{
		Config: moduleConfig,
		Name:   testRuntimeModuleName,
		Type:   config.PluginModuleTypeGo,
		Path:   testRuntimePluginPath,
	}
}

func nextRuntimeConfig(moduleConfig map[string]any, mutate func(*config.PluginModule)) *config.FileSettings {
	module := initialRuntimeModule(moduleConfig)
	if mutate != nil {
		mutate(&module)
	}

	return &config.FileSettings{
		Plugins: &config.PluginsSection{
			Modules: []config.PluginModule{module},
		},
	}
}

func sameStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}

	return true
}

type runtimePlugin struct {
	events            *[]string
	reconfigureErr    error
	reconfigureValues []string
}

type blockingStopPlugin struct {
	runtimePlugin
}

func (p *blockingStopPlugin) Stop(ctx context.Context) error {
	<-ctx.Done()

	return ctx.Err()
}

type workerRuntimePlugin struct {
	runtimePlugin
	started chan struct{}
	done    chan struct{}
}

func (p *workerRuntimePlugin) Start(_ context.Context, host pluginapi.Host) error {
	host.Go(context.Background(), "worker", func(ctx context.Context) error {
		close(p.started)
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond)
		close(p.done)

		return nil
	})

	return nil
}

func (p *runtimePlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:       "runtime",
		Version:    testRuntimePluginVersion,
		APIVersion: pluginapi.APIVersion,
	}
}

func (p *runtimePlugin) Register(pluginapi.Registrar) error {
	return nil
}

func (p *runtimePlugin) Start(context.Context, pluginapi.Host) error {
	if p.events != nil {
		*p.events = append(*p.events, testRuntimeEventStart)
	}

	return nil
}

func (p *runtimePlugin) Stop(context.Context) error {
	if p.events != nil {
		*p.events = append(*p.events, testRuntimeEventStop)
	}

	return nil
}

func (p *runtimePlugin) Reconfigure(_ context.Context, view pluginapi.ConfigView) error {
	if p.reconfigureErr != nil {
		return p.reconfigureErr
	}

	value, _ := view.Get(testRuntimeConfigKey)
	if text, ok := value.(string); ok {
		p.reconfigureValues = append(p.reconfigureValues, text)
	}

	return nil
}

type runtimeInitTask struct {
	events *[]string
}

func (t *runtimeInitTask) Name() string {
	return "init"
}

func (t *runtimeInitTask) Start(context.Context, pluginapi.InitContext) error {
	if t.events != nil {
		*t.events = append(*t.events, testRuntimeEventInitStart)
	}

	return nil
}

func (t *runtimeInitTask) Stop(context.Context) error {
	if t.events != nil {
		*t.events = append(*t.events, testRuntimeEventInitStop)
	}

	return nil
}

type runtimeEnvironmentSource struct {
	name          string
	panicEvaluate bool
}

func (s runtimeEnvironmentSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{
		Name:        s.name,
		AbortPolicy: pluginapi.AbortPolicyNone,
	}
}

func (s runtimeEnvironmentSource) Evaluate(context.Context, pluginapi.EnvironmentRequest) (pluginapi.EnvironmentResult, error) {
	if s.panicEvaluate {
		panic("environment failed")
	}

	return pluginapi.EnvironmentResult{Triggered: true}, nil
}

type recordingObserver struct {
	records []CallRecord
}

func (o *recordingObserver) ObservePluginCall(record CallRecord) {
	o.records = append(o.records, record)
}

func (o *recordingObserver) sawPanic(component string, method string) bool {
	for _, record := range o.records {
		if record.ComponentName == component && record.Method == method && record.Panicked {
			return true
		}
	}

	return false
}

// sawCall reports whether the observer recorded a component method call.
func (o *recordingObserver) sawCall(component string, extensionPoint string, method string) bool {
	for _, record := range o.records {
		if record.ComponentName == component && record.ExtensionPoint == extensionPoint && record.Method == method {
			return true
		}
	}

	return false
}
