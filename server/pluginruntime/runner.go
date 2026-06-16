// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package pluginruntime owns native plugin lifecycle execution.
package pluginruntime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/pluginloader"
	"github.com/croessner/nauthilus/server/pluginregistry"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
)

var (
	// ErrNotReady is returned when request-time components are invoked before lifecycle readiness.
	ErrNotReady = errors.New("plugin runtime is not ready")

	// ErrPluginPanic is returned when a plugin method panics behind the host boundary.
	ErrPluginPanic = errors.New("plugin method panicked")

	// ErrLifecycleFailed wraps startup or shutdown lifecycle failures.
	ErrLifecycleFailed = errors.New("plugin lifecycle failed")

	// ErrComponentNotFound is returned when a qualified component is not registered.
	ErrComponentNotFound = errors.New("plugin component not found")

	// ErrComponentKindMismatch is returned when a component exists under another extension kind.
	ErrComponentKindMismatch = errors.New("plugin component kind mismatch")

	// ErrRestartRequired is returned when reload input changes restart-only plugin fields.
	ErrRestartRequired = errors.New("plugin restart required")
)

var defaultRunner atomic.Value // stores *Runner

const extensionPointPlugin = "plugin"

// Option customizes a Runner.
type Option func(*Runner)

// CallRecord describes one host-invoked plugin method call.
type CallRecord struct {
	Err            error
	Duration       time.Duration
	ModuleName     string
	ComponentName  string
	ExtensionPoint string
	Method         string
	Panicked       bool
}

// Observer receives automatic plugin call observations.
type Observer interface {
	ObservePluginCall(CallRecord)
}

// Runner coordinates plugin lifecycle and request-time readiness.
type Runner struct {
	host             pluginapi.Host
	observer         Observer
	registry         *pluginregistry.Registry
	pluginConfig     *config.PluginsSection
	modules          []moduleRuntime
	startedModules   []string
	startedInitTasks []pluginregistry.Component
	moduleIndex      map[string]int
	failedModules    map[string]error
	mu               sync.RWMutex
	ready            bool
}

type moduleRuntime struct {
	instance pluginloader.ModuleInstance
}

type invokeSpec struct {
	moduleName     string
	componentName  string
	extensionPoint string
	method         string
}

// NewRunner returns a lifecycle runner for a loader state.
func NewRunner(state *pluginloader.State, options ...Option) *Runner {
	if state == nil {
		return NewRunnerFromInstances(pluginregistry.NewRegistry(), nil, options...)
	}

	return NewRunnerFromInstances(state.Registry(), state.Instances(), options...)
}

// NewRunnerFromInstances returns a lifecycle runner from explicit module instances.
func NewRunnerFromInstances(
	registry *pluginregistry.Registry,
	instances []pluginloader.ModuleInstance,
	options ...Option,
) *Runner {
	runner := &Runner{
		host:          NewHost(),
		observer:      noopObserver{},
		registry:      registry,
		moduleIndex:   make(map[string]int, len(instances)),
		failedModules: make(map[string]error),
	}
	if runner.registry == nil {
		runner.registry = pluginregistry.NewRegistry()
	}

	for _, instance := range instances {
		if instance.Status != "" && instance.Status != pluginloader.ModuleStatusRegistered {
			continue
		}

		runner.moduleIndex[instance.ModuleName] = len(runner.modules)
		runner.modules = append(runner.modules, moduleRuntime{instance: instance})
	}

	runner.pluginConfig = pluginSectionFromModules(runner.modules)
	for _, option := range options {
		option(runner)
	}

	if runner.pluginConfig == nil {
		runner.pluginConfig = pluginSectionFromModules(runner.modules)
	}

	core.RegisterPluginSubjectSourceBridge(NewSubjectSourceBridge(runner))
	core.RegisterPluginEffectBridge(NewEffectBridge(runner))

	return runner
}

// WithHost configures the host facade passed to plugin lifecycle methods.
func WithHost(host pluginapi.Host) Option {
	return func(runner *Runner) {
		if host != nil {
			runner.host = host
		}
	}
}

// WithObserver configures automatic plugin call observation.
func WithObserver(observer Observer) Option {
	return func(runner *Runner) {
		if observer != nil {
			runner.observer = observer
		}
	}
}

// WithPluginConfig records the restart-only baseline used by later config reloads.
func WithPluginConfig(plugins *config.PluginsSection) Option {
	return func(runner *Runner) {
		runner.pluginConfig = clonePluginSection(plugins)
	}
}

// SetDefaultRunner publishes the current process plugin runtime runner.
func SetDefaultRunner(runner *Runner) {
	defaultRunner.Store(runner)
}

// DefaultRunner returns the current process plugin runtime runner.
func DefaultRunner() (*Runner, bool) {
	runner, ok := defaultRunner.Load().(*Runner)

	return runner, ok && runner != nil
}

// Start runs plugin Start, registered init tasks, and finally marks request-time execution ready.
func (r *Runner) Start(ctx context.Context) error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ready {
		return nil
	}

	for index := range r.modules {
		if err := r.startModule(ctx, index); err != nil {
			return err
		}
	}

	for _, component := range r.registry.InitTasks() {
		if err := r.startInitTask(ctx, component); err != nil {
			return err
		}
	}

	r.ready = true

	return nil
}

// Stop stops init tasks before plugin runtime instances.
func (r *Runner) Stop(ctx context.Context) error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.ready = false

	var errs []error

	for index := len(r.startedInitTasks) - 1; index >= 0; index-- {
		if err := r.stopInitTask(ctx, r.startedInitTasks[index]); err != nil {
			errs = append(errs, err)
		}
	}

	for index := len(r.startedModules) - 1; index >= 0; index-- {
		if err := r.stopModule(ctx, r.startedModules[index]); err != nil {
			errs = append(errs, err)
		}
	}

	r.startedInitTasks = nil
	r.startedModules = nil

	return errors.Join(errs...)
}

// Ready reports whether request-time plugin component invocation is enabled.
func (r *Runner) Ready() bool {
	if r == nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.ready
}

// ModuleConfig returns the current host-owned plugin config view for a module.
func (r *Runner) ModuleConfig(moduleName string) pluginapi.ConfigView {
	if r == nil {
		return pluginregistry.NewConfigView(nil)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	index, ok := r.moduleIndex[moduleName]
	if !ok {
		return pluginregistry.NewConfigView(nil)
	}

	return pluginregistry.NewConfigView(r.modules[index].instance.Module.Config)
}

// ModuleCapabilities returns a copy of the capabilities granted to one module.
func (r *Runner) ModuleCapabilities(moduleName string) []pluginapi.Capability {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	index, ok := r.moduleIndex[moduleName]
	if !ok {
		return nil
	}

	return slices.Clone(r.modules[index].instance.Capabilities)
}

// EvaluateEnvironment invokes one ready environment source behind the host panic boundary.
func (r *Runner) EvaluateEnvironment(
	ctx context.Context,
	qualifiedName string,
	request pluginapi.EnvironmentRequest,
) (pluginapi.EnvironmentResult, error) {
	return invokeTypedComponent(ctx, r, qualifiedName, pluginregistry.ComponentKindEnvironmentSource, "Evaluate", func(callCtx context.Context, source pluginapi.EnvironmentSource) (pluginapi.EnvironmentResult, error) {
		return source.Evaluate(callCtx, request)
	})
}

// EvaluateSubject invokes one ready subject source behind the host panic boundary.
func (r *Runner) EvaluateSubject(
	ctx context.Context,
	qualifiedName string,
	request pluginapi.SubjectRequest,
) (pluginapi.SubjectResult, error) {
	return invokeTypedComponent(ctx, r, qualifiedName, pluginregistry.ComponentKindSubjectSource, "Evaluate", func(callCtx context.Context, source pluginapi.SubjectSource) (pluginapi.SubjectResult, error) {
		return source.Evaluate(callCtx, request)
	})
}

// ExecuteObligation invokes one ready obligation target behind the host panic boundary.
func (r *Runner) ExecuteObligation(
	ctx context.Context,
	qualifiedName string,
	request pluginapi.ObligationRequest,
) (pluginapi.ObligationResult, error) {
	return invokeTypedComponent(ctx, r, qualifiedName, pluginregistry.ComponentKindObligationTarget, "Execute", func(callCtx context.Context, target pluginapi.ObligationTarget) (pluginapi.ObligationResult, error) {
		return target.Execute(callCtx, request)
	})
}

// EnqueuePostAction invokes one ready post-action target behind the host panic boundary.
func (r *Runner) EnqueuePostAction(
	ctx context.Context,
	qualifiedName string,
	request pluginapi.PostActionRequest,
) (pluginapi.PostActionEnqueueResult, error) {
	return invokeTypedComponent(ctx, r, qualifiedName, pluginregistry.ComponentKindPostActionTarget, "Enqueue", func(callCtx context.Context, target pluginapi.PostActionTarget) (pluginapi.PostActionEnqueueResult, error) {
		return target.Enqueue(callCtx, request)
	})
}

// ServeHook invokes one ready hook behind the host panic boundary.
func (r *Runner) ServeHook(
	ctx context.Context,
	qualifiedName string,
	request pluginapi.HookRequest,
) (pluginapi.HookResponse, error) {
	return invokeTypedComponent(ctx, r, qualifiedName, pluginregistry.ComponentKindHook, "Serve", func(callCtx context.Context, hook pluginapi.Hook) (pluginapi.HookResponse, error) {
		return hook.Serve(callCtx, request)
	})
}

// VerifyPassword invokes one ready backend password check behind the host panic boundary.
func (r *Runner) VerifyPassword(
	ctx context.Context,
	qualifiedName string,
	request pluginapi.BackendAuthRequest,
) (pluginapi.BackendResult, error) {
	return invokeTypedComponent(ctx, r, qualifiedName, pluginregistry.ComponentKindBackend, "VerifyPassword", func(callCtx context.Context, backend pluginapi.Backend) (pluginapi.BackendResult, error) {
		return backend.VerifyPassword(callCtx, request)
	})
}

// ListAccounts invokes one ready backend account listing behind the host panic boundary.
func (r *Runner) ListAccounts(
	ctx context.Context,
	qualifiedName string,
	request pluginapi.AccountListRequest,
) (pluginapi.AccountListResult, error) {
	return invokeTypedComponent(ctx, r, qualifiedName, pluginregistry.ComponentKindBackend, "ListAccounts", func(callCtx context.Context, backend pluginapi.Backend) (pluginapi.AccountListResult, error) {
		return backend.ListAccounts(callCtx, request)
	})
}

// invokeTypedComponent fetches a ready component and invokes one typed component method.
func invokeTypedComponent[T any, R any](
	ctx context.Context,
	r *Runner,
	qualifiedName string,
	kind pluginregistry.ComponentKind,
	method string,
	call func(context.Context, T) (R, error),
) (result R, err error) {
	component, err := r.readyComponent(qualifiedName, kind)
	if err != nil {
		return result, err
	}

	value, ok := component.Value.(T)
	if !ok {
		return result, fmt.Errorf("%w: %s", ErrComponentKindMismatch, qualifiedName)
	}

	err = r.invoke(ctx, componentInvokeSpec(component, method), func(callCtx context.Context) error {
		nextResult, callErr := call(callCtx, value)
		result = nextResult

		return callErr
	})

	return result, err
}

// startModule runs one plugin Start method when implemented.
func (r *Runner) startModule(ctx context.Context, index int) error {
	instance := r.modules[index].instance

	runtimePlugin, ok := instance.Plugin.(pluginapi.RuntimePlugin)
	if !ok {
		return nil
	}

	spec := invokeSpec{
		moduleName:     instance.ModuleName,
		componentName:  instance.ModuleName,
		extensionPoint: extensionPointPlugin,
		method:         "Start",
	}
	if err := r.invoke(ctx, spec, func(callCtx context.Context) error {
		return runtimePlugin.Start(callCtx, r.host)
	}); err != nil {
		return r.handleLifecycleError(instance, "Start", err)
	}

	r.startedModules = append(r.startedModules, instance.ModuleName)

	return nil
}

// stopModule runs one plugin Stop method when it was started.
func (r *Runner) stopModule(ctx context.Context, moduleName string) error {
	index, ok := r.moduleIndex[moduleName]
	if !ok {
		return nil
	}

	instance := r.modules[index].instance

	runtimePlugin, ok := instance.Plugin.(pluginapi.RuntimePlugin)
	if !ok {
		return nil
	}

	spec := invokeSpec{
		moduleName:     instance.ModuleName,
		componentName:  instance.ModuleName,
		extensionPoint: extensionPointPlugin,
		method:         "Stop",
	}
	if err := r.invoke(ctx, spec, func(callCtx context.Context) error {
		return runtimePlugin.Stop(callCtx)
	}); err != nil {
		return fmt.Errorf("%w: module %q Stop failed: %w", ErrLifecycleFailed, instance.ModuleName, err)
	}

	return nil
}

// startInitTask runs one registered init task after plugin Start completed.
func (r *Runner) startInitTask(ctx context.Context, component pluginregistry.Component) error {
	if _, failed := r.failedModules[component.ModuleName]; failed {
		return nil
	}

	task, ok := component.Value.(pluginapi.InitTask)
	if !ok {
		return fmt.Errorf("%w: %s", ErrComponentKindMismatch, component.QualifiedName)
	}

	initContext := pluginapi.InitContext{
		Host:   r.host,
		Config: r.moduleConfigLocked(component.ModuleName),
	}
	if err := r.invoke(ctx, componentInvokeSpec(component, "Start"), func(callCtx context.Context) error {
		return task.Start(callCtx, initContext)
	}); err != nil {
		return fmt.Errorf("%w: module %q component %q init task Start failed: %w", ErrLifecycleFailed, component.ModuleName, component.LocalName, err)
	}

	r.startedInitTasks = append(r.startedInitTasks, component)

	return nil
}

// stopInitTask runs one registered init task Stop method.
func (r *Runner) stopInitTask(ctx context.Context, component pluginregistry.Component) error {
	task, ok := component.Value.(pluginapi.InitTask)
	if !ok {
		return fmt.Errorf("%w: %s", ErrComponentKindMismatch, component.QualifiedName)
	}

	if err := r.invoke(ctx, componentInvokeSpec(component, "Stop"), func(callCtx context.Context) error {
		return task.Stop(callCtx)
	}); err != nil {
		return fmt.Errorf("%w: module %q component %q init task Stop failed: %w", ErrLifecycleFailed, component.ModuleName, component.LocalName, err)
	}

	return nil
}

// handleLifecycleError applies optional module failure rules.
func (r *Runner) handleLifecycleError(instance pluginloader.ModuleInstance, method string, err error) error {
	if instance.Optional {
		r.failedModules[instance.ModuleName] = err

		return nil
	}

	return fmt.Errorf("%w: module %q %s failed: %w", ErrLifecycleFailed, instance.ModuleName, method, err)
}

// readyComponent fetches a component only after request-time readiness is enabled.
func (r *Runner) readyComponent(qualifiedName string, kind pluginregistry.ComponentKind) (pluginregistry.Component, error) {
	if r == nil {
		return pluginregistry.Component{}, ErrNotReady
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.ready {
		return pluginregistry.Component{}, ErrNotReady
	}

	component, ok := r.registry.Lookup(qualifiedName)
	if !ok {
		return pluginregistry.Component{}, fmt.Errorf("%w: %s", ErrComponentNotFound, qualifiedName)
	}

	if component.Kind != kind {
		return pluginregistry.Component{}, fmt.Errorf("%w: %s is %s, want %s", ErrComponentKindMismatch, qualifiedName, component.Kind, kind)
	}

	if err, failed := r.failedModules[component.ModuleName]; failed {
		return pluginregistry.Component{}, fmt.Errorf("%w: module %q unavailable: %w", ErrLifecycleFailed, component.ModuleName, err)
	}

	return component, nil
}

// moduleConfigLocked returns a config view while the caller holds the runner lock.
func (r *Runner) moduleConfigLocked(moduleName string) pluginapi.ConfigView {
	index, ok := r.moduleIndex[moduleName]
	if !ok {
		return pluginregistry.NewConfigView(nil)
	}

	return pluginregistry.NewConfigView(r.modules[index].instance.Module.Config)
}

// invoke runs one host-invoked plugin method with panic recovery and call observation.
func (r *Runner) invoke(ctx context.Context, spec invokeSpec, fn func(context.Context) error) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}

	start := time.Now()
	panicked := false
	ctx, span := startPluginCallSpan(ctx, spec)

	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = true
			err = fmt.Errorf(
				"%w: module %q component %q method %s",
				ErrPluginPanic,
				spec.moduleName,
				spec.componentName,
				spec.method,
			)
		}

		finishPluginCallSpan(span, err, panicked)
		r.observe(CallRecord{
			Err:            err,
			Duration:       time.Since(start),
			ModuleName:     spec.moduleName,
			ComponentName:  spec.componentName,
			ExtensionPoint: spec.extensionPoint,
			Method:         spec.method,
			Panicked:       panicked,
		})
	}()

	if err := ctx.Err(); err != nil {
		return err
	}

	return fn(ctx)
}

// startPluginCallSpan creates a low-cardinality host span for one plugin method.
func startPluginCallSpan(ctx context.Context, spec invokeSpec) (context.Context, oteltrace.Span) {
	tracer := monittrace.New("nauthilus/plugin/runtime")

	return tracer.Start(ctx, pluginCallSpanName(spec),
		attribute.String("plugin.module", spec.moduleName),
		attribute.String("plugin.component", spec.componentName),
		attribute.String("plugin.extension_point", spec.extensionPoint),
		attribute.String("plugin.method", spec.method),
	)
}

// finishPluginCallSpan marks the plugin span with a bounded result and ends it.
func finishPluginCallSpan(span oteltrace.Span, err error, panicked bool) {
	if span == nil {
		return
	}

	result := pluginCallResult(CallRecord{Err: err, Panicked: panicked})
	span.SetAttributes(attribute.String("plugin.result", result))

	if err != nil || panicked {
		span.SetStatus(codes.Error, "plugin call failed")
	}

	span.End()
}

// pluginCallSpanName returns a stable span name for one plugin method.
func pluginCallSpanName(spec invokeSpec) string {
	if spec.extensionPoint == "" {
		return "plugin." + spec.method
	}

	return "plugin." + spec.extensionPoint + "." + spec.method
}

// observe emits a call record through the configured observer.
func (r *Runner) observe(record CallRecord) {
	if r == nil || r.observer == nil {
		return
	}

	r.observer.ObservePluginCall(record)
}

// componentInvokeSpec builds a stable observation scope from a component.
func componentInvokeSpec(component pluginregistry.Component, method string) invokeSpec {
	return invokeSpec{
		moduleName:     component.ModuleName,
		componentName:  component.LocalName,
		extensionPoint: string(component.Kind),
		method:         method,
	}
}

// pluginSectionFromModules creates a reload baseline from module runtime state.
func pluginSectionFromModules(modules []moduleRuntime) *config.PluginsSection {
	if len(modules) == 0 {
		return &config.PluginsSection{}
	}

	plugins := &config.PluginsSection{
		Modules: make([]config.PluginModule, 0, len(modules)),
	}
	for _, module := range modules {
		plugins.Modules = append(plugins.Modules, clonePluginModule(module.instance.Module))
	}

	return plugins
}

// clonePluginSection returns a detached copy of plugin loader configuration.
func clonePluginSection(plugins *config.PluginsSection) *config.PluginsSection {
	if plugins == nil {
		return &config.PluginsSection{}
	}

	cloned := &config.PluginsSection{
		Trust: config.PluginTrustSection{
			Signers: append([]config.PluginTrustSigner(nil), plugins.Trust.Signers...),
		},
		AllowedDirs:        append([]string(nil), plugins.AllowedDirs...),
		Modules:            make([]config.PluginModule, 0, len(plugins.Modules)),
		VerificationPolicy: plugins.VerificationPolicy,
	}
	for _, module := range plugins.Modules {
		cloned.Modules = append(cloned.Modules, clonePluginModule(module))
	}

	return cloned
}

// clonePluginModule returns a detached copy of one module config.
func clonePluginModule(module config.PluginModule) config.PluginModule {
	cloned := module
	cloned.AllowCapabilities = append([]pluginapi.Capability(nil), module.AllowCapabilities...)
	cloned.Config = cloneConfigMap(module.Config)

	return cloned
}

// cloneConfigMap recursively copies plugin-owned opaque config values.
func cloneConfigMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}

	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = cloneConfigValue(value)
	}

	return cloned
}

// cloneConfigValue copies common decoded config containers.
func cloneConfigValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneConfigMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneConfigValue(item)
		}

		return cloned
	default:
		return value
	}
}

type noopObserver struct{}

// ObservePluginCall intentionally discards plugin call observations.
func (noopObserver) ObservePluginCall(CallRecord) {}

// sameCapabilities reports whether capability lists are identical.
func sameCapabilities(left []pluginapi.Capability, right []pluginapi.Capability) bool {
	return slices.Equal(left, right)
}
