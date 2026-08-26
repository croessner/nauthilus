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

package pluginloader

import (
	"errors"
	"fmt"
	"log/slog"
	stdplugin "plugin"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
)

const pluginFactorySymbol = "NauthilusPlugin"

var (
	// ErrArtifactUnavailable is returned when a verified handoff path is not openable anymore.
	ErrArtifactUnavailable = errors.New("plugin artifact unavailable after verification")

	// ErrPluginOpenFailed is returned when plugin.Open fails.
	ErrPluginOpenFailed = errors.New("plugin open failed")

	// ErrFactorySymbolMissing is returned when the plugin factory symbol cannot be resolved.
	ErrFactorySymbolMissing = errors.New("plugin factory symbol missing")

	// ErrFactorySymbolInvalid is returned when the factory has the wrong Go type.
	ErrFactorySymbolInvalid = errors.New("plugin factory symbol has invalid type")

	// ErrFactoryFailed is returned when the factory returns an error.
	ErrFactoryFailed = errors.New("plugin factory failed")

	// ErrNilPlugin is returned when the factory returns a nil plugin.
	ErrNilPlugin = errors.New("plugin factory returned nil plugin")

	// ErrPluginPanic is returned when a host-invoked plugin method panics.
	ErrPluginPanic = errors.New("plugin panicked")

	// ErrRequiredModuleFailed is returned when a required module cannot be registered.
	ErrRequiredModuleFailed = errors.New("required plugin module failed")
)

// PluginHandle resolves symbols from one opened plugin artifact.
type PluginHandle interface {
	Lookup(symbol string) (any, error)
}

// Opener opens an already verified plugin artifact path.
type Opener interface {
	Open(path string) (PluginHandle, error)
}

// Option configures a Loader.
type Option func(*Loader)

// Loader opens verified artifacts and records registered module instances.
type Loader struct {
	readArtifact func(string) ([]byte, error)
	opener       Opener
	logger       *slog.Logger
}

// ModuleStatus describes the registration state for one configured module.
type ModuleStatus string

const (
	// ModuleStatusRegistered marks a module whose factory, metadata, and Register call succeeded.
	ModuleStatusRegistered ModuleStatus = "registered"

	// ModuleStatusFailed marks a module whose startup-time registration path failed.
	ModuleStatusFailed ModuleStatus = "failed"
)

// ModuleInstance stores the host-visible state for one configured plugin module.
type ModuleInstance struct {
	Plugin            pluginapi.Plugin
	RegistrationError error
	Metadata          pluginapi.Metadata
	Module            config.PluginModule
	Descriptors       []pluginregistry.Component
	PolicyAttributes  []policyregistry.AttributeDefinition
	DebugModules      []pluginregistry.DebugModule
	Capabilities      []pluginapi.Capability
	ArtifactPath      string
	SignaturePath     string
	VerifiedSigner    string
	ModuleName        string
	Status            ModuleStatus
	ArtifactDigest    ArtifactDigest
	Optional          bool
}

// IsRegistered reports whether the instance can participate in the plugin runtime.
func (m ModuleInstance) IsRegistered() bool {
	return m.Status == "" || m.Status == ModuleStatusRegistered
}

// State contains all module instances registered during one loader run.
type State struct {
	registry  *pluginregistry.Registry
	instances []ModuleInstance
}

// ModuleError annotates a module load error with an operator-readable step.
type ModuleError struct {
	Err          error
	ModuleName   string
	ArtifactPath string
	Step         string
}

// Error describes the failed module step without exposing plugin-owned config.
func (e *ModuleError) Error() string {
	if e == nil {
		return "<nil>"
	}

	return fmt.Sprintf("plugin module %q %s failed for %q: %v", e.ModuleName, e.Step, e.ArtifactPath, e.Err)
}

// Unwrap returns the underlying module error.
func (e *ModuleError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

// NewLoader returns a plugin loader that requires an explicit reader for verified modules.
func NewLoader(options ...Option) *Loader {
	loader := &Loader{opener: stdlibOpener{}}
	for _, option := range options {
		option(loader)
	}

	return loader
}

// WithLoaderArtifactReader binds staging to the same candidate-owned bytes verified earlier.
func WithLoaderArtifactReader(reader func(string) ([]byte, error)) Option {
	return func(loader *Loader) {
		if reader != nil {
			loader.readArtifact = reader
		}
	}
}

// WithOpener injects an opener, primarily for fake-backed loader tests.
func WithOpener(opener Opener) Option {
	return func(loader *Loader) {
		if opener != nil {
			loader.opener = opener
		}
	}
}

// WithLogger configures operator-visible optional module logging.
func WithLogger(logger *slog.Logger) Option {
	return func(loader *Loader) {
		loader.logger = logger
	}
}

// Load opens, validates, and registers verified module artifacts.
func (l *Loader) Load(verified []VerifiedModule) (state *State, err error) {
	if l == nil {
		l = NewLoader()
	}

	registry := pluginregistry.NewRegistry()
	state = &State{registry: registry}

	if len(verified) == 0 {
		return state, nil
	}

	if l.readArtifact == nil {
		return nil, ErrArtifactReaderRequired
	}

	stager, err := newVerifiedArtifactStager(l.readArtifact)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, stager.close())
	}()

	for _, verifiedModule := range verified {
		l.logModuleLoadStart(verifiedModule)

		var instance ModuleInstance

		loadErr := verifiedModule.VerificationError
		if loadErr == nil {
			instance, loadErr = l.loadModule(registry, stager, verifiedModule)
		} else {
			loadErr = moduleError(verifiedModule, "verification", loadErr)
		}
		if loadErr != nil {
			failed := failedModuleInstance(verifiedModule, loadErr)
			state.instances = append(state.instances, failed)

			if verifiedModule.Module.Optional {
				l.logOptionalFailure(failed)

				continue
			}

			l.logRequiredFailure(failed)

			return state, fmt.Errorf("%w: %w", ErrRequiredModuleFailed, loadErr)
		}

		state.instances = append(state.instances, instance)
		l.logRegistered(instance)
	}

	return state, nil
}

// Registry returns the component registry created by the loader run.
func (s *State) Registry() *pluginregistry.Registry {
	if s == nil {
		return pluginregistry.NewRegistry()
	}

	return s.registry
}

// Instances returns module instance state in configured order.
func (s *State) Instances() []ModuleInstance {
	if s == nil || len(s.instances) == 0 {
		return nil
	}

	instances := make([]ModuleInstance, len(s.instances))
	copy(instances, s.instances)

	return instances
}

// loadModule performs the verified artifact to registered module transition.
func (l *Loader) loadModule(
	registry *pluginregistry.Registry,
	stager *verifiedArtifactStager,
	verified VerifiedModule,
) (ModuleInstance, error) {
	artifact, err := stager.stage(verified)
	if err != nil {
		return ModuleInstance{}, moduleError(verified, "artifact identity", err)
	}

	handle, err := l.opener.Open(artifact.path)
	if err != nil {
		return ModuleInstance{}, moduleError(verified, "open", fmt.Errorf("%w: %w", ErrPluginOpenFailed, err))
	}

	factory, err := lookupFactory(handle)
	if err != nil {
		return ModuleInstance{}, moduleError(verified, "symbol", err)
	}

	pluginObject, err := callFactory(factory)
	if err != nil {
		return ModuleInstance{}, moduleError(verified, "factory", err)
	}

	metadata, err := readMetadata(pluginObject)
	if err != nil {
		return ModuleInstance{}, moduleError(verified, "metadata", err)
	}

	registrar := registry.NewRegistrar(verified.Module)
	if err := callRegister(pluginObject, registrar); err != nil {
		return ModuleInstance{}, moduleError(verified, "register", err)
	}

	if err := registrar.Commit(); err != nil {
		return ModuleInstance{}, moduleError(verified, "register", err)
	}

	return ModuleInstance{
		Plugin:           pluginObject,
		Metadata:         metadata,
		Module:           verified.Module,
		Descriptors:      registrar.Components(),
		PolicyAttributes: registrar.PolicyAttributes(),
		DebugModules:     registry.DebugModulesByModule(verified.Module.Name),
		Capabilities:     registrar.Capabilities(),
		ArtifactPath:     verified.ArtifactPath,
		SignaturePath:    verified.SignaturePath,
		ArtifactDigest:   artifact.digest,
		VerifiedSigner:   verifiedSignerID(verified.Signer),
		ModuleName:       verified.Module.Name,
		Status:           ModuleStatusRegistered,
		Optional:         verified.Module.Optional,
	}, nil
}

// verifiedSignerID returns the trusted signer that actually verified an artifact.
func verifiedSignerID(signer *config.PluginTrustSigner) string {
	if signer == nil {
		return ""
	}

	return signer.ID
}

// lookupFactory resolves and type-checks the required NauthilusPlugin factory.
func lookupFactory(handle PluginHandle) (func() (pluginapi.Plugin, error), error) {
	if handle == nil {
		return nil, fmt.Errorf("%w: plugin handle is nil", ErrFactorySymbolMissing)
	}

	symbol, err := handle.Lookup(pluginFactorySymbol)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFactorySymbolMissing, err)
	}

	factory, ok := symbol.(func() (pluginapi.Plugin, error))
	if !ok {
		return nil, fmt.Errorf("%w: %s must be func() (pluginapi.Plugin, error)", ErrFactorySymbolInvalid, pluginFactorySymbol)
	}

	return factory, nil
}

// callFactory invokes a plugin factory behind a panic boundary.
func callFactory(factory func() (pluginapi.Plugin, error)) (plugin pluginapi.Plugin, err error) {
	defer recoverPluginPanic(&err)

	plugin, err = factory()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFactoryFailed, err)
	}

	if plugin == nil {
		return nil, ErrNilPlugin
	}

	return plugin, nil
}

// readMetadata validates the plugin metadata before registration.
func readMetadata(plugin pluginapi.Plugin) (metadata pluginapi.Metadata, err error) {
	defer recoverPluginPanic(&err)

	metadata = plugin.Metadata()
	if err := pluginapi.ValidateMetadata(metadata); err != nil {
		return pluginapi.Metadata{}, err
	}

	return metadata, nil
}

// callRegister invokes Register behind a panic boundary.
func callRegister(plugin pluginapi.Plugin, registrar pluginapi.Registrar) (err error) {
	defer recoverPluginPanic(&err)

	return plugin.Register(registrar)
}

// recoverPluginPanic turns plugin panics into regular load errors.
func recoverPluginPanic(err *error) {
	if recovered := recover(); recovered != nil {
		*err = ErrPluginPanic
	}
}

// moduleError annotates an error with module name, artifact path, and load step.
func moduleError(verified VerifiedModule, step string, err error) error {
	return &ModuleError{
		Err:          err,
		ModuleName:   verified.Module.Name,
		ArtifactPath: verified.ArtifactPath,
		Step:         step,
	}
}

// failedModuleInstance creates state for a module that did not register.
func failedModuleInstance(verified VerifiedModule, err error) ModuleInstance {
	return ModuleInstance{
		RegistrationError: err,
		Module:            verified.Module,
		ArtifactPath:      verified.ArtifactPath,
		SignaturePath:     verified.SignaturePath,
		ArtifactDigest:    verified.ArtifactDigest,
		VerifiedSigner:    verifiedSignerID(verified.Signer),
		ModuleName:        verified.Module.Name,
		Status:            ModuleStatusFailed,
		Optional:          verified.Module.Optional,
	}
}

// logModuleLoadStart emits a bounded structured record before plugin code is opened.
func (l *Loader) logModuleLoadStart(module VerifiedModule) {
	if l.logger == nil {
		return
	}

	_ = level.Debug(l.logger).Log(
		definitions.LogKeyMsg, "Native plugin module load started",
		"plugin_module", module.Module.Name,
		"plugin_path", module.ArtifactPath,
		"plugin_optional", module.Module.Optional,
	)
}

// logOptionalFailure emits a visible warning for optional plugin failures.
func (l *Loader) logOptionalFailure(instance ModuleInstance) {
	if l.logger == nil {
		return
	}

	_ = level.Warn(l.logger).Log(
		definitions.LogKeyMsg, "Optional plugin module registration failed",
		"plugin_module", instance.ModuleName,
		"plugin_path", instance.ArtifactPath,
		"plugin_failure_step", moduleFailureStep(instance.RegistrationError),
		"plugin_error_class", "module_load",
	)
}

// logRequiredFailure emits a visible error before required module failure aborts startup.
func (l *Loader) logRequiredFailure(instance ModuleInstance) {
	if l.logger == nil {
		return
	}

	_ = level.Error(l.logger).Log(
		definitions.LogKeyMsg, "Required plugin module registration failed",
		"plugin_module", instance.ModuleName,
		"plugin_path", instance.ArtifactPath,
		"plugin_failure_step", moduleFailureStep(instance.RegistrationError),
		"plugin_error_class", "module_load",
	)
}

// logRegistered emits a debug record for a registered module instance.
func (l *Loader) logRegistered(instance ModuleInstance) {
	if l.logger == nil {
		return
	}

	_ = level.Debug(l.logger).Log(
		definitions.LogKeyMsg, "Plugin module registered",
		"plugin_module", instance.ModuleName,
		"plugin_name", instance.Metadata.Name,
		"plugin_version", instance.Metadata.Version,
		"plugin_path", instance.ArtifactPath,
	)
}

type stdlibOpener struct{}

// Open delegates to the Go standard library plugin loader.
func (stdlibOpener) Open(path string) (PluginHandle, error) {
	plugin, err := stdplugin.Open(path)
	if err != nil {
		return nil, err
	}

	return stdlibHandle{plugin: plugin}, nil
}

type stdlibHandle struct {
	plugin *stdplugin.Plugin
}

// Lookup adapts the standard library plugin symbol type to the loader interface.
func (h stdlibHandle) Lookup(symbol string) (any, error) {
	return h.plugin.Lookup(symbol)
}
