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

package pluginruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

var (
	// ErrReconfigureFailed wraps Reconfigure failures reported after a reload was committed.
	ErrReconfigureFailed = errors.New("plugin reconfiguration failed")

	// ErrReconfigurePlanStale is returned when another reload changed the plugin state after preparation.
	ErrReconfigurePlanStale = errors.New("plugin reconfiguration plan is stale")
)

const (
	methodReconfigure         = "Reconfigure"
	methodValidateReconfigure = "ValidateReconfigure"
)

// ReconfigurePlan is one validated, not yet applied set of plugin config changes.
//
// A plan is produced by Runner.PrepareReconfigure and finished exactly once by Commit or
// Discard. Preparation has no side effects, so discarding a plan only reports its outcome.
// A nil plan is valid and has nothing to apply.
type ReconfigurePlan struct {
	runner  *Runner
	next    *config.PluginsSection
	changes []moduleChange
	version uint64
	once    sync.Once
}

// Reconfigure validates and applies config-only plugin reloads in one step.
func (r *Runner) Reconfigure(ctx context.Context, file config.File) error {
	plan, err := r.PrepareReconfigure(ctx, file)
	if err != nil {
		return err
	}

	return plan.Commit(ctx)
}

// PrepareReconfigure classifies a candidate plugin section and validates every changed module.
//
// Restart-bound changes and every ValidateReconfigure failure reject the whole candidate; all
// causes are joined into the returned error and no module state changes.
func (r *Runner) PrepareReconfigure(ctx context.Context, file config.File) (*ReconfigurePlan, error) {
	if r == nil {
		return nil, nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	next := pluginSectionFromFile(file)
	plan := &ReconfigurePlan{runner: r, next: next, version: r.configVersion}

	changes, err := r.classifier.classify(r.pluginConfig, next)
	if err != nil && changes == nil {
		r.observeReload(ReloadRecord{Result: ReloadResultRestartRequired})

		return nil, err
	}

	plan.changes = changes

	errs := []error{err}
	if err == nil {
		errs = append(errs, r.validatePendingLocked(ctx, plan))
	}

	if err = errors.Join(errs...); err != nil {
		plan.Discard()

		return nil, err
	}

	if plan.pending() > 0 && (r.stopping || r.stopped) {
		plan.Discard()

		return nil, ErrNotReady
	}

	return plan, nil
}

// pluginSectionFromFile returns the cloned plugin section from a config file.
func pluginSectionFromFile(file config.File) *config.PluginsSection {
	if file == nil {
		return clonePluginSection(nil)
	}

	return clonePluginSection(file.GetPlugins())
}

// validatePendingLocked asks every changed reloadable module to validate its candidate config.
func (r *Runner) validatePendingLocked(ctx context.Context, plan *ReconfigurePlan) error {
	var errs []error

	for index := range plan.changes {
		change := &plan.changes[index]
		if change.result != reloadResultPending {
			continue
		}

		result, err := r.validateModuleLocked(ctx, change)
		if err != nil {
			change.result = result

			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// validateModuleLocked runs one optional ValidateReconfigure call and maps its error to a bounded result.
func (r *Runner) validateModuleLocked(ctx context.Context, change *moduleChange) (ReloadResult, error) {
	index, registered := r.moduleIndex[change.name]
	if !registered {
		return ReloadResultRestartRequired, fmt.Errorf("%w: plugin module %q is not registered", ErrRestartRequired, change.name)
	}

	if _, failed := r.failedModules[change.name]; failed {
		return ReloadResultRestartRequired, fmt.Errorf("%w: plugin module %q failed to start", ErrRestartRequired, change.name)
	}

	instance := r.modules[index].instance

	validator, ok := instance.Plugin.(pluginapi.ReconfigureValidator)
	if !ok {
		return reloadResultPending, nil
	}

	view := pluginregistry.NewConfigView(change.next.Config)

	err := r.invoke(ctx, moduleInvokeSpec(instance.ModuleName, methodValidateReconfigure), func(callCtx context.Context) error {
		return validator.ValidateReconfigure(callCtx, view)
	})

	switch {
	case err == nil:
		return reloadResultPending, nil
	case errors.Is(err, pluginapi.ErrRestartRequired):
		return ReloadResultRestartRequired, fmt.Errorf("%w: plugin module %q: %w", ErrRestartRequired, change.name, err)
	default:
		return ReloadResultRejected, fmt.Errorf("plugin module %q rejected its configuration: %w", change.name, err)
	}
}

// Commit applies every validated change in module declaration order.
//
// A module whose Reconfigure fails keeps its previous config view, and the runner keeps the
// previous module config as its baseline so that the next reload retries the change. The
// remaining modules are still applied. Failures are joined and wrap ErrReconfigureFailed.
func (p *ReconfigurePlan) Commit(ctx context.Context) error {
	if p == nil {
		return nil
	}

	var err error

	p.once.Do(func() {
		err = p.runner.commitReconfigure(ctx, p)
	})

	return err
}

// Discard finishes a plan without applying it and reports its validated changes as aborted.
func (p *ReconfigurePlan) Discard() {
	if p == nil {
		return
	}

	p.once.Do(func() {
		p.abortPending()
		p.runner.observePlan(p)
	})
}

// pending counts the validated changes that wait for commit.
func (p *ReconfigurePlan) pending() int {
	count := 0

	for _, change := range p.changes {
		if change.result == reloadResultPending {
			count++
		}
	}

	return count
}

// abortPending marks every change that was not applied.
func (p *ReconfigurePlan) abortPending() {
	for index := range p.changes {
		if p.changes[index].result == reloadResultPending {
			p.changes[index].result = ReloadResultAborted
		}
	}
}

// commitReconfigure calls Reconfigure for each pending change and publishes the applied config views.
func (r *Runner) commitReconfigure(ctx context.Context, plan *ReconfigurePlan) error {
	r.reconfigureMu.Lock()
	defer r.reconfigureMu.Unlock()

	defer r.observePlan(plan)

	if plan.pending() == 0 {
		return nil
	}

	r.mu.RLock()

	if err := r.commitPreconditionLocked(plan); err != nil {
		r.mu.RUnlock()
		plan.abortPending()

		return err
	}

	errs := r.reconfigureModulesLocked(ctx, plan)
	r.mu.RUnlock()

	r.mu.Lock()
	r.publishReconfiguredLocked(plan)
	r.mu.Unlock()

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrReconfigureFailed, err)
	}

	return nil
}

// commitPreconditionLocked rejects plans prepared against an older runner state or a stopping runner.
func (r *Runner) commitPreconditionLocked(plan *ReconfigurePlan) error {
	if plan.version != r.configVersion {
		return ErrReconfigurePlanStale
	}

	if r.stopping || r.stopped {
		return ErrNotReady
	}

	return nil
}

// reconfigureModulesLocked calls Reconfigure in declaration order while the caller holds the read lock.
//
// Holding the read lock keeps Stop from running concurrently while request-time calls continue.
func (r *Runner) reconfigureModulesLocked(ctx context.Context, plan *ReconfigurePlan) []error {
	var errs []error

	for index := range plan.changes {
		change := &plan.changes[index]
		if change.result != reloadResultPending {
			continue
		}

		instance := r.modules[r.moduleIndex[change.name]].instance
		if err := r.reconfigureModule(ctx, instance, change.next); err != nil {
			change.result = ReloadResultFailed

			errs = append(errs, err)

			continue
		}

		change.result = ReloadResultReloaded
	}

	return errs
}

// reconfigureModule invokes one reloadable plugin module.
func (r *Runner) reconfigureModule(
	ctx context.Context,
	instance pluginloader.ModuleInstance,
	nextModule config.PluginModule,
) error {
	reloadable, ok := instance.Plugin.(pluginapi.ReloadablePlugin)
	if !ok {
		return fmt.Errorf("%w: plugin module %q does not support config reload", ErrRestartRequired, instance.ModuleName)
	}

	view := pluginregistry.NewConfigView(nextModule.Config)

	if err := r.invoke(ctx, moduleInvokeSpec(instance.ModuleName, methodReconfigure), func(callCtx context.Context) error {
		return reloadable.Reconfigure(callCtx, view)
	}); err != nil {
		return fmt.Errorf("plugin module %q Reconfigure failed: %w", instance.ModuleName, err)
	}

	return nil
}

// publishReconfiguredLocked swaps host-owned config views of reloaded modules and advances the baseline.
//
// Failed modules keep their previous config in both places.
func (r *Runner) publishReconfiguredLocked(plan *ReconfigurePlan) {
	baseline := clonePluginSection(plan.next)
	current := clonePluginSection(r.pluginConfig)

	for index, change := range plan.changes {
		switch change.result {
		case ReloadResultReloaded:
			instance := &r.modules[r.moduleIndex[change.name]].instance
			instance.Module.Config = cloneConfigMap(change.next.Config)
		case ReloadResultFailed:
			baseline.Modules[index].Config = cloneConfigMap(current.Modules[index].Config)
		}
	}

	r.pluginConfig = baseline
	r.configVersion++
}

// observePlan emits one record per configured module of a finished plan.
func (r *Runner) observePlan(plan *ReconfigurePlan) {
	for _, change := range plan.changes {
		r.observeReload(ReloadRecord{ModuleName: change.name, Result: change.result})
	}
}

// observeReload forwards one reload record to an observer that supports reload observation.
func (r *Runner) observeReload(record ReloadRecord) {
	observer, ok := r.observer.(ReloadObserver)
	if !ok {
		return
	}

	defer func() {
		_ = recover()
	}()

	observer.ObservePluginReload(record)
}

// moduleInvokeSpec builds the observation scope of one module-level lifecycle method.
func moduleInvokeSpec(moduleName string, method string) invokeSpec {
	return invokeSpec{
		moduleName:     moduleName,
		componentName:  moduleName,
		extensionPoint: extensionPointPlugin,
		method:         method,
	}
}
