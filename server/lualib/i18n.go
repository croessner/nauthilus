// Copyright (C) 2026 Christian Rößner
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

package lualib

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"

	lua "github.com/yuin/gopher-lua"
)

// I18NMode controls whether the Lua module runs during startup or request time.
type I18NMode uint8

const (
	// I18NModeRequest exposes read-only localization helpers.
	I18NModeRequest I18NMode = iota

	// I18NModeStartup allows deployment catalog registration.
	I18NModeStartup
)

// I18NRuntimeOptions configures the Lua i18n runtime.
type I18NRuntimeOptions struct {
	Registry          *localization.CatalogRegistry
	Resolver          localization.MessageResolver
	Logger            *slog.Logger
	DefaultPreference localization.LanguagePreference
	DefaultLanguage   string
	MaxLength         int
}

// I18NRuntime owns resolver and catalog dependencies shared by Lua states.
type I18NRuntime struct {
	Registry          *localization.CatalogRegistry
	Resolver          localization.MessageResolver
	Logger            *slog.Logger
	catalogSession    *I18NCatalogSession
	DefaultPreference localization.LanguagePreference
	DefaultLanguage   string
	MaxLength         int
}

// I18NCatalogSession collects startup overlays until the init script succeeds.
type I18NCatalogSession struct {
	base     *I18NRuntime
	overlays []localization.CatalogOverlay
	mu       sync.Mutex
}

// NewI18NRuntime creates a Lua i18n runtime with safe empty defaults.
func NewI18NRuntime(options I18NRuntimeOptions) *I18NRuntime {
	registry := options.Registry
	if registry == nil {
		registry = newEmptyI18NRegistry()
	}

	return &I18NRuntime{
		Registry:          registry,
		Resolver:          options.Resolver,
		Logger:            options.Logger,
		DefaultPreference: options.DefaultPreference,
		DefaultLanguage:   strings.TrimSpace(options.DefaultLanguage),
		MaxLength:         options.MaxLength,
	}
}

// NewCatalogSession returns a runtime that validates startup catalog overlays before activation.
func (r *I18NRuntime) NewCatalogSession() *I18NRuntime {
	base := resolveI18NRuntime(r)

	return &I18NRuntime{
		Registry:          base.Registry,
		Resolver:          base.Resolver,
		Logger:            base.Logger,
		catalogSession:    &I18NCatalogSession{base: base},
		DefaultPreference: base.DefaultPreference,
		DefaultLanguage:   base.DefaultLanguage,
		MaxLength:         base.MaxLength,
	}
}

// CommitCatalogSession activates collected startup overlays atomically.
func (r *I18NRuntime) CommitCatalogSession() error {
	if r == nil || r.catalogSession == nil {
		return nil
	}

	overrides, err := r.catalogSession.commit()
	if err != nil {
		return err
	}

	r.logOverrides(overrides)

	return nil
}

var defaultI18NRuntime = struct {
	runtime *I18NRuntime
	mu      sync.RWMutex
}{
	runtime: NewI18NRuntime(I18NRuntimeOptions{}),
}

// SetDefaultI18NRuntime replaces the process-wide Lua i18n runtime.
func SetDefaultI18NRuntime(runtime *I18NRuntime) {
	defaultI18NRuntime.mu.Lock()
	defer defaultI18NRuntime.mu.Unlock()

	if runtime == nil {
		runtime = NewI18NRuntime(I18NRuntimeOptions{})
	}

	defaultI18NRuntime.runtime = runtime
}

// ConfigureDefaultI18NRuntime builds the process-wide runtime from a system catalog.
func ConfigureDefaultI18NRuntime(system localization.Catalog, defaultLanguage string, logger *slog.Logger) error {
	if system == nil {
		system = localization.NewMapCatalog(nil)
	}

	registry, err := localization.NewCatalogRegistry(system)
	if err != nil {
		return err
	}

	SetDefaultI18NRuntime(NewI18NRuntime(I18NRuntimeOptions{
		Registry:        registry,
		Logger:          logger,
		DefaultLanguage: defaultLanguage,
		DefaultPreference: localization.LanguagePreference{
			Default: defaultLanguage,
		},
	}))

	return nil
}

// DefaultI18NRuntime returns the currently configured process-wide Lua i18n runtime.
func DefaultI18NRuntime() *I18NRuntime {
	defaultI18NRuntime.mu.RLock()
	defer defaultI18NRuntime.mu.RUnlock()

	return defaultI18NRuntime.runtime
}

// LoaderModI18N returns the nauthilus_i18n Lua module.
func LoaderModI18N(runtime *I18NRuntime, mode I18NMode) lua.LGFunction {
	return func(L *lua.LState) int {
		module := &i18nModule{
			runtime: resolveI18NRuntime(runtime),
			mode:    mode,
		}
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnI18NGetLocalized:    module.getLocalized,
			definitions.LuaFnI18NRegisterCatalog: module.registerCatalog,
		})
		L.Push(mod)

		return 1
	}
}

// LoaderI18NStateless returns the default request-time i18n module.
func LoaderI18NStateless() lua.LGFunction {
	return LoaderModI18N(nil, I18NModeRequest)
}

type i18nModule struct {
	runtime *I18NRuntime
	mode    I18NMode
}

func (m *i18nModule) getLocalized(L *lua.LState) int {
	table, ok := checkSingleTableArgument(L, definitions.LuaFnI18NGetLocalized)
	if !ok {
		return 0
	}

	key, ok := requiredI18NStringField(L, table, "i18n_key")
	if !ok {
		return 0
	}

	fallback, ok := requiredI18NStringField(L, table, "fallback")
	if !ok {
		return 0
	}

	languageName, ok := optionalI18NStringField(L, table, "language")
	if !ok {
		return 0
	}

	runtime := resolveI18NRuntime(m.runtime)
	preference := runtime.DefaultPreference
	if strings.TrimSpace(languageName) != "" {
		preference.Explicit = strings.TrimSpace(languageName)
	}

	ctx := L.Context()
	if ctx == nil {
		L.RaiseError("nauthilus_i18n context is not available")

		return 0
	}

	resolved := runtime.resolver().ResolveStatusMessage(
		ctx,
		localization.StatusMessage{
			Text:      fallback,
			I18NKey:   key,
			MaxLength: runtime.MaxLength,
		},
		preference,
	)

	result := L.NewTable()
	L.SetField(result, "message", lua.LString(resolved.Text))
	L.SetField(result, "language", lua.LString(resolved.Language))
	L.SetField(result, "localized", lua.LBool(resolved.Localized))
	L.SetField(result, "i18n_key", lua.LString(resolved.Key))
	L.SetField(result, "fallback_used", lua.LBool(resolved.FallbackUsed))
	L.Push(result)

	return 1
}

func (m *i18nModule) registerCatalog(L *lua.LState) int {
	if m.mode != I18NModeStartup {
		L.RaiseError("register_catalog is only available during startup Lua execution")

		return 0
	}

	table, ok := checkSingleTableArgument(L, definitions.LuaFnI18NRegisterCatalog)
	if !ok {
		return 0
	}

	languageName, ok := requiredI18NStringField(L, table, "language")
	if !ok {
		return 0
	}

	namespace, ok := optionalI18NStringField(L, table, "namespace")
	if !ok {
		return 0
	}

	entries, ok := i18nEntriesFromTable(L, table.RawGetString("entries"))
	if !ok {
		return 0
	}

	runtime := resolveI18NRuntime(m.runtime)
	overrides, err := runtime.registerOverlay(localization.CatalogOverlay{
		Entries: map[string]map[string]string{
			languageName: entries,
		},
		Namespace: namespace,
	})
	if err != nil {
		L.RaiseError("%s", err.Error())

		return 0
	}

	runtime.logOverrides(overrides)

	return 0
}

func (r *I18NRuntime) registerOverlay(overlay localization.CatalogOverlay) ([]localization.CatalogOverride, error) {
	if r == nil || r.Registry == nil {
		return nil, localization.ErrNilCatalog
	}

	if r.catalogSession != nil {
		return r.catalogSession.registerOverlay(overlay)
	}

	return r.Registry.RegisterOverlay(overlay)
}

func (s *I18NCatalogSession) registerOverlay(overlay localization.CatalogOverlay) ([]localization.CatalogOverride, error) {
	if s == nil || s.base == nil || s.base.Registry == nil {
		return nil, localization.ErrNilCatalog
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	next := append(localization.CloneCatalogOverlays(s.overlays), localization.CloneCatalogOverlay(overlay))
	overrides, err := s.base.Registry.ValidateAdditionalOverlays(next...)
	if err != nil {
		return nil, err
	}

	s.overlays = localization.CloneCatalogOverlays(next)

	return overrides, nil
}

func (s *I18NCatalogSession) commit() ([]localization.CatalogOverride, error) {
	if s == nil || s.base == nil || s.base.Registry == nil {
		return nil, localization.ErrNilCatalog
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.overlays) == 0 {
		return nil, nil
	}

	return s.base.Registry.RegisterOverlays(s.overlays...)
}

func (r *I18NRuntime) resolver() localization.MessageResolver {
	if r == nil {
		return localization.NewResolver(nil, "")
	}

	if r.Resolver != nil {
		return r.Resolver
	}

	return localization.NewResolver(r.activeCatalog(), r.DefaultLanguage)
}

func (r *I18NRuntime) activeCatalog() *localization.EffectiveCatalog {
	if r == nil || r.Registry == nil {
		return nil
	}

	return r.Registry.Active()
}

func (r *I18NRuntime) logOverrides(overrides []localization.CatalogOverride) {
	if r == nil || r.Logger == nil {
		return
	}

	for _, override := range overrides {
		r.Logger.Info(
			"deployment localization catalog entry overrides an existing entry",
			"language", override.Language,
			"i18n_key", override.Key,
			"namespace", override.Namespace,
			"previous_namespace", override.PreviousNamespace,
		)
	}
}

func resolveI18NRuntime(runtime *I18NRuntime) *I18NRuntime {
	if runtime != nil {
		return runtime
	}

	return DefaultI18NRuntime()
}

func newEmptyI18NRegistry() *localization.CatalogRegistry {
	registry, err := localization.NewCatalogRegistry(localization.NewMapCatalog(nil))
	if err != nil {
		panic(fmt.Sprintf("create empty i18n registry: %v", err))
	}

	return registry
}

func checkSingleTableArgument(L *lua.LState, functionName string) (*lua.LTable, bool) {
	if L.GetTop() != 1 || L.Get(1).Type() != lua.LTTable {
		L.RaiseError("%s expects exactly one table argument", functionName)

		return nil, false
	}

	return L.CheckTable(1), true
}

func requiredI18NStringField(L *lua.LState, table *lua.LTable, field string) (string, bool) {
	value := table.RawGetString(field)
	if value.Type() != lua.LTString {
		L.RaiseError("%s must be a non-empty string", field)

		return "", false
	}

	text := strings.TrimSpace(string(value.(lua.LString)))
	if text == "" {
		L.RaiseError("%s must be a non-empty string", field)

		return "", false
	}

	return text, true
}

func optionalI18NStringField(L *lua.LState, table *lua.LTable, field string) (string, bool) {
	value := table.RawGetString(field)
	if value == lua.LNil {
		return "", true
	}

	if value.Type() != lua.LTString {
		L.RaiseError("%s must be a string when provided", field)

		return "", false
	}

	return strings.TrimSpace(string(value.(lua.LString))), true
}

func i18nEntriesFromTable(L *lua.LState, value lua.LValue) (map[string]string, bool) {
	entriesTable, ok := value.(*lua.LTable)
	if !ok {
		L.RaiseError("entries must be a table")

		return nil, false
	}

	entries := make(map[string]string)
	valid := true
	entriesTable.ForEach(func(key lua.LValue, entry lua.LValue) {
		if !valid {
			return
		}

		if key.Type() != lua.LTString {
			L.RaiseError("entries keys must be strings")
			valid = false

			return
		}

		if entry.Type() != lua.LTString {
			L.RaiseError("entries values must be strings")
			valid = false

			return
		}

		entryKey := strings.TrimSpace(string(key.(lua.LString)))
		if entryKey == "" {
			L.RaiseError("entries keys must be non-empty strings")
			valid = false

			return
		}

		entries[entryKey] = string(entry.(lua.LString))
	})
	if !valid {
		return nil, false
	}

	if len(entries) == 0 {
		L.RaiseError("entries must contain at least one message")

		return nil, false
	}

	return entries, true
}
