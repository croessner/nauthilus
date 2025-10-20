// Copyright (C) 2024 Christian Rößner
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

package config

import (
	"fmt"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/go-playground/validator/v10"
)

type LuaSection struct {
	Actions             []LuaAction         `mapstructure:"actions" validate:"omitempty,dive"`
	Features            []LuaFeature        `mapstructure:"features" validate:"omitempty,dive"`
	Filters             []LuaFilter         `mapstructure:"filters" validate:"omitempty,dive"`
	Hooks               []LuaHooks          `mapstructure:"custom_hooks" validate:"omitempty,dive"`
	Config              *LuaConf            `mapstructure:"config" validate:"omitempty"`
	OptionalLuaBackends map[string]*LuaConf `mapstructure:"optional_lua_backends" validate:"omitempty,dive,validateOptionalLuaBackend"`
	Search              []LuaSearchProtocol `mapstructure:"search" validate:"omitempty,dive"`
}

func (l *LuaSection) String() string {
	if l == nil {
		return "LuaSection: <nil>"
	}

	return fmt.Sprintf("LuaSection: {Config[%+v] Search[%+v]}", l.Config, l.Search)
}

// GetConfig retrieves the `Config` field from the LuaSection. Returns an empty LuaConf if the LuaSection is nil.
func (l *LuaSection) GetConfig() any {
	if l == nil {
		return &LuaConf{}
	}

	if l.Config == nil {
		return &LuaConf{}
	}

	return l.Config
}

// GetProtocols retrieves the search protocols from the LuaSection. Returns an empty slice if the LuaSection is nil.
func (l *LuaSection) GetProtocols() any {
	if l == nil {
		return []LuaSearchProtocol{}
	}

	if l.Search == nil {
		return []LuaSearchProtocol{}
	}

	return l.Search
}

var _ GetterHandler = (*LuaSection)(nil)

// GetOptionalLuaBackends retrieves the `OptionalLuaBackends` field from the LuaSection. Returns an empty map if the LuaSection is nil.
func (l *LuaSection) GetOptionalLuaBackends() map[string]*LuaConf {
	if l == nil {
		return map[string]*LuaConf{}
	}

	if l.OptionalLuaBackends == nil {
		return map[string]*LuaConf{}
	}

	return l.OptionalLuaBackends
}

// GetActions retrieves the list of LuaAction from the LuaSection. Returns an empty slice if the LuaSection is nil.
func (l *LuaSection) GetActions() []LuaAction {
	if l == nil {
		return []LuaAction{}
	}

	return l.Actions
}

// GetFeatures retrieves the list of LuaFeature from the LuaSection. Returns an empty slice if the LuaSection is nil.
func (l *LuaSection) GetFeatures() []LuaFeature {
	if l == nil {
		return []LuaFeature{}
	}

	return l.Features
}

// GetFilters retrieves the list of LuaFilter from the LuaSection. Returns an empty slice if the LuaSection is nil.
func (l *LuaSection) GetFilters() []LuaFilter {
	if l == nil {
		return []LuaFilter{}
	}

	return l.Filters
}

// GetHooks retrieves the list of LuaHooks from the LuaSection. Returns an empty slice if the LuaSection is nil.
func (l *LuaSection) GetHooks() []LuaHooks {
	if l == nil {
		return []LuaHooks{}
	}

	return l.Hooks
}

// validateOptionalLuaBackend checks if a map of LuaConf structs has empty PackagePath and InitScriptPath for all entries.
// Returns false if any entry has a non-empty PackagePath or InitScriptPath, otherwise returns true.
func validateOptionalLuaBackend(fl validator.FieldLevel) bool {
	optBbackend, ok := fl.Field().Interface().(LuaConf)
	if !ok {
		return false
	}

	if optBbackend.PackagePath != "" || optBbackend.InitScriptPath != "" {
		return false
	}

	return true
}

type LuaAction struct {
	ActionType string `mapstructure:"type" validate:"required,oneof=brute_force rbl tls_encryption relay_domains lua post"`
	ScriptName string `mapstructure:"name" validate:"required"`
	ScriptPath string `mapstructure:"script_path" validate:"required,file"`
}

func (l *LuaAction) String() string {
	if l == nil {
		return "<nil>"
	}

	return fmt.Sprintf("{ActionType: %s}, {BackendScriptPath: %s}", l.ActionType, l.ScriptPath)
}

// GetAction returns the ActionType, ScriptName, and ScriptPath of a LuaAction.
// It is a method of the LuaAction struct.
// The ActionType field represents the type of the Lua action.
// The ScriptName field represents the name of the Lua script.
// The ScriptPath field represents the path to the Lua script file.
// It returns these values as strings.
func (l *LuaAction) GetAction() (string, string, string) {
	if l == nil {
		return "", "", ""
	}

	return l.ActionType, l.ScriptName, l.ScriptPath
}

// GetActionType retrieves the ActionType from the LuaAction. Returns an empty string if the LuaAction is nil.
func (l *LuaAction) GetActionType() string {
	if l == nil {
		return ""
	}

	return l.ActionType
}

// GetScriptName retrieves the ScriptName from the LuaAction. Returns an empty string if the LuaAction is nil.
func (l *LuaAction) GetScriptName() string {
	if l == nil {
		return ""
	}

	return l.ScriptName
}

// GetScriptPath retrieves the ScriptPath from the LuaAction. Returns an empty string if the LuaAction is nil.
func (l *LuaAction) GetScriptPath() string {
	if l == nil {
		return ""
	}

	return l.ScriptPath
}

type LuaFeature struct {
	Name       string `mapstructure:"name" validate:"required"`
	ScriptPath string `mapstructure:"script_path" validate:"required,file"`
}

func (l *LuaFeature) String() string {
	if l == nil {
		return "<nil>"
	}

	return fmt.Sprintf("{Name: %s}, {BackendScriptPath: %s}", l.Name, l.ScriptPath)
}

// GetName retrieves the Name from the LuaFeature. Returns an empty string if the LuaFeature is nil.
func (l *LuaFeature) GetName() string {
	if l == nil {
		return ""
	}

	return l.Name
}

// GetScriptPath retrieves the ScriptPath from the LuaFeature. Returns an empty string if the LuaFeature is nil.
func (l *LuaFeature) GetScriptPath() string {
	if l == nil {
		return ""
	}

	return l.ScriptPath
}

type LuaFilter struct {
	Name       string `mapstructure:"name" validate:"required"`
	ScriptPath string `mapstructure:"script_path" validate:"required,file"`
}

func (l *LuaFilter) String() string {
	if l == nil {
		return "<nil>"
	}

	return fmt.Sprintf("{Name: %s}, {BackendScriptPath: %s}", l.Name, l.ScriptPath)
}

// GetName retrieves the Name from the LuaFilter. Returns an empty string if the LuaFilter is nil.
func (l *LuaFilter) GetName() string {
	if l == nil {
		return ""
	}

	return l.Name
}

// GetScriptPath retrieves the ScriptPath from the LuaFilter. Returns an empty string if the LuaFilter is nil.
func (l *LuaFilter) GetScriptPath() string {
	if l == nil {
		return ""
	}

	return l.ScriptPath
}

type LuaConf struct {
	NumberOfWorkers   int      `mapstructure:"number_of_workers" validate:"omitempty,min=1,max=1000000"`
	QueueLength       int      `mapstructure:"queue_length" validate:"omitempty,min=0"`
	PackagePath       string   `mapstructure:"package_path"`
	BackendScriptPath string   `mapstructure:"backend_script_path" validate:"omitempty,file"`
	InitScriptPath    string   `mapstructure:"init_script_path" validate:"omitempty,file"`
	InitScriptPaths   []string `mapstructure:"init_script_paths" validate:"omitempty,dive,file"`
}

func (l *LuaConf) String() string {
	if l == nil {
		return "<nil>"
	}

	return l.BackendScriptPath
}

// GetNumberOfWorkers returns the number of workers configured in the LuaConf object. Defaults to 0 if the receiver is nil.
func (l *LuaConf) GetNumberOfWorkers() int {
	if l == nil {
		return definitions.DefaultNumberOfWorkers
	}

	if l.NumberOfWorkers == 0 {
		return definitions.DefaultNumberOfWorkers
	}

	return l.NumberOfWorkers
}

// GetQueueLength returns the max queue length for Lua backend requests; 0 means unlimited.
func (l *LuaConf) GetQueueLength() int {
	if l == nil || l.QueueLength < 0 {
		return 0
	}

	return l.QueueLength
}

// GetPackagePath retrieves the PackagePath from the LuaConf. Returns an empty string if the LuaConf is nil.
func (l *LuaConf) GetPackagePath() string {
	if l == nil {
		return ""
	}

	return l.PackagePath
}

// GetBackendScriptPath retrieves the BackendScriptPath from the LuaConf. Returns an empty string if the LuaConf is nil.
func (l *LuaConf) GetBackendScriptPath() string {
	if l == nil {
		return ""
	}

	return l.BackendScriptPath
}

// GetInitScriptPath retrieves the InitScriptPath from the LuaConf. Returns an empty string if the LuaConf is nil.
func (l *LuaConf) GetInitScriptPath() string {
	if l == nil {
		return ""
	}

	return l.InitScriptPath
}

// GetInitScriptPaths retrieves the InitScriptPaths from the LuaConf. Returns an empty slice if the LuaConf is nil.
func (l *LuaConf) GetInitScriptPaths() []string {
	if l == nil {
		return []string{}
	}

	return l.InitScriptPaths
}

type LuaSearchProtocol struct {
	Protocols   []string `mapstructure:"protocol"`
	CacheName   string   `mapstructure:"cache_name" validate:"required,printascii,excludesall= "`
	BackendName string   `mapstructure:"backend_name" validate:"omitempty,printascii,excludesall= "`
}

// GetCacheName returns the Redis cache domain. It returns a DetailedError, if no value has
// been configured.
func (l *LuaSearchProtocol) GetCacheName() (string, error) {
	if l == nil || l.CacheName == "" {
		return "", errors.ErrLuaConfig.WithDetail("No cache name setting")
	}

	return l.CacheName, nil
}

// GetBackendName returns the backend name configured in LuaSearchProtocol or a default value if not specified.
func (l *LuaSearchProtocol) GetBackendName() string {
	if l == nil || l.BackendName == "" {
		return definitions.DefaultBackendName
	}

	return l.BackendName
}

// GetProtocols retrieves the list of protocols from the LuaSearchProtocol. Returns an empty slice if the LuaSearchProtocol is nil or if the Protocols field is nil.
func (l *LuaSearchProtocol) GetProtocols() []string {
	if l == nil {
		return []string{}
	}

	if l.Protocols == nil {
		return []string{}
	}

	return l.Protocols
}

type LuaHooks struct {
	Location    string   `mapstructure:"http_location" validate:"required,printascii,excludesall= "`
	Method      string   `mapstructure:"http_method" validate:"required,oneof=HEAD GET POST PUT DELETE PATCH"`
	ContentType string   `mapstructure:"content_type" validate:"omitempty,printascii,excludesall= "`
	ScriptPath  string   `mapstructure:"script_path" validate:"required,file"`
	Roles       []string `mapstructure:"roles"`
}

func (l *LuaHooks) String() string {
	if l == nil {
		return "<nil>"
	}

	return fmt.Sprintf("{Location: %s}, {Method: %s}, {ScriptPath: %s}, {Roles: %v}", l.Location, l.Method, l.ScriptPath, l.Roles)
}

// GetRoles returns the roles configured for the hook. If no roles are configured, it returns an empty slice.
func (l *LuaHooks) GetRoles() []string {
	if l == nil {
		return []string{}
	}

	return l.Roles
}

// GetLocation retrieves the Location from the LuaHooks. Returns an empty string if the LuaHooks is nil.
func (l *LuaHooks) GetLocation() string {
	if l == nil {
		return ""
	}

	return l.Location
}

// GetContentType retrieves the Content-Type from the LuaHooks. Returns "application/json" if the LuaHooks is nil or
// the ContentType is an empty string
func (l *LuaHooks) GetContentType() string {
	if l == nil {
		return "application/json"
	}

	if l.ContentType == "" {
		return "application/json"
	}

	return l.ContentType
}

// GetMethod retrieves the Method from the LuaHooks. Returns an empty string if the LuaHooks is nil.
func (l *LuaHooks) GetMethod() string {
	if l == nil {
		return ""
	}

	return l.Method
}

// GetScriptPath retrieves the ScriptPath from the LuaHooks. Returns an empty string if the LuaHooks is nil.
func (l *LuaHooks) GetScriptPath() string {
	if l == nil {
		return ""
	}

	return l.ScriptPath
}
