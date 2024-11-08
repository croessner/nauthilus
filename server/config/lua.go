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

	"github.com/croessner/nauthilus/server/errors"
)

type LuaSection struct {
	Actions  []LuaAction
	Features []LuaFeature
	Filters  []LuaFilter
	Config   *LuaConf
	Search   []LuaSearchProtocol
}

func (l *LuaSection) String() string {
	return fmt.Sprintf("LuaSection: {Config[%+v] Search[%+v]}", l.Config, l.Search)
}

func (l *LuaSection) GetConfig() any {
	if l == nil {
		return nil
	}

	return l.Config
}

func (l *LuaSection) GetProtocols() any {
	if l == nil {
		return nil
	}

	return l.Search
}

var _ GetterHandler = (*LuaSection)(nil)

type LuaAction struct {
	ActionType string `mapstructure:"type"`
	ScriptName string `mapstructure:"name"`
	ScriptPath string `mapstructure:"script_path"`
}

func (l *LuaAction) String() string {
	return fmt.Sprintf("{ActionType: %s}, {BackendScriptPath: %s}", l.ActionType, l.ScriptPath)
}

// GetAction returns the ActionType, ScriptName, and ScriptPath of a LuaAction.
// It is a method of the LuaAction struct.
// The ActionType field represents the type of the Lua action.
// The ScriptName field represents the name of the Lua script.
// The ScriptPath field represents the path to the Lua script file.
// It returns these values as strings.
func (l *LuaAction) GetAction() (string, string, string) {
	return l.ActionType, l.ScriptName, l.ScriptPath
}

type LuaFeature struct {
	Name       string
	ScriptPath string `mapstructure:"script_path"`
}

func (l *LuaFeature) String() string {
	return fmt.Sprintf("{Name: %s}, {BackendScriptPath: %s}", l.Name, l.ScriptPath)
}

type LuaFilter struct {
	Name       string
	ScriptPath string `mapstructure:"script_path"`
}

func (l *LuaFilter) String() string {
	return fmt.Sprintf("{Name: %s}, {BackendScriptPath: %s}", l.Name, l.ScriptPath)
}

type LuaConf struct {
	PackagePath        string `mapstructure:"package_path"`
	BackendScriptPath  string `mapstructure:"backend_script_path"`
	CallbackScriptPath string `mapstructure:"callback_script_path"`
	InitScriptPath     string `mapstructure:"init_script_path"`
}

func (l *LuaConf) String() string {
	return l.BackendScriptPath
}

type LuaSearchProtocol struct {
	Protocols []string `mapstructure:"protocol"`
	CacheName string   `mapstructure:"cache_name"`
}

// GetCacheName returns the Redis cache domain. It returns a DetailedError, if no value has
// been configured.
func (l *LuaSearchProtocol) GetCacheName() (string, error) {
	if l.CacheName == "" {
		return "", errors.ErrLuaConfig.WithDetail("No cache name setting")
	}

	return l.CacheName, nil
}
