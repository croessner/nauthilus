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

type LuaAction struct {
	ActionType string `mapstructure:"type"`
	ScriptPath string `mapstructure:"script_path"`
}

func (l *LuaAction) String() string {
	return fmt.Sprintf("{ActionType: %s}, {ScriptPath: %s}", l.ActionType, l.ScriptPath)
}

// GetAction returns the action type and a path to a Lua script as defined in the LuaAction struct.
func (l *LuaAction) GetAction() (string, string) {
	return l.ActionType, l.ScriptPath
}

type LuaFeature struct {
	Name       string
	ScriptPath string `mapstructure:"script_path"`
}

func (l *LuaFeature) String() string {
	return fmt.Sprintf("{Name: %s}, {ScriptPath: %s}", l.Name, l.ScriptPath)
}

type LuaFilter struct {
	Name       string
	ScriptPath string `mapstructure:"script_path"`
}

func (l *LuaFilter) String() string {
	return fmt.Sprintf("{Name: %s}, {ScriptPath: %s}", l.Name, l.ScriptPath)
}

type LuaConf struct {
	PackagePath string `mapstructure:"package_path"`
	ScriptPath  string `mapstructure:"script_path"`
}

func (l *LuaConf) String() string {
	return l.ScriptPath
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
