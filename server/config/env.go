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
	"strings"

	"github.com/spf13/viper"
)

// environment represents the environment configuration for the application
// It is a pointer to the EnvironmentSettings type
var environment Environment

// GetEnvironment returns the singleton instance of the environmentSettings configuration. Panics if the environment is uninitialized.
func GetEnvironment() Environment {
	if environment == nil {
		panic("environment not initialized")
	}

	return environment
}

// Environment defines methods for accessing application configuration settings.
type Environment interface {
	// GetDevMode indicates whether the application is in developer mode.
	GetDevMode() bool
}

// EnvironmentSettings represents overall configuration settings for the application.
type EnvironmentSettings struct {
	// DevMode indicates whether the application is running in developer mode.
	DevMode bool
}

var _ Environment = (*EnvironmentSettings)(nil)

// GetDevMode returns the DevMode value, indicating whether the application is running in developer mode.
func (env *EnvironmentSettings) GetDevMode() bool {
	if env == nil {
		return false
	}

	return env.DevMode
}

// setCommonDefaultEnvVars sets default values for commonly used environment variables related to backend services configuration.
func setCommonDefaultEnvVars() {
	viper.SetDefault("developer_mode", false)
}

// setDefaultEnvVars initializes default environment variables using the viper package for configuration management.
func setDefaultEnvVars() {
	viper.SetEnvPrefix("nauthilus")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	setCommonDefaultEnvVars()

	viper.AllowEmptyEnv(true)
	viper.AutomaticEnv()
}

// String returns the name of the Config object.
func (env *EnvironmentSettings) String() string {
	if env == nil {
		return "<nil>"
	}

	return fmt.Sprintf("DevMode='%v'", env.DevMode)
}

// setConfigFromEnvVars initializes configuration fields from environment variables using the viper package.
func (env *EnvironmentSettings) setConfigFromEnvVars() {
	env.DevMode = viper.GetBool("developer_mode")
}

// NewEnvironmentConfig initializes and returns a singleton instance of EnvironmentSettings, setting default and custom configurations.
func NewEnvironmentConfig() Environment {
	if environment != nil {
		return environment
	}

	setDefaultEnvVars()

	newCfg := &EnvironmentSettings{}

	newCfg.setConfigFromEnvVars()

	environment = newCfg

	return newCfg
}

// NewTestEnvironmentConfig creates and returns a new instance of Environment with default settings.
func NewTestEnvironmentConfig() Environment {
	return &EnvironmentSettings{}
}

// SetTestEnvironmentConfig sets the environment configuration for the test environment using the provided Environment interface.
func SetTestEnvironmentConfig(env Environment) {
	environment = env
}
