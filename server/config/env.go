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
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
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
	// GetSMTPBackendAddress returns the address of the SMTP backend server.
	GetSMTPBackendAddress() string

	// GetSMTPBackendPort returns the port of the SMTP backend server.
	GetSMTPBackendPort() int

	// GetIMAPBackendAddress returns the address of the IMAP backend server.
	GetIMAPBackendAddress() string

	// GetIMAPBackendPort returns the port of the IMAP backend server.
	GetIMAPBackendPort() int

	// GetPOP3BackendAddress returns the address of the POP3 backend server.
	GetPOP3BackendAddress() string

	// GetPOP3BackendPort returns the port of the POP3 backend server.
	GetPOP3BackendPort() int

	// GetWaitDelay returns the delay between connection attempts in seconds.
	GetWaitDelay() uint8

	// GetMaxLoginAttempts returns the maximum number of allowed login attempts.
	GetMaxLoginAttempts() uint8

	// GetDevMode indicates whether the application is in developer mode.
	GetDevMode() bool

	// GetMaxActionWorkers returns the maximum number of simultaneous action workers.
	GetMaxActionWorkers() uint16

	// GetLocalCacheAuthTTL returns the time-to-live duration for local cache authentication.
	GetLocalCacheAuthTTL() time.Duration
}

// EnvironmentSettings represents overall configuration settings for the application.
type EnvironmentSettings struct {
	// SMTPBackendAddress is the address of the SMTP backend server.
	SMTPBackendAddress string

	// SMTPBackendPort is the port of the SMTP backend server.
	SMTPBackendPort int

	// IMAPBackendAddress is the address of the IMAP backend server.
	IMAPBackendAddress string

	// IMAPBackendPort is the port of the IMAP backend server.
	IMAPBackendPort int

	// POP3BackendAddress is the address of the POP3 backend server.
	POP3BackendAddress string

	// POP3BackendPort is the port of the IMAP POP3 server.
	POP3BackendPort int

	// WaitDelay is the time in seconds to wait between connection attempts.
	WaitDelay uint8

	// MaxLoginAttempts is the maximum number of login attempts.
	MaxLoginAttempts uint8

	// DevMode indicates whether the application is running in developer mode.
	DevMode bool

	// MaxActionWorkers is the maximum number of action workers that can be run simultaneously.
	MaxActionWorkers uint16

	// LocalCacheAuthTTL
	LocalCacheAuthTTL time.Duration
}

var _ Environment = (*EnvironmentSettings)(nil)

// GetSMTPBackendAddress retrieves the address of the SMTP backend server from the EnvironmentSettings instance.
func (env *EnvironmentSettings) GetSMTPBackendAddress() string {
	if env == nil {
		return ""
	}

	return env.SMTPBackendAddress
}

// GetSMTPBackendPort retrieves the port of the SMTP backend server from the EnvironmentSettings instance.
func (env *EnvironmentSettings) GetSMTPBackendPort() int {
	if env == nil {
		return 0
	}

	return env.SMTPBackendPort
}

// GetIMAPBackendAddress retrieves the address of the IMAP backend server from the EnvironmentSettings instance.
func (env *EnvironmentSettings) GetIMAPBackendAddress() string {
	if env == nil {
		return ""
	}

	return env.IMAPBackendAddress
}

// GetIMAPBackendPort retrieves the port of the IMAP backend server from the EnvironmentSettings instance.
func (env *EnvironmentSettings) GetIMAPBackendPort() int {
	if env == nil {
		return 0
	}

	return env.IMAPBackendPort
}

// GetPOP3BackendAddress retrieves the address of the POP3 backend server from the EnvironmentSettings instance.
func (env *EnvironmentSettings) GetPOP3BackendAddress() string {
	if env == nil {
		return ""
	}

	return env.POP3BackendAddress
}

// GetPOP3BackendPort retrieves the port of the POP3 backend server from the EnvironmentSettings instance.
func (env *EnvironmentSettings) GetPOP3BackendPort() int {
	if env == nil {
		return 0
	}

	return env.POP3BackendPort
}

// GetWaitDelay retrieves the wait delay in seconds between connection attempts from the EnvironmentSettings instance.
func (env *EnvironmentSettings) GetWaitDelay() uint8 {
	if env == nil {
		return 0
	}

	return env.WaitDelay
}

// GetMaxLoginAttempts retrieves the maximum allowed number of login attempts from the EnvironmentSettings instance.
func (env *EnvironmentSettings) GetMaxLoginAttempts() uint8 {
	if env == nil {
		return 0
	}

	return env.MaxLoginAttempts
}

// GetDevMode returns the DevMode value, indicating whether the application is running in developer mode.
func (env *EnvironmentSettings) GetDevMode() bool {
	if env == nil {
		return false
	}

	return env.DevMode
}

// GetMaxActionWorkers retrieves the maximum number of action workers allowed from the EnvironmentSettings instance.
func (env *EnvironmentSettings) GetMaxActionWorkers() uint16 {
	if env == nil {
		return 0
	}

	return env.MaxActionWorkers
}

// GetLocalCacheAuthTTL retrieves the time-to-live duration for local cache authentication from the EnvironmentSettings instance.
func (env *EnvironmentSettings) GetLocalCacheAuthTTL() time.Duration {
	if env == nil {
		return 0
	}

	return env.LocalCacheAuthTTL
}

// setCommonDefaultEnvVars sets default values for commonly used environment variables related to backend services configuration.
func setCommonDefaultEnvVars() {
	viper.SetDefault("smtp_backend_address", definitions.SMTPBackendAddress)
	viper.SetDefault("smtp_backend_port", definitions.SMTPBackendPort)
	viper.SetDefault("imap_backend_address", definitions.IMAPBackendAddress)
	viper.SetDefault("imap_backend_port", definitions.IMAPBackendPort)
	viper.SetDefault("pop3_backend_address", definitions.POP3BackendAddress)
	viper.SetDefault("pop3_backend_port", definitions.POP3BackendPort)
	viper.SetDefault("nginx_wait_delay", definitions.WaitDelay)
	viper.SetDefault("max_login_attempts", definitions.MaxLoginAttempts)
	viper.SetDefault("developer_mode", false)
	viper.SetDefault("max_action_workers", definitions.MaxActionWorkers)
	viper.SetDefault("lua_script_timeout", definitions.LuaMaxExecutionTime)
}

// setProtectionDefaultEnvVars sets the default environment variables for trusted proxies using the viper configuration package.
func setProtectionDefaultEnvVars() {
	viper.SetDefault("trusted_proxies", []string{"127.0.0.1", "::1"})
}

// setWebDefaultEnvVars sets the default environment variables for web content configuration using the viper package.
func setWebDefaultEnvVars() {
	viper.SetDefault("html_static_content_path", "/usr/app/static")
	viper.SetDefault("default_logo_image", "/static/img/logo.png")
	viper.SetDefault("homepage", "https://nauthilus.org")
	viper.SetDefault("language_resources", "/usr/app/resources")
}

// setLoginPageDefaultEnvVars sets the default environment variables for the login page using the viper configuration package.
func setLoginPageDefaultEnvVars() {
	viper.SetDefault("login_page", "/login")
	viper.SetDefault("login_page_logo_image_alt", definitions.ImageCopyright)
	viper.SetDefault("login_remember_for", 10800)
	viper.SetDefault("login_page_welcome", "")
}

// setConsentPageDefaultEnvVars sets the default environment variables for the consent page using the viper configuration package.
func setConsentPageDefaultEnvVars() {
	viper.SetDefault("consent_page", "/consent")
	viper.SetDefault("consent_page_logo_image_alt", definitions.ImageCopyright)
	viper.SetDefault("consent_remember_for", 3600)
	viper.SetDefault("consent_page_welcome", "")
}

// setLogoutPageDefaultEnvVars sets the default environment variables for the logout page using the viper configuration package.
func setLogoutPageDefaultEnvVars() {
	viper.SetDefault("logout_page", "/logout")
	viper.SetDefault("logout_page_welcome", "")
}

// setWebAuthnDefaultEnvVars sets the default environment variables related to WebAuthn configuration using viper.
func setWebAuthnDefaultEnvVars() {
	viper.SetDefault("device_page", "/device")
	viper.SetDefault("webauthn_page", "/webauthn")
	viper.SetDefault("webauthn_display_name", "Nauthilus")
	viper.SetDefault("webauthn_rp_id", viper.GetString("totp_issuer"))
	viper.SetDefault("webauthn_rp_origins", []string{"https://login.nauthilus.me"})
}

// setRegisterPageDefaultEnvVars sets the default environment variables for the registration page using viper configuration.
func setRegisterPageDefaultEnvVars() {
	viper.SetDefault("login_2fa_page", "/register")
	viper.SetDefault("login_2fa_page_welcome", "")
	viper.SetDefault("login_2fa_post_page", viper.GetString("login_2fa_page")+"/home")
}

// setTOTPPageDefaultEnvVars sets the default environment variables for the TOTP page using the viper configuration package.
func setTOTPPageDefaultEnvVars() {
	viper.SetDefault("totp_skew", uint(1))
	viper.SetDefault("totp_page", "/totp")
	viper.SetDefault("totp_issuer", "nauthilus.me")
	viper.SetDefault("totp_welcome", "")
	viper.SetDefault("totp_page_logo_image_alt", definitions.ImageCopyright)
}

// setNotifyPageDefaultEnvVars sets the default environment variables for the notification page using viper configuration.
func setNotifyPageDefaultEnvVars() {
	viper.SetDefault("notify_page", "/notify")
	viper.SetDefault("notify_page_welcome", "")
	viper.SetDefault("notify_page_logo_image_alt", definitions.ImageCopyright)
}

// setLocalCacheDefaults sets the default time-to-live value for local cache authentication using the viper configuration package.
func setLocalCacheDefaults() {
	viper.SetDefault("local_cache_auth_ttl", 30*time.Second)
}

// setDefaultEnvVars initializes default environment variables using the viper package for configuration management.
func setDefaultEnvVars() {
	viper.SetEnvPrefix("nauthilus")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	setCommonDefaultEnvVars()
	setLocalCacheDefaults()
	setProtectionDefaultEnvVars()
	setWebDefaultEnvVars()

	setLoginPageDefaultEnvVars()
	setConsentPageDefaultEnvVars()
	setLogoutPageDefaultEnvVars()

	setTOTPPageDefaultEnvVars()
	setRegisterPageDefaultEnvVars()
	setWebAuthnDefaultEnvVars()

	setNotifyPageDefaultEnvVars()

	viper.AllowEmptyEnv(true)
	viper.AutomaticEnv()
}

// String returns the name of the Config object excluding the HTTPOptions.
func (env *EnvironmentSettings) String() string {
	var result string

	if env == nil {
		return "<nil>"
	}

	value := reflect.ValueOf(*env)
	typeOfValue := value.Type()

	for index := 0; index < value.NumField(); index++ {
		switch typeOfValue.Field(index).Name {
		case "HTTPOptions":
			continue
		default:
			result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
		}
	}

	return result[1:]
}

// setConfigFromEnvVars initializes configuration fields from environment variables using the viper package.
func (env *EnvironmentSettings) setConfigFromEnvVars() {
	env.SMTPBackendAddress = viper.GetString("smtp_backend_address")
	env.SMTPBackendPort = viper.GetInt("smtp_backend_port")
	env.IMAPBackendAddress = viper.GetString("imap_backend_address")
	env.IMAPBackendPort = viper.GetInt("imap_backend_port")
	env.POP3BackendAddress = viper.GetString("pop3_backend_address")
	env.POP3BackendPort = viper.GetInt("pop3_backend_port")
	env.DevMode = viper.GetBool("developer_mode")
}

// setConfigWaitDelay sets the WaitDelay field based on the "wait_delay" configuration value from viper.
// If the value is greater than 1 and less than math.MaxUint8, it is set directly. Otherwise, it is capped at math.MaxUint8.
func (env *EnvironmentSettings) setConfigWaitDelay() {
	if val := viper.GetUint("wait_delay"); val > 1 {
		if val < math.MaxUint8 {
			env.WaitDelay = uint8(val)
		} else {
			env.WaitDelay = math.MaxUint8
		}
	} else {
		env.WaitDelay = uint8(val)
	}
}

// setConfigMaxLoginAttempts sets the MaxLoginAttempts field from the "max_login_attempts" configuration value using viper.
// If the value is greater than 0 and less than math.MaxUint8, it is assigned directly. Otherwise, it is capped at math.MaxUint8.
func (env *EnvironmentSettings) setConfigMaxLoginAttempts() {
	if val := viper.GetUint("max_login_attempts"); val > 0 {
		if val < math.MaxUint8 {
			env.MaxLoginAttempts = uint8(val)
		} else {
			env.MaxLoginAttempts = math.MaxUint8
		}
	}
}

// setConfigMaxActionWorkers sets the MaxActionWorkers field based on the "max_action_workers" value from the configuration.
func (env *EnvironmentSettings) setConfigMaxActionWorkers() {
	if val := viper.GetUint("max_action_workers"); val > 1 {
		if val < math.MaxUint16 {
			env.MaxActionWorkers = uint16(val)
		} else {
			env.MaxActionWorkers = math.MaxUint16
		}
	} else {
		env.MaxActionWorkers = 1
	}
}

// setLocalCacheTTL sets the LocalCacheAuthTTL field based on the "local_cache_auth_ttl" configuration value using viper.
// If the value is greater than 5 seconds but less than 1 hour, it is set directly; otherwise, it is capped accordingly.
func (env *EnvironmentSettings) setLocalCacheTTL() {
	if val := viper.GetDuration("local_cache_auth_ttl"); val*time.Second > 5*time.Second {
		if val*time.Second < time.Hour {
			env.LocalCacheAuthTTL = val * time.Second
		} else {
			env.LocalCacheAuthTTL = time.Hour
		}
	} else {
		env.LocalCacheAuthTTL = 5 * time.Second
	}
}

// setConfig initializes multiple configuration fields for the EnvironmentSettings instance using internal helper methods.
func (env *EnvironmentSettings) setConfig() {
	env.setConfigWaitDelay()
	env.setConfigMaxLoginAttempts()
	env.setConfigMaxActionWorkers()
	env.setLocalCacheTTL()
}

// NewEnvironmentConfig initializes and returns a singleton instance of EnvironmentSettings, setting default and custom configurations.
func NewEnvironmentConfig() Environment {
	if environment != nil {
		return environment
	}

	setDefaultEnvVars()

	newCfg := &EnvironmentSettings{}

	newCfg.setConfigFromEnvVars()
	newCfg.setConfig()

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
