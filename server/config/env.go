package config

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/global"
	"github.com/spf13/viper"
)

// EnvConfig represents the environment configuration for the application
// It is a pointer to Config type
var EnvConfig *Config //nolint:gochecknoglobals // System wide configuration

// Config represents overall configuration settings for the application.
type Config struct {
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

// setCommonDefaultEnvVars sets the default environment variables for the application.
// It initializes various viper configuration variables with default values.
// The default values are taken from the global constants and types defined in the code.
func setCommonDefaultEnvVars() {
	viper.SetDefault("smtp_backend_address", global.SMTPBackendAddress)
	viper.SetDefault("smtp_backend_port", global.SMTPBackendPort)
	viper.SetDefault("imap_backend_address", global.IMAPBackendAddress)
	viper.SetDefault("imap_backend_port", global.IMAPBackendPort)
	viper.SetDefault("pop3_backend_address", global.POP3BackendAddress)
	viper.SetDefault("pop3_backend_port", global.POP3BackendPort)
	viper.SetDefault("nginx_wait_delay", global.WaitDelay)
	viper.SetDefault("max_login_attempts", global.MaxLoginAttempts)
	viper.SetDefault("developer_mode", false)
	viper.SetDefault("max_action_workers", global.MaxActionWorkers)
	viper.SetDefault("lua_script_timeout", global.LuaMaxExecutionTime)
}

// setProtectionDefaultEnvVars sets the default environment variables for the application.
// It initializes various viper configuration variables with default values for
// brute_force_protection, and trusted_proxies.
// The default values are taken from the global constants and types defined in the code.
func setProtectionDefaultEnvVars() {
	viper.SetDefault("trusted_proxies", []string{"127.0.0.1", "::1"})
}

// setWebDefaultEnvVars sets the default environment variables for the web-related functionality of the application.
// It initializes various viper configuration variables with default values specific to the web module.
// The default values are based on the constants and types defined in the code.
func setWebDefaultEnvVars() {
	viper.SetDefault("html_static_content_path", "/usr/app/static")
	viper.SetDefault("default_logo_image", "/static/img/logo.png")
	viper.SetDefault("homepage", "https://nauthilus.org")
	viper.SetDefault("language_resources", "/usr/app/resources")
}

// setLoginPageDefaultEnvVars sets the default environment variables for the login page.
// It initializes various viper configuration variables with default values specific to the login page.
// The default values are taken from the global constants and types defined in the code.
// SetDefault sets the default value for the "login_page" configuration variable
func setLoginPageDefaultEnvVars() {
	viper.SetDefault("login_page", "/login")
	viper.SetDefault("login_page_logo_image_alt", global.ImageCopyright)
	viper.SetDefault("login_remember_for", 10800)
	viper.SetDefault("login_page_welcome", "")
}

// setConsentPageDefaultEnvVars sets the default environment variables for the consent page.
// It initializes various viper configuration variables with default values.
// The default values are taken from the global constants and types defined in the code.
func setConsentPageDefaultEnvVars() {
	viper.SetDefault("consent_page", "/consent")
	viper.SetDefault("consent_page_logo_image_alt", global.ImageCopyright)
	viper.SetDefault("consent_remember_for", 3600)
	viper.SetDefault("consent_page_welcome", "")
}

// setLogoutPageDefaultEnvVars sets the default environment variables for the logout page.
// It initializes the "logout_page" and "logout_page_welcome" variables with default values.
// The default values are taken from the global constants and types defined in the code.
func setLogoutPageDefaultEnvVars() {
	viper.SetDefault("logout_page", "/logout")
	viper.SetDefault("logout_page_welcome", "")
}

// setWebAuthnDefaultEnvVars sets the default environment variables for the WebAuthn feature of the application.
// It initializes various viper configuration variables with default values.
// The default values are taken from the global constants and types defined in the code.
// These default values are used when the corresponding environment variables are not set.
func setWebAuthnDefaultEnvVars() {
	viper.SetDefault("device_page", "/device")
	viper.SetDefault("webauthn_page", "/webauthn")
	viper.SetDefault("webauthn_display_name", "Nauthilus")
	viper.SetDefault("webauthn_rp_id", viper.GetString("totp_issuer"))
	viper.SetDefault("webauthn_rp_origins", []string{"https://login.nauthilus.me"})
}

// setRegisterPageDefaultEnvVars sets the default environment variables for the register page.
// It initializes various viper configuration variables with default values.
// The default values are taken from the global constants and types defined in the code.
func setRegisterPageDefaultEnvVars() {
	viper.SetDefault("login_2fa_page", "/register")
	viper.SetDefault("login_2fa_page_welcome", "")
	viper.SetDefault("login_2fa_post_page", viper.GetString("login_2fa_page")+"/home")
}

// setTOTPPageDefaultEnvVars sets the default environment variables for the TOTP page of the application.
// It initializes various viper configuration variables with default values.
func setTOTPPageDefaultEnvVars() {
	viper.SetDefault("totp_skew", uint(1))
	viper.SetDefault("totp_page", "/totp")
	viper.SetDefault("totp_issuer", "nauthilus.me")
	viper.SetDefault("totp_welcome", "")
	viper.SetDefault("totp_page_logo_image_alt", global.ImageCopyright)
}

// setNotifyPageDefaultEnvVars sets the default environment variables for the notify page.
// It initializes various viper configuration variables with default values.
// The default values are taken from the global constants and types defined in the code.
func setNotifyPageDefaultEnvVars() {
	viper.SetDefault("notify_page", "/notify")
	viper.SetDefault("notify_page_welcome", "")
	viper.SetDefault("notify_page_logo_image_alt", global.ImageCopyright)
}

// setLocalCacheDefaults sets the default value for the "local_cache_auth_ttl" configuration key to 30 seconds.
//
// Example usage:
// setLocalCacheDefaults()
func setLocalCacheDefaults() {
	viper.SetDefault("local_cache_auth_ttl", 30*time.Second)
}

// setDefaultEnvVars sets the default environment variables for the application.
// It initializes various viper configuration variables with default values.
// The default values are taken from the global constants and types defined in the code.
//
// setDefaultEnvVars() calls the following functions to set the respective configuration variables:
// - setCommonDefaultEnvVars()
// - setLocalCacheDefaults()
// - setRedisDefaultEnvVars()
// - setProtectionDefaultEnvVars()
// - setSQLDefaultEnvVars()
// - setWebDefaultEnvVars()
// - setLoginPageDefaultEnvVars()
// - setConsentPageDefaultEnvVars()
// - setLogoutPageDefaultEnvVars()
// - setTOTPPageDefaultEnvVars()
// - setRegisterPageDefaultEnvVars()
// - setWebAuthnDefaultEnvVars()
// - setNotifyPageDefaultEnvVars()
//
// Finally, it allows empty environment variables and enables automatic environment variable detection for viper.
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
func (c *Config) String() string {
	var result string

	value := reflect.ValueOf(*c)
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

// setConfigFromEnvVars sets the configuration values from environment variables using Viper.
// Each configuration value is retrieved from the corresponding environment variable using Viper's Get method,
// and then assigned to the corresponding field in the Config struct.
// The configuration fields that are set in this method include HTTPAddress, HTTPOptions,
// SMTPBackendAddress, SMTPBackendPort, IMAPBackendAddress, IMAPBackendPort, ResolveIP, RedisAddress,
// RedisPort, RedisDB, RedisUsername, RedisPassword, RedisAddressRO, RedisPortRO, RedisPrefix, RedisPosCacheTTL,
// RedisNegCacheTTL, RedisSentinels, RedisSentinelMasterName, RedisSentinelUsername, RedisSentinelPassword, DNSResolver,
// and DevMode.
func (c *Config) setConfigFromEnvVars() {
	c.SMTPBackendAddress = viper.GetString("smtp_backend_address")
	c.SMTPBackendPort = viper.GetInt("smtp_backend_port")
	c.IMAPBackendAddress = viper.GetString("imap_backend_address")
	c.IMAPBackendPort = viper.GetInt("imap_backend_port")
	c.POP3BackendAddress = viper.GetString("pop3_backend_address")
	c.POP3BackendPort = viper.GetInt("pop3_backend_port")
	c.DevMode = viper.GetBool("developer_mode")
}

// setConfigWaitDelay sets the value of the WaitDelay field in the Config struct based on the value of the "wait_delay" configuration property from the config file.
// If the value is greater than 1, it is checked against math.MaxUint8. If it is less than the maximum uint8 value, the value is assigned to c.WaitDelay.
// If the value is greater than or equal to the maximum uint8 value, c.WaitDelay is set to math.MaxUint8.
// If the value is less than or equal to 1, c.WaitDelay is set to the value.
// Example usage:
//
//	c := &Config{}
//	c.setConfigWaitDelay()
func (c *Config) setConfigWaitDelay() {
	if val := viper.GetUint("wait_delay"); val > 1 {
		if val < math.MaxUint8 {
			c.WaitDelay = uint8(val)
		} else {
			c.WaitDelay = math.MaxUint8
		}
	} else {
		c.WaitDelay = uint8(val)
	}
}

// setConfigMaxLoginAttempts sets the maximum number of login attempts from the configuration file.
// It retrieves the value of "max_login_attempts" from the configuration using viper.GetUint.
// If the value is greater than 0, it checks if it is less than math.MaxUint8.
// If it is, it assigns the value to c.MaxLoginAttempts as uint8.
// Otherwise, it assigns math.MaxUint8 to c.MaxLoginAttempts.
func (c *Config) setConfigMaxLoginAttempts() {
	if val := viper.GetUint("max_login_attempts"); val > 0 {
		if val < math.MaxUint8 {
			c.MaxLoginAttempts = uint8(val)
		} else {
			c.MaxLoginAttempts = math.MaxUint8
		}
	}
}

// setConfigMaxActionWorkers sets the value of MaxActionWorkers field in the Config struct.
// The value is retrieved from the configuration file using viper.GetUint("max_action_workers").
// If the retrieved value is greater than 1, it is checked if it is less than math.MaxUint16.
// If it is, the MaxActionWorkers field is set to that value. Otherwise, it is set to math.MaxUint16.
// If the retrieved value is not greater than 1, then MaxActionWorkers is set to 1.
func (c *Config) setConfigMaxActionWorkers() {
	if val := viper.GetUint("max_action_workers"); val > 1 {
		if val < math.MaxUint16 {
			c.MaxActionWorkers = uint16(val)
		} else {
			c.MaxActionWorkers = math.MaxUint16
		}
	} else {
		c.MaxActionWorkers = 1
	}
}

// setLocalCacheTTL sets the value of the LocalCacheAuthTTL field in the Config struct based on the value retrieved from the configuration file (viper).
// If the value is greater than 5 seconds, it will be assigned to the field. If it is less than an hour, it will be assigned to the field.
// Otherwise, the field will be assigned the value of 5 seconds.
// Please note that this method does not return errors.
func (c *Config) setLocalCacheTTL() {
	if val := viper.GetDuration("local_cache_auth_ttl"); val*time.Second > 5*time.Second {
		if val*time.Second < time.Hour {
			c.LocalCacheAuthTTL = val * time.Second
		} else {
			c.LocalCacheAuthTTL = time.Hour
		}
	} else {
		c.LocalCacheAuthTTL = 5 * time.Second
	}
}

// setConfig initializes the configuration options based on the environment variables and flags.
// It calls several helper methods to set each specific option.
func (c *Config) setConfig() {
	c.setConfigWaitDelay()
	c.setConfigMaxLoginAttempts()
	c.setConfigMaxActionWorkers()
	c.setLocalCacheTTL()
}

// NewConfig initializes a new Config struct and sets its values based on
// environment variables. It calls various methods to set specific
// configuration options and returns the new Config struct or an error if
// any configuration fails.
func NewConfig() *Config {
	setDefaultEnvVars()

	newCfg := &Config{}

	newCfg.setConfigFromEnvVars()
	newCfg.setConfig()

	return newCfg
}
