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
	// HTTPAddress is the address where HTTP server should listen.
	// It should be in the format "ip:port".
	HTTPAddress string

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

	// ResolveIP is a flag indicating whether to resolve IP addresses to hostnames.
	ResolveIP bool

	// MasterSeparator is the character used to separate master data fields.
	MasterSeparator string

	// RedisAddress is the address of the Redis server for master pool.
	RedisAddress string

	// RedisPort is the port of the Redis server for master pool.
	RedisPort int

	// RedisUsername is the username for authenticating to the Redis server for master pool.
	RedisUsername string

	// RedisPassword is the password for authenticating to the Redis server for master pool.
	RedisPassword string

	// RedisAddressRO is the address of the Redis server for read replica pool.
	RedisAddressRO string

	// RedisPortRO is the port of the Redis server for read replica pool.
	RedisPortRO int

	// RedisSentinels is the list of address of the Redis sentinel servers.
	RedisSentinels []string

	// RedisSentinelMasterName is the name of the Redis sentinel master.
	RedisSentinelMasterName string

	// RedisSentinelUsername is the username for Redis sentinel authentication.
	RedisSentinelUsername string

	// RedisSentinelPassword is the password for Redis sentinel authentication.
	RedisSentinelPassword string

	// RedisPrefix is the prefix to prepend to all Redis keys.
	RedisPrefix string

	// RedisDB is the Redis database number to use.
	RedisDB int

	// RedisPosCacheTTL is the positive response cache time-to-live in Redis.
	RedisPosCacheTTL uint

	// RedisNegCacheTTL is the negative response cache time-to-live in Redis.
	RedisNegCacheTTL uint

	// DNSResolver specifies the DNS resolver to use.
	DNSResolver string

	// DNSTimeout is the DNS resolution timeout in seconds.
	DNSTimeout uint

	// PassDBs is a list of password databases.
	PassDBs []*PassDB

	// DevMode indicates whether the application is running in developer mode.
	DevMode bool

	// MaxActionWorkers is the maximum number of action workers that can be run simultaneously.
	MaxActionWorkers uint16

	// LocalCacheAuthTTL
	LocalCacheAuthTTL time.Duration

	// HTTPOptions contains configurations related to HTTP(S) server.
	HTTPOptions
}

// setCommonDefaultEnvVars sets the default environment variables for the application.
// It initializes various viper configuration variables with default values.
// The default values are taken from the global constants and types defined in the code.
func setCommonDefaultEnvVars() {
	viper.SetDefault("http_address", global.HTTPAddress)
	viper.SetDefault("smtp_backend_address", global.SMTPBackendAddress)
	viper.SetDefault("smtp_backend_port", global.SMTPBackendPort)
	viper.SetDefault("imap_backend_address", global.IMAPBackendAddress)
	viper.SetDefault("imap_backend_port", global.IMAPBackendPort)
	viper.SetDefault("pop3_backend_address", global.POP3BackendAddress)
	viper.SetDefault("pop3_backend_port", global.POP3BackendPort)
	viper.SetDefault("nginx_wait_delay", global.WaitDelay)
	viper.SetDefault("max_login_attempts", global.MaxLoginAttempts)
	viper.SetDefault("dns_timeout", uint(10))
	viper.SetDefault("passdb_backends", []*PassDB{{global.BackendCache}, {global.BackendLDAP}})
	viper.SetDefault("developer_mode", false)
	viper.SetDefault("max_action_workers", global.MaxActionWorkers)
	viper.SetDefault("lua_script_timeout", global.LuaMaxExecutionTime)
}

// setRedisDefaultEnvVars sets the default environment variables for Redis configuration.
// It initializes various viper configuration variables with default values specific to Redis.
// The default values are taken from the global constants and types defined in the code.
// Default values for Redis configuration variables:
// - redis_address: Default value is the constant global.RedisAddress (localhost)
// - redis_port: Default value is the constant global.RedisPort (6379)
// - redis_database_number: Default value is 0
// - redis_replica_address: Default value is the constant global.RedisAddress (localhost)
// - redis_replica_port: Default value is the constant global.RedisPort (6379)
// - redis_prefix: Default value is the constant global.RedisPrefix ("nt_")
// - redis_sentinels: Default value is an empty string slice []
// - redis_sentinel_master_name: Default value is an empty string
// - redis_sentinel_username: Default value is an empty string
// - redis_sentinel_password: Default value is an empty string
// - redis_positive_cache_ttl: Default value is the constant global.RedisPosCacheTTL (3600)
// - redis_negative_cache_ttl: Default value is the constant global.RedisNegCacheTTL (3600)
func setRedisDefaultEnvVars() {
	viper.SetDefault("redis_address", global.RedisAddress)
	viper.SetDefault("redis_port", global.RedisPort)
	viper.SetDefault("redis_database_number", 0)
	viper.SetDefault("redis_replica_address", global.RedisAddress)
	viper.SetDefault("redis_replica_port", global.RedisPort)
	viper.SetDefault("redis_prefix", global.RedisPrefix)
	viper.SetDefault("redis_sentinels", []string{})
	viper.SetDefault("redis_sentinel_master_name", "")
	viper.SetDefault("redis_sentinel_username", "")
	viper.SetDefault("redis_sentinel_password", "")
	viper.SetDefault("redis_positive_cache_ttl", global.RedisPosCacheTTL)
	viper.SetDefault("redis_negative_cache_ttl", global.RedisNegCacheTTL)
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
	viper.SetDefault("hydra_admin_uri", "http://127.0.0.1:4445")
	viper.SetDefault("http_client_skip_tls_verify", false)
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

	setCommonDefaultEnvVars()
	setLocalCacheDefaults()
	setRedisDefaultEnvVars()
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
	c.HTTPAddress = viper.GetString("http_address")
	c.HTTPOptions.UseSSL = viper.GetBool("http_use_ssl")
	c.HTTPOptions.UseBasicAuth = viper.GetBool("http_use_basic_auth")
	c.SMTPBackendAddress = viper.GetString("smtp_backend_address")
	c.SMTPBackendPort = viper.GetInt("smtp_backend_port")
	c.IMAPBackendAddress = viper.GetString("imap_backend_address")
	c.IMAPBackendPort = viper.GetInt("imap_backend_port")
	c.POP3BackendAddress = viper.GetString("pop3_backend_address")
	c.POP3BackendPort = viper.GetInt("pop3_backend_port")
	c.ResolveIP = viper.GetBool("resolve_ip")
	c.RedisAddress = viper.GetString("redis_address")
	c.RedisPort = viper.GetInt("redis_port")
	c.RedisDB = viper.GetInt("redis_database_number")
	c.RedisUsername = viper.GetString("redis_username")
	c.RedisPassword = viper.GetString("redis_password")
	c.RedisAddressRO = viper.GetString("redis_replica_address")
	c.RedisPortRO = viper.GetInt("redis_replica_port")
	c.RedisPrefix = viper.GetString("redis_prefix")
	c.RedisPosCacheTTL = viper.GetUint("redis_positive_cache_ttl")
	c.RedisNegCacheTTL = viper.GetUint("redis_negative_cache_ttl")
	c.RedisSentinels = viper.GetStringSlice("redis_sentinels")
	c.RedisSentinelMasterName = viper.GetString("redis_sentinel_master_name")
	c.RedisSentinelUsername = viper.GetString("redis-sentinel-username")
	c.RedisSentinelPassword = viper.GetString("redis-sentinel-password")
	c.DNSResolver = viper.GetString("dns_resolver")
	c.DevMode = viper.GetBool("developer_mode")
}

// setConfigHTTPOptionUseSSL sets the X509 certificate and key paths for HTTPS if the UseSSL flag is true
func (c *Config) setConfigHTTPOptionUseSSL() {
	if c.HTTPOptions.UseSSL {
		if val := viper.GetString("http_tls_cert"); val != "" {
			c.HTTPOptions.X509.Cert = val
		}

		if val := viper.GetString("http_tls_key"); val != "" {
			c.HTTPOptions.X509.Key = val
		}
	}
}

// setConfigHTTPOptionUseBasicAuth sets the username and password for basic authentication if enabled.
func (c *Config) setConfigHTTPOptionUseBasicAuth() {
	if c.HTTPOptions.UseBasicAuth {
		if val := viper.GetString("http_basic_auth_username"); val != "" {
			c.HTTPOptions.Auth.UserName = val
		}

		if val := viper.GetString("http_basic_auth_password"); val != "" {
			c.HTTPOptions.Auth.Password = val
		}
	}
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

// setConfigDNSTimeout sets the DNS timeout value in the Config struct
// based on the value retrieved from the "dns_timeout" configuration.
// If the value is greater than 1, it is set as the DNSTimeout.
// If the value is greater than math.MaxUint8, DNSTimeout is set to math.MaxUint8.
// If the value is less than or equal to 1, DNSTimeout is set to 1.
func (c *Config) setConfigDNSTimeout() {
	if val := viper.GetUint("dns_timeout"); val > 1 {
		if val < math.MaxUint8 {
			c.DNSTimeout = val
		} else {
			c.DNSTimeout = math.MaxUint8
		}
	} else {
		c.DNSTimeout = 1
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

// setConfigPassDBBackends sets the passdb_backends configuration option.
// It parses the value from the configuration using Viper and initializes
// the Config struct's PassDBs field with the appropriate data.
//
// The value of passdb_backends can be either a string containing
// space-separated backend names, or a slice of *PassDB.
// In the case of a string, the method splits it into a list
// of backends and creates a new *PassDB instance for each backend.
// The method then sets the Config's PassDBs field with the created
// instances. In the case of a slice, the method directly assigns
// the slice to the Config's PassDBs field.
//
// If there is an error during parsing or initializing the PassDBs,
// the method returns an error. Otherwise, it returns nil.
func (c *Config) setConfigPassDBBackends() error {
	passDBsI := viper.Get("passdb_backends")
	switch passDBs := passDBsI.(type) {
	case string:
		passDBsList := strings.Split(strings.TrimSpace(passDBs), " ")
		for _, passDB := range passDBsList {
			p := &PassDB{}
			if err := p.Set(passDB); err != nil {
				return err
			}

			c.PassDBs = append(c.PassDBs, p)
		}
	case []*PassDB:
		c.PassDBs = passDBs
	}

	return nil
}

// setLocalCacheTTL sets the value of the LocalCacheAuthTTL field in the Config struct based on the value retrieved from the configuration file (viper).
// If the value is greater than 5 seconds, it will be assigned to the field. If it is less than an hour, it will be assigned to the field.
// Otherwise, the field will be assigned the value of 5 seconds.
// Please note that this method does not return errors.
func (c *Config) setLocalCacheTTL() {
	if val := viper.GetDuration("local_cache_auth_ttl"); val > 5*time.Second {
		if val < time.Hour {
			c.LocalCacheAuthTTL = val
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
	c.setConfigHTTPOptionUseSSL()
	c.setConfigHTTPOptionUseBasicAuth()
	c.setConfigWaitDelay()
	c.setConfigMaxLoginAttempts()
	c.setConfigDNSTimeout()
	c.setConfigMaxActionWorkers()
	c.setLocalCacheTTL()
}

// setConfigWithError sets the configuration with error handling.
// It calls multiple methods to set different parts of the config.
// If any of those methods return an error, it returns that error.
// Otherwise, it returns nil.
func (c *Config) setConfigWithError() error {
	if err := c.setConfigPassDBBackends(); err != nil {
		return err
	}

	return nil
}

// NewConfig initializes a new Config struct and sets its values based on
// environment variables. It calls various methods to set specific
// configuration options and returns the new Config struct or an error if
// any configuration fails.
func NewConfig() (*Config, error) {
	setDefaultEnvVars()

	newCfg := &Config{}

	newCfg.setConfigFromEnvVars()
	newCfg.setConfig()

	if err := newCfg.setConfigWithError(); err != nil {
		return nil, err
	}

	return newCfg, nil
}
