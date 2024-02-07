package config

import (
	"fmt"
	"math"
	"reflect"
	"strings"

	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/go-ldap/ldap/v3"
	"github.com/spf13/viper"
)

// EnvConfig represents the environment configuration for the application
// It is a pointer to Config type
var EnvConfig *Config //nolint:gochecknoglobals // System wide configuration

// Verbosity is a type that represents the verbosity details.
type Verbosity struct {
	// verboseLevel holds the level of detail for logging
	verboseLevel int

	// name is the name of the verbosity level
	name string
}

func (v *Verbosity) String() string {
	return v.name
}

// Set updates the verbosity level and name based on the provided value.
// It returns an error if the value is not valid.
// Valid values for the verbosity level are "none", "error", "warn", "info", and "debug".
// If the value is valid, the verboseLevel and name fields are updated accordingly.
// An error of type ErrWrongVerboseLevel is returned if the value is not valid.
func (v *Verbosity) Set(value string) error {
	switch value {
	case "none", "":
		v.verboseLevel = global.LogLevelNone
	case global.LogKeyError:
		v.verboseLevel = global.LogLevelError
	case global.LogKeyWarning:
		v.verboseLevel = global.LogLevelWarn
	case "info":
		v.verboseLevel = global.LogLevelInfo
	case "debug":
		v.verboseLevel = global.LogLevelDebug
	default:
		return errors.ErrWrongVerboseLevel
	}

	v.name = value

	return nil
}

// Type returns the type of the Verbosity struct.
func (v *Verbosity) Type() string {
	return "Verbosity"
}

// Level returns the verbosity level of the Verbosity instance.
func (v *Verbosity) Level() int {
	return v.verboseLevel
}

// Get returns the name of the log level as string.
func (v *Verbosity) Get() string {
	return v.name
}

// LDAPScope is the search scope for an LDAP server.
type LDAPScope struct {
	scope int
	name  string
}

func (l *LDAPScope) String() string {
	return l.name
}

// Set sets the numeric LDAP search scope by its string representation.
func (l *LDAPScope) Set(value string) error {
	switch value {
	case "base":
		l.scope = ldap.ScopeBaseObject
	case "one":
		l.scope = ldap.ScopeSingleLevel
	case "sub":
		l.scope = ldap.ScopeWholeSubtree
	default:
		return errors.ErrWrongLDAPScope
	}

	l.name = value

	return nil
}

// Type returns the name of the type.
func (l *LDAPScope) Type() string {
	return "LDAPScope"
}

// Get returns the numeric LDAP search scope.
func (l *LDAPScope) Get() int {
	return l.scope
}

// Protocol is the protocol used between a remote client and a server. This server sets the protocol in an HTTP request
// header "Auth-Protocol" (Nginx protocol).
type Protocol struct {
	name string
}

func (p *Protocol) String() string {
	return p.name
}

// Set sets the name of the protocol.
func (p *Protocol) Set(value string) {
	p.name = value
}

// Type returns the name of the type.
func (p *Protocol) Type() string {
	return "Protocol"
}

// Get returns the string for a protocol.
func (p *Protocol) Get() string {
	return p.name
}

// NewProtocol creates a new Protocol object with the given protocol string.
// It initializes the name field of the Protocol object.
//
// Example usage:
// protocol := NewProtocol("http")
func NewProtocol(protocol string) *Protocol {
	p := &Protocol{}
	p.Set(protocol)

	return p
}

// PassDB is a password Database container.
type PassDB struct {
	backend global.Backend
}

func (p *PassDB) String() string {
	return p.backend.String()
}

// Set updates the backend of the PassDB based on the provided value.
// It returns an error if the value is not valid.
// Valid values for the backend are "cache", "ldap", "mysql", "postgresql", "sql", and "lua".
// If the value is valid, the backend field of PassDB is updated accordingly.
// An error of type ErrWrongPassDB is returned if the value is not valid.
func (p *PassDB) Set(value string) error {
	switch value {
	case global.BackendCacheName:
		p.backend = global.BackendCache
	case global.BackendLDAPName:
		p.backend = global.BackendLDAP
	case global.BackendLuaName:
		p.backend = global.BackendLua
	default:
		return errors.ErrWrongPassDB
	}

	return nil
}

// Type returns the name of the type.
func (p *PassDB) Type() string {
	return "PassDB"
}

// Get gets the name of a password Database.
func (p *PassDB) Get() global.Backend {
	return p.backend
}

// Feature is a container for Nauthilus features.
type Feature struct {
	name string
}

func (f *Feature) String() string {
	return f.name
}

// Set updates the feature name based on the provided value.
// It returns an error if the value is not a valid feature name.
// Valid feature names are "tls_encryption", "rbl", "geoip", "relay_domains", and "lua".
// If the value is valid, the name field of the Feature struct is updated accordingly.
// An error of type ErrWrongFeature is returned if the value is not valid.
func (f *Feature) Set(value string) error {
	switch value {
	case "":
	case global.FeatureTLSEncryption, global.FeatureRBL, global.FeatureGeoIP, global.FeatureRelayDomains, global.FeatureLua, global.FeatureNginxMonitoring:
		f.name = value
	default:
		return errors.ErrWrongFeature
	}

	return nil
}

// Type returns the name of the type.
func (f *Feature) Type() string {
	return "Feature"
}

// Get gets the name of a feature returned as string.
func (f *Feature) Get() string {
	return f.name
}

// DbgModule represents a debugging module configuration.
type DbgModule struct {
	name   string
	module global.DbgModule
}

func (d *DbgModule) String() string {
	return d.name
}

// Set updates the debug module based on the provided value.
// It returns an error if the value is not valid.
// Valid values for the debug module are "none", "all", "auth", "hydra", "webauthn",
// "statistics", "whitelist", "ldap", "ldappool", "sql", "cache", "bf", "rbl", "action", "feature", and "lua".
// If the value is valid, the module and name fields are updated accordingly.
// An error of type ErrWrongDebugModule is returned if the value is not valid.
func (d *DbgModule) Set(value string) error {
	switch value {
	case global.DbgNoneName, "":
		d.module = global.DbgNone
	case global.DbgAllName:
		d.module = global.DbgAll
	case global.DbgAuthName:
		d.module = global.DbgAuth
	case global.DbgHydraName:
		d.module = global.DbgHydra
	case global.DbgWebAuthnName:
		d.module = global.DbgWebAuthn
	case global.DbgStatsName:
		d.module = global.DbgStats
	case global.DbgWhitelistName:
		d.module = global.DbgWhitelist
	case global.DbgLDAPName:
		d.module = global.DbgLDAP
	case global.DbgLDAPPoolName:
		d.module = global.DbgLDAPPool
	case global.DbgCacheName:
		d.module = global.DbgCache
	case global.DbgBfName:
		d.module = global.DbgBf
	case global.DbgRBLName:
		d.module = global.DbgRBL
	case global.DbgActionName:
		d.module = global.DbgAction
	case global.DbgFeatureName:
		d.module = global.DbgFeature
	case global.DbgLuaName:
		d.module = global.DbgLua
	default:
		return errors.ErrWrongDebugModule
	}

	d.name = value

	return nil
}

// Type returns the type of the DbgModule, which is always "DebugModule".
func (d *DbgModule) Type() string {
	return "DebugModule"
}

// Get returns the name of the `DbgModule` instance.
// The name represents the current debug module.
// It can be used to identify the debug module when needed.
func (d *DbgModule) Get() string {
	return d.name
}

// GetModule returns the `module` field of the `DbgModule` struct.
// It is used to retrieve the current debug module.
//
// Usage:
//
//	module := d.GetModule()
//
// Example:
//
//	func main() {
//	  dbg := &DbgModule{}
//	  module := dbg.GetModule()
//	  fmt.Println(module) // Output: 0
//	}
func (d *DbgModule) GetModule() global.DbgModule {
	return d.module
}

// HTTPOptions is a type that holds configurations related to an HTTP(S) server.
// It contains fields for authentication credentials, X.509 certificate and key paths, and flags for enabling basic authentication and SSL.
type HTTPOptions struct {
	Auth struct {
		UserName string
		Password string
	}
	X509 struct {
		Cert string
		Key  string
	}
	UseBasicAuth bool
	UseSSL       bool
}

func (h HTTPOptions) String() string {
	var result string

	v := reflect.ValueOf(h)
	typeOfV := v.Type()

	for i := 0; i < v.NumField(); i++ {
		result += fmt.Sprintf(" %s='%v'", typeOfV.Field(i).Name, v.Field(i).Interface())
	}

	return result[1:]
}

// Config represents overall configuration settings for the application.
type Config struct {

	// InstanceName is the name of the current application instance.
	InstanceName string

	// HTTPAddress is the address where HTTP server should listen.
	// It should be in the format "ip:port".
	HTTPAddress string

	// LogJSON is a flag indicating whether the logs should be in JSON format.
	LogJSON bool

	// Verbosity is a value to set the logging severity level.
	Verbosity

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

	// GeoipPath is the file path to the GeoIP database.
	GeoipPath string

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

	// Features is a list of enabled application features.
	Features []*Feature

	// BruteForce contains configuration for brute force prevention per each protocol.
	BruteForce []*Protocol

	// DbgModule contains configurations for debugging modules.
	DbgModule []*DbgModule

	// DevMode indicates whether the application is running in developer mode.
	DevMode bool

	// MaxActionWorkers is the maximum number of action workers that can be run simultaneously.
	MaxActionWorkers uint16

	// HTTPOptions contains configurations related to HTTP(S) server.
	HTTPOptions
}

// setCommonDefaultEnvVars sets the default environment variables for the application.
// It initializes various viper configuration variables with default values.
// The default values are taken from the global constants and types defined in the code.
func setCommonDefaultEnvVars() {
	viper.SetDefault("instance_name", global.InstanceName)
	viper.SetDefault("log_format_json", false)
	viper.SetDefault("log_debug_modules", []*DbgModule{
		{global.DbgAuthName, global.DbgAuth},
		{global.DbgStatsName, global.DbgStats},
	})
	viper.SetDefault("http_address", global.HTTPAddress)
	viper.SetDefault("smtp_backend_address", global.SMTPBackendAddress)
	viper.SetDefault("smtp_backend_port", global.SMTPBackendPort)
	viper.SetDefault("imap_backend_address", global.IMAPBackendAddress)
	viper.SetDefault("imap_backend_port", global.IMAPBackendPort)
	viper.SetDefault("pop3_backend_address", global.POP3BackendAddress)
	viper.SetDefault("pop3_backend_port", global.POP3BackendPort)
	viper.SetDefault("nginx_wait_delay", global.WaitDelay)
	viper.SetDefault("max_login_attempts", global.MaxLoginAttempts)
	viper.SetDefault("geoip_path", global.GeoIPPath)
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
// features, brute_force_protection, and trusted_proxies.
// The default values are taken from the global constants and types defined in the code.
// Feature type represents a specific feature of the application.
func setProtectionDefaultEnvVars() {
	viper.SetDefault("features", []*Feature{
		{global.FeatureTLSEncryption},
		{global.FeatureRBL},
		{global.FeatureGeoIP},
		{global.FeatureRelayDomains},
	})
	viper.SetDefault("brute_force_protection", []*Protocol{
		{global.ProtoHTTP},
	})
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

// setDefaultEnvVars sets the default environment variables for the application.
// It initializes various viper configuration variables with default values.
// The default values are taken from the global constants and types defined in the code.
//
// setDefaultEnvVars() calls the following functions to set the respective configuration variables:
// - setCommonDefaultEnvVars()
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
// The configuration fields that are set in this method include LogJSON, InstanceName, HTTPAddress, HTTPOptions,
// SMTPBackendAddress, SMTPBackendPort, IMAPBackendAddress, IMAPBackendPort, ResolveIP, GeoipPath, RedisAddress,
// RedisPort, RedisDB, RedisUsername, RedisPassword, RedisAddressRO, RedisPortRO, RedisPrefix, RedisPosCacheTTL,
// RedisNegCacheTTL, RedisSentinels, RedisSentinelMasterName, RedisSentinelUsername, RedisSentinelPassword, DNSResolver,
// and DevMode.
func (c *Config) setConfigFromEnvVars() {
	c.LogJSON = viper.GetBool("log_format_json")
	c.InstanceName = viper.GetString("instance_name")
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
	c.GeoipPath = viper.GetString("geoip_path")
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

// setConfigBruteforceProtection sets the brute force protection configurations in the Config struct.
// It checks the value of the "brute_force_protection" configuration from the viper instance and handles it based on its type.
// If the value is a string, it splits it by spaces, creates a Protocol instance for each non-empty value, and appends it to the Config.BruteForce slice.
// If the value is []*Protocol, it creates a Protocol instance for each element and appends it to the Config.BruteForce slice.
func (c *Config) setConfigBruteforceProtection() {
	bruteForceI := viper.Get("brute_force_protection")
	switch bruteForceServices := bruteForceI.(type) {
	case string:
		bruteForceServicesList := strings.Split(strings.TrimSpace(bruteForceServices), " ")
		for _, bruteForceService := range bruteForceServicesList {
			if bruteForceService == "" {
				continue
			}

			p := &Protocol{}
			p.Set(bruteForceService)

			c.BruteForce = append(c.BruteForce, p)
		}
	case []*Protocol:
		for _, bruteForceService := range bruteForceServices {
			p := &Protocol{}
			p.Set(bruteForceService.Get())

			c.BruteForce = append(c.BruteForce, p)
		}
	}
}

// setConfigVerboseLevel sets the verbose level configuration for the Config struct.
// It gets the value from the 'verbose_level' environment variable.
// If the value is not of type string, it returns an error.
// It then calls the Set method of the Verbosity struct to set the log level.
// If the Set method returns an error, it returns that error.
// Otherwise, it returns nil.
func (c *Config) setConfigVerboseLevel() error {
	verbosity, assertOk := viper.Get("verbose_level").(string)
	if !assertOk {
		return errors.ErrWrongVerboseLevel
	}

	if err := c.Verbosity.Set(verbosity); err != nil {
		return err
	}

	return nil
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

// setConfigLogDebugModules sets the debug modules for logging.
// It retrieves the debug modules from the "log_debug_modules" configuration value.
// If the value is a string, it splits it by spaces and creates a new DbgModule for each module.
// If the value is already a []*DbgModule, it sets the Config's DbgModule field to the value.
// Returns an error if there was an issue setting the debug modules.
// Example usage:
//
//	c := &Config{}
//	if err := c.setConfigLogDebugModules(); err != nil {
//	  log.Fatal(err)
//	}
func (c *Config) setConfigLogDebugModules() error {
	dbgModulesI := viper.Get("log_debug_modules")
	switch dbgModules := dbgModulesI.(type) {
	case string:
		dbgModulesList := strings.Split(strings.TrimSpace(dbgModules), " ")
		for _, dbgModule := range dbgModulesList {
			module := &DbgModule{}

			if err := module.Set(dbgModule); err != nil {
				return err
			}

			c.DbgModule = append(c.DbgModule, module)
		}
	case []*DbgModule:
		c.DbgModule = dbgModules
	}

	return nil
}

// setConfigFeatures sets the features for the Config object based on the "features" configuration option.
// It accepts a comma-separated list of features or an array of Feature objects.
// If the "features" configuration option is a string, it splits the string and creates a Feature object for each feature.
// If the "features" configuration option is an array of Feature objects, it creates a Feature object for each feature.
// The created Feature objects are added to the Features slice of the Config object.
// Returns an error if there is an issue with setting the features.
func (c *Config) setConfigFeatures() error {
	featuresI := viper.Get("features")
	switch features := featuresI.(type) {
	case string:
		featuresList := strings.Split(strings.TrimSpace(features), " ")
		for _, feature := range featuresList {
			if feature == "" {
				continue
			}

			f := &Feature{}
			if err := f.Set(feature); err != nil {
				return err
			}

			c.Features = append(c.Features, f)
		}
	case []*Feature:
		for _, feature := range features {
			f := &Feature{}
			if err := f.Set(feature.Get()); err != nil {
				return err
			}

			c.Features = append(c.Features, f)
		}
	}

	return nil
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
	c.setConfigBruteforceProtection()
}

// setConfigWithError sets the configuration with error handling.
// It calls multiple methods to set different parts of the config.
// If any of those methods return an error, it returns that error.
// Otherwise, it returns nil.
func (c *Config) setConfigWithError() error {
	if err := c.setConfigVerboseLevel(); err != nil {
		return err
	}

	if err := c.setConfigPassDBBackends(); err != nil {
		return err
	}

	if err := c.setConfigLogDebugModules(); err != nil {
		return err
	}

	if err := c.setConfigFeatures(); err != nil {
		return err
	}

	return nil
}

// HasFeature checks if the given feature exists in the Config's Features list
func (c *Config) HasFeature(feature string) bool {
	if c.Features == nil {
		return false
	}

	for _, item := range c.Features {
		if item.Get() == feature {
			return true
		}
	}

	return false
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
