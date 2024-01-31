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

var EnvConfig *Config //nolint:gochecknoglobals // System wide configuration

// Verbosity is the log level type.
type Verbosity struct {
	verboseLevel int
	name         string
}

func (v *Verbosity) String() string {
	return v.name
}

// Set sets the log level.
func (v *Verbosity) Set(value string) error {
	switch value {
	case "none":
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

// Type returns the name of the type.
func (v *Verbosity) Type() string {
	return "Verbosity"
}

// Level returns the numeric log level.
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

// Set sets the password Database to one of the supported database backends.
func (p *PassDB) Set(value string) error {
	switch value {
	case global.BackendCacheName:
		p.backend = global.BackendCache
	case global.BackendLDAPName:
		p.backend = global.BackendLDAP
	case global.BackendMySQLName, global.BackendPostgresName, global.BackendSQLName:
		p.backend = global.BackendSQL
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

// Set sets the features supported by Nauthilus.
func (f *Feature) Set(value string) error {
	switch value {
	case global.FeatureTLSEncryption, global.FeatureRBL, global.FeatureGeoIP, global.FeatureRelayDomains, global.FeatureLua:
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

type DbgModule struct {
	name   string
	module global.DbgModule
}

func (d *DbgModule) String() string {
	return d.name
}

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
	case global.DbgSQLName:
		d.module = global.DbgSQL
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

func (d *DbgModule) Type() string {
	return "DebugModule"
}

func (d *DbgModule) Get() string {
	return d.name
}

func (d *DbgModule) GetModule() global.DbgModule {
	return d.module
}

// HTTPOptions is a container for HTTP basic authorization information, a X509 certificate and key.
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

// Config is the data structure that is used to store values given by the environment variables. For further information
// please read the markdown reference documentation.
//
// This configuration is loaded at startup and can not be reloaded.
//
//nolint:maligned // This structure has a logical order that shall not be mangled
type Config struct {
	InstanceName string

	// IP address and port of the HTTP web server separated by a colon.
	HTTPAddress string

	// LogJSON is a flag to enable logging in JSON format.
	LogJSON bool

	Verbosity

	SMTPBackendAddress string
	SMTPBackendPort    int
	IMAPBackendAddress string
	IMAPBackendPort    int

	WaitDelay        uint8
	MaxLoginAttempts uint8
	ResolveIP        bool

	MasterSeparator string
	GeoipPath       string

	// Redis settings for a master pool
	RedisAddress  string
	RedisPort     int
	RedisUsername string
	RedisPassword string

	// Redis settings for a replica pool
	RedisAddressRO string
	RedisPortRO    int

	RedisSentinels          []string
	RedisSentinelMasterName string
	RedisSentinelUsername   string
	RedisSentinelPassword   string

	RedisPrefix      string
	RedisDB          int
	RedisPosCacheTTL uint
	RedisNegCacheTTL uint

	DNSResolver string
	DNSTimeout  uint

	PassDBs    []*PassDB
	Features   []*Feature
	BruteForce []*Protocol
	DbgModule  []*DbgModule
	DevMode    bool

	MaxActionWorkers uint16

	HTTPOptions
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

// NewConfig is the constructor for a Config object and sets all member fields.
//
//nolint:gocognit,gocyclo,maintidx // Factory
func NewConfig() (*Config, error) {
	newCfg := &Config{}

	viper.SetEnvPrefix("nauthilus")

	// Set defaults
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
	viper.SetDefault("nginx_wait_delay", global.WaitDelay)
	viper.SetDefault("max_login_attempts", global.MaxLoginAttempts)
	viper.SetDefault("geoip_path", global.GeoIPPath)
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
	//nolint:gomnd // Ignore
	viper.SetDefault("dns_timeout", uint(10))
	viper.SetDefault("passdb_backends", []*PassDB{{global.BackendCache}, {global.BackendLDAP}})
	viper.SetDefault("redis_positive_cache_ttl", global.RedisPosCacheTTL)
	viper.SetDefault("redis_negative_cache_ttl", global.RedisNegCacheTTL)
	viper.SetDefault("features", []*Feature{
		{global.FeatureTLSEncryption},
		{global.FeatureRBL},
		{global.FeatureGeoIP},
		{global.FeatureRelayDomains},
	})
	viper.SetDefault("developer_mode", false)
	viper.SetDefault("max_action_workers", global.MaxActionWorkers)
	viper.SetDefault("sql_max_connections", global.SQLMaxConns)
	viper.SetDefault("sql_max_idle_connections", global.SQLMaxIdleConns)
	viper.SetDefault("lua_script_timeout", global.LuaMaxExecutionTime)
	viper.SetDefault("brute_force_protection", []*Protocol{
		{global.ProtoHTTP},
	})
	viper.SetDefault("trusted_proxies", []string{"127.0.0.1", "::1"})
	viper.SetDefault("html_static_content_path", "/usr/app/static")
	viper.SetDefault("default_logo_image", "/static/img/logo.png")
	viper.SetDefault("hydra_admin_uri", "http://127.0.0.1:4445")
	viper.SetDefault("http_client_skip_tls_verify", false)
	viper.SetDefault("homepage", "https://nauthilus.org")
	viper.SetDefault("language_resources", "/usr/app/resources")

	viper.SetDefault("login_page", "/login")
	viper.SetDefault("login_page_logo_image_alt", global.ImageCopyright)
	viper.SetDefault("login_remember_for", 10800)
	viper.SetDefault("login_page_welcome", "")
	// U2F/FIDO2
	viper.SetDefault("device_page", "/device")

	viper.SetDefault("consent_page", "/consent")
	viper.SetDefault("consent_page_logo_image_alt", global.ImageCopyright)
	viper.SetDefault("consent_remember_for", 3600)
	viper.SetDefault("consent_page_welcome", "")

	viper.SetDefault("logout_page", "/logout")
	viper.SetDefault("logout_page_welcome", "")

	viper.SetDefault("login_2fa_page", "/register")
	viper.SetDefault("login_2fa_page_welcome", "")

	viper.SetDefault("login_2fa_post_page", viper.GetString("login_2fa_page")+"/home")

	viper.SetDefault("totp_skew", uint(1))
	viper.SetDefault("totp_page", "/totp")
	viper.SetDefault("totp_issuer", "nauthilus.me")
	viper.SetDefault("totp_welcome", "")
	viper.SetDefault("totp_page_logo_image_alt", global.ImageCopyright)

	viper.SetDefault("webauthn_page", "/webauthn")
	viper.SetDefault("webauthn_display_name", "Nauthilus")
	viper.SetDefault("webauthn_rp_id", viper.GetString("totp_issuer"))
	viper.SetDefault("webauthn_rp_origins", []string{"https://login.nauthilus.me"})

	viper.SetDefault("notify_page", "/notify")
	viper.SetDefault("notify_page_welcome", "")
	viper.SetDefault("notify_page_logo_image_alt", global.ImageCopyright)

	viper.AllowEmptyEnv(true)
	viper.AutomaticEnv()

	newCfg.LogJSON = viper.GetBool("log_format_json")
	newCfg.InstanceName = viper.GetString("instance_name")
	newCfg.HTTPAddress = viper.GetString("http_address")
	newCfg.HTTPOptions.UseSSL = viper.GetBool("http_use_ssl")
	newCfg.HTTPOptions.UseBasicAuth = viper.GetBool("http_use_basic_auth")
	newCfg.SMTPBackendAddress = viper.GetString("smtp_backend_address")
	newCfg.SMTPBackendPort = viper.GetInt("smtp_backend_port")
	newCfg.IMAPBackendAddress = viper.GetString("imap_backend_address")
	newCfg.IMAPBackendPort = viper.GetInt("imap_backend_port")
	newCfg.ResolveIP = viper.GetBool("resolve_ip")
	newCfg.GeoipPath = viper.GetString("geoip_path")
	newCfg.RedisAddress = viper.GetString("redis_address")
	newCfg.RedisPort = viper.GetInt("redis_port")
	newCfg.RedisDB = viper.GetInt("redis_database_number")
	newCfg.RedisUsername = viper.GetString("redis_username")
	newCfg.RedisPassword = viper.GetString("redis_password")
	newCfg.RedisAddressRO = viper.GetString("redis_replica_address")
	newCfg.RedisPortRO = viper.GetInt("redis_replica_port")
	newCfg.RedisPrefix = viper.GetString("redis_prefix")
	newCfg.RedisPosCacheTTL = viper.GetUint("redis_positive_cache_ttl")
	newCfg.RedisNegCacheTTL = viper.GetUint("redis_negative_cache_ttl")
	newCfg.RedisSentinels = viper.GetStringSlice("redis_sentinels")
	newCfg.RedisSentinelMasterName = viper.GetString("redis_sentinel_master_name")
	newCfg.RedisSentinelUsername = viper.GetString("redis-sentinel-username")
	newCfg.RedisSentinelPassword = viper.GetString("redis-sentinel-password")
	newCfg.DNSResolver = viper.GetString("dns_resolver")
	newCfg.DevMode = viper.GetBool("developer_mode")

	verbosity, assertOk := viper.Get("verbose_level").(string)
	if !assertOk {
		return nil, errors.ErrWrongVerboseLevel
	}

	if err := newCfg.Verbosity.Set(verbosity); err != nil {
		return nil, err
	}

	if newCfg.HTTPOptions.UseSSL {
		if val := viper.GetString("http_tls_cert"); val != "" {
			newCfg.HTTPOptions.X509.Cert = val
		}

		if val := viper.GetString("http_tls_key"); val != "" {
			newCfg.HTTPOptions.X509.Key = val
		}
	}

	if newCfg.HTTPOptions.UseBasicAuth {
		if val := viper.GetString("http_basic_auth_username"); val != "" {
			newCfg.HTTPOptions.Auth.UserName = val
		}

		if val := viper.GetString("http_basic_auth_password"); val != "" {
			newCfg.HTTPOptions.Auth.Password = val
		}
	}

	if val := viper.GetUint("wait_delay"); val > 1 {
		if val < math.MaxUint8 {
			newCfg.WaitDelay = uint8(val)
		} else {
			newCfg.WaitDelay = math.MaxUint8
		}
	}

	if val := viper.GetUint("max_login_attempts"); val > 0 {
		if val < math.MaxUint8 {
			newCfg.MaxLoginAttempts = uint8(val)
		} else {
			newCfg.MaxLoginAttempts = math.MaxUint8
		}
	}

	if val := viper.GetUint("dns_timeout"); val > 1 {
		if val < math.MaxUint8 {
			newCfg.DNSTimeout = val
		} else {
			newCfg.DNSTimeout = math.MaxUint8
		}
	}

	if val := viper.GetUint("max_action_workers"); val < 1 {
		newCfg.MaxActionWorkers = uint16(1)
	} else {
		if val < math.MaxUint16 {
			newCfg.MaxActionWorkers = uint16(val)
		} else {
			newCfg.MaxActionWorkers = math.MaxUint16
		}
	}

	passDBsI := viper.Get("passdb_backends")
	switch passDBs := passDBsI.(type) {
	case string:
		passDBsList := strings.Split(strings.TrimSpace(passDBs), " ")
		for _, passDB := range passDBsList {
			p := &PassDB{}
			if err := p.Set(passDB); err != nil {
				return nil, err
			}

			newCfg.PassDBs = append(newCfg.PassDBs, p)
		}
	case []*PassDB:
		newCfg.PassDBs = passDBs
	}

	dbgModulesI := viper.Get("log_debug_modules")
	switch dbgModules := dbgModulesI.(type) {
	case string:
		dbgModulesList := strings.Split(strings.TrimSpace(dbgModules), " ")
		for _, dbgModule := range dbgModulesList {
			module := &DbgModule{}

			if err := module.Set(dbgModule); err != nil {
				return nil, err
			}

			newCfg.DbgModule = append(newCfg.DbgModule, module)
		}
	case []*DbgModule:
		newCfg.DbgModule = dbgModules
	}

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
				return nil, err
			}

			newCfg.Features = append(newCfg.Features, f)
		}
	case []*Feature:
		for _, feature := range features {
			f := &Feature{}
			if err := f.Set(feature.Get()); err != nil {
				return nil, err
			}

			newCfg.Features = append(newCfg.Features, f)
		}
	}

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

			newCfg.BruteForce = append(newCfg.BruteForce, p)
		}
	case []*Protocol:
		for _, bruteForceService := range bruteForceServices {
			p := &Protocol{}
			p.Set(bruteForceService.Get())

			newCfg.BruteForce = append(newCfg.BruteForce, p)
		}
	}

	return newCfg, nil
}

// HasFeature is a helper method for a Config object. It returns true, if a feature was set in the environment.
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
