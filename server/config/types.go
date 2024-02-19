package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/go-ldap/ldap/v3"
)

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
	value = strings.TrimSpace(value)

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
	value = strings.TrimSpace(value)

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
	value = strings.TrimSpace(value)

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
// Valid feature names are "tls_encryption", "rbl", "relay_domains", and "lua".
// If the value is valid, the name field of the Feature struct is updated accordingly.
// An error of type ErrWrongFeature is returned if the value is not valid.
func (f *Feature) Set(value string) error {
	switch value {
	case "":
	case global.FeatureTLSEncryption, global.FeatureRBL, global.FeatureRelayDomains, global.FeatureLua, global.FeatureNginxMonitoring:
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
	value = strings.TrimSpace(value)

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
	case global.DbgFilterName:
		d.module = global.DbgFilter
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
