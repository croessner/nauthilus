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
	stderrors "errors"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unsafe"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/go-kit/log/level"
	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// The configuration file is briefly documented in the markdown file Configuration-FileSettings.md.

// LoadableConfig is a variable of type *FileSettings that represents the configuration file that can be loaded.
var file File

// GetFile returns the loaded FileSettings configuration instance.
func GetFile() File {
	if file == nil {
		panic("FileSettings not loaded")
	}

	return file
}

// SetTestFile sets the global `file` variable to the provided `testFile` implementing the `File` interface.
func SetTestFile(testFile File) {
	file = testFile
}

// GetterHandler is an interface that provides methods to retrieve configuration and protocol information.
type GetterHandler interface {
	// GetConfig retrieves the configuration associated with the implementing object or returns nil if unavailable.
	GetConfig() any

	// GetProtocols retrieves protocol configurations associated with the implementing object or returns nil if unavailable.
	GetProtocols() any
}

// File represents an interface encapsulating various methods for configuration, file handling, and related operations.
type File interface {
	/*
		General file handling methods
	*/

	// HandleFile processes the configuration file.
	HandleFile() error

	/*
		Lua-related methods
	*/

	// HaveLuaFeatures checks if Lua features are available.
	HaveLuaFeatures() bool

	// HaveLuaFilters checks if Lua filters are active.
	HaveLuaFilters() bool

	// HaveLuaActions checks if Lua actions are enabled.
	HaveLuaActions() bool

	// HaveLuaHooks checks if Lua hooks are being used.
	HaveLuaHooks() bool

	// HaveLuaInit checks if a Lua initialization script exists.
	HaveLuaInit() bool

	// HaveLua checks if Lua-based configuration in general is available.
	HaveLua() bool

	// GetLuaInitScriptPath returns the path to the Lua initialization script.
	GetLuaInitScriptPath() string

	// GetLuaPackagePath retrieves the Lua package path from the configuration.
	GetLuaPackagePath() string

	// GetLuaScriptPath returns the path to the Lua script.
	GetLuaScriptPath() string

	// GetLuaSearchProtocol retrieves the Lua search protocol for a given protocol name.
	GetLuaSearchProtocol(protocol string) (*LuaSearchProtocol, error)

	/*
		LDAP-related methods
	*/

	// HaveLDAPBackend checks if an LDAP backend is being used.
	HaveLDAPBackend() bool

	// LDAPHavePoolOnly checks whether LDAP connections are only handled via a pool.
	LDAPHavePoolOnly() bool

	// GetLDAPConfigLookupPoolSize returns the pool size for LDAP lookups.
	GetLDAPConfigLookupPoolSize() int

	// GetLDAPConfigAuthPoolSize returns the pool size for LDAP authentication.
	GetLDAPConfigAuthPoolSize() int

	// GetLDAPConfigLookupIdlePoolSize retrieves the idle pool size for LDAP lookups.
	GetLDAPConfigLookupIdlePoolSize() int

	// GetLDAPConfigAuthIdlePoolSize retrieves the idle pool size for LDAP authentication.
	GetLDAPConfigAuthIdlePoolSize() int

	// GetLDAPConfigBindDN returns the Bind DN for LDAP.
	GetLDAPConfigBindDN() string

	// GetLDAPConfigBindPW retrieves the password for the LDAP bind.
	GetLDAPConfigBindPW() string

	// GetLDAPConfigTLSCAFile returns the TLS CA file for LDAP.
	GetLDAPConfigTLSCAFile() string

	// GetLDAPConfigTLSClientCert retrieves the TLS client certificate for LDAP.
	GetLDAPConfigTLSClientCert() string

	// GetLDAPConfigTLSClientKey returns the TLS client key for LDAP.
	GetLDAPConfigTLSClientKey() string

	// GetLDAPConfigServerURIs retrieves a list of LDAP server URIs.
	GetLDAPConfigServerURIs() []string

	// GetLDAPConfigStartTLS indicates if StartTLS is enabled for LDAP.
	GetLDAPConfigStartTLS() bool

	// GetLDAPConfigTLSSkipVerify checks whether TLS verification for LDAP is skipped.
	GetLDAPConfigTLSSkipVerify() bool

	// GetLDAPConfigSASLExternal checks if SASL External is configured for LDAP.
	GetLDAPConfigSASLExternal() bool

	// GetLDAPSearchProtocol retrieves the LDAP search protocol for a given protocol name.
	GetLDAPSearchProtocol(protocol string) (*LDAPSearchProtocol, error)

	/*
		Backend server-related methods
	*/

	// GetBackendServers returns a list of backend servers.
	GetBackendServers() []*BackendServer

	// GetBackendServerMonitoring provides the configuration and status of server monitoring.
	GetBackendServerMonitoring() *BackendServerMonitoring

	/*
		Features and options
	*/

	// HasFeature checks whether a specific feature is available.
	HasFeature(feature string) bool

	// GetServerInsightsEnableBlockProfile checks if block profiling for server insights is enabled.
	GetServerInsightsEnableBlockProfile() bool

	// GetServerInsightsEnablePprof checks whether pprof profiling is enabled for server insights.
	GetServerInsightsEnablePprof() bool

	/*
		Authentication and security methods
	*/

	// GetClientHost returns the client's hostname.
	GetClientHost() string

	// GetClientIP retrieves the client's IP address.
	GetClientIP() string

	// GetClientPort returns the client's port.
	GetClientPort() string

	// GetClientID retrieves the client's ID.
	GetClientID() string

	// GetUsername returns the username of the currently authenticated user.
	GetUsername() string

	// GetPassword retrieves the user's password.
	GetPassword() string

	// GetPasswordEncoded returns the encoded password.
	GetPasswordEncoded() string

	// GetLoginAttempt retrieves the current login attempt.
	GetLoginAttempt() string

	// GetAuthMethod provides the authentication method used.
	GetAuthMethod() string

	// GetSkipTOTP checks if TOTP (Two-Factor Authentication) is skipped.
	GetSkipTOTP(string) bool

	// GetSkipConsent checks if consent is skipped.
	GetSkipConsent(string) bool

	/*
		SSL and certificate-related methods
	*/

	// GetSSL retrieves the SSL configuration.
	GetSSL() string

	// GetSSLSessionID returns the SSL session ID.
	GetSSLSessionID() string

	// GetSSLVerify checks whether the SSL connection is verified.
	GetSSLVerify() string

	// GetSSLSubject retrieves the subject certificate of the SSL connection.
	GetSSLSubject() string

	// GetSSLClientCN returns the common name (CN) of the client certificate.
	GetSSLClientCN() string

	// GetSSLIssuer returns the issuer of the SSL certificate as a string.
	GetSSLIssuer() string

	// GetSSLClientNotBefore retrieves the `notBefore` date from the client's SSL certificate as a string.
	GetSSLClientNotBefore() string

	// GetSSLClientNotAfter retrieves the expiration timestamp of the SSL client certificate as a string.
	GetSSLClientNotAfter() string

	// GetSSLSubjectDN retrieves the Distinguished Name (DN) from the SSL certificate of the client.
	GetSSLSubjectDN() string

	// GetSSLIssuerDN retrieves the Distinguished Name (DN) of the SSL certificate issuer.
	GetSSLIssuerDN() string

	// GetSSLClientSubjectDN retrieves the distinguished name (DN) of the SSL client from the request.
	GetSSLClientSubjectDN() string

	// GetSSLClientIssuerDN retrieves the Distinguished Name (DN) of the issuer of the client's SSL certificate.
	GetSSLClientIssuerDN() string

	// GetSSLCipher retrieves the SSL cipher suite used in the connection.
	GetSSLCipher() string

	// GetSSLProtocol retrieves the SSL protocol version being used for the current connection.
	GetSSLProtocol() string

	// GetSSLSerial returns the serial number of the SSL certificate as a string.
	GetSSLSerial() string

	// GetSSLFingerprint returns the SSL fingerprint as a string representation of a hash.
	GetSSLFingerprint() string

	/*
		Network-related methods
	*/

	// GetLocalIP returns the local IP address.
	GetLocalIP() string

	// GetLocalPort retrieves the local port.
	GetLocalPort() string

	/*
		Protocol and rules
	*/

	// GetProtocol returns the protocol as a string, typically used to retrieve and determine the communication protocol in use.
	GetProtocol() string

	// GetAllProtocols returns all available protocols.
	GetAllProtocols() []string

	// GetBruteForceRules retrieves the brute force protection rules.
	GetBruteForceRules() []BruteForceRule

	/*
		Configuration and section retrievers
	*/

	// GetServer retrieves the server section of the configuration.
	GetServer() *ServerSection

	// GetRBLs retrieves the Realtime Block Lists (RBL).
	GetRBLs() *RBLSection

	// GetClearTextList returns a list of clear-text entries configured for the application.
	GetClearTextList() []string

	// GetRelayDomains retrieves the relay domains configuration section of the file.
	GetRelayDomains() *RelayDomainsSection

	// GetBruteForce retrieves the BruteForceSection configuration, containing brute force protection rules and settings.
	GetBruteForce() *BruteForceSection

	// GetLua retrieves the LuaSection from the configuration, containing actions, features, filters, hooks, and related config.
	GetLua() *LuaSection

	// GetOauth2 retrieves the Oauth2Section configuration, containing custom scopes and clients for OAuth2 authentication.
	GetOauth2() *Oauth2Section

	// GetLDAP returns the LDAPSection object containing configuration and search definitions for LDAP operations.
	GetLDAP() *LDAPSection
}

// FileSettings represents a comprehensive configuration structure utilized to manage server settings, blackhole lists, brute force,
// Lua scripting, OAuth2, LDAP, and other miscellaneous configurations. It includes synchronization via a mutex.
type FileSettings struct {
	Server                  *ServerSection           `mapstructure:"server" valdiate:"required"`
	RBLs                    *RBLSection              `mapstructure:"realtime_blackhole_lists" valdiate:"omitempty"`
	ClearTextList           []string                 `mapstructure:"cleartext_networks" valdiate:"omitempty,dive"`
	RelayDomains            *RelayDomainsSection     `mapstructure:"relay_domains" valdiate:"omitempty"`
	BackendServerMonitoring *BackendServerMonitoring `mapstructure:"backend_server_monitoring" valdiate:"omitempty"`
	BruteForce              *BruteForceSection       `mapstructure:"brute_force" valdiate:"omitempty"`
	Lua                     *LuaSection              `mapstructure:"lua" valdiate:"omitempty"`
	Oauth2                  *Oauth2Section           `mapstructure:"oauth2" valdiate:"omitempty"`
	LDAP                    *LDAPSection             `mapstructure:"ldap" valdiate:"omitempty"`
	Other                   map[string]any           `mapstructure:",remain"`
	Mu                      sync.Mutex
}

var _ File = (*FileSettings)(nil)

// GetRBLs retrieves the RBLSection configuration from the FileSettings instance.
// Returns nil if the FileSettings instance is nil.
func (f *FileSettings) GetRBLs() *RBLSection {
	if f == nil {
		return nil
	}

	return f.RBLs
}

// GetClearTextList retrieves a list of clear text strings from the FileSettings instance.
// Returns nil if the FileSettings instance is nil.
func (f *FileSettings) GetClearTextList() []string {
	if f == nil {
		return nil
	}

	return f.ClearTextList
}

// GetRelayDomains retrieves the RelayDomainsSection from the FileSettings. Returns nil if the FileSettings is nil.
func (f *FileSettings) GetRelayDomains() *RelayDomainsSection {
	if f == nil {
		return nil
	}

	return f.RelayDomains
}

// GetBruteForce returns the BruteForceSection associated with the FileSettings instance. Returns nil if the instance is nil.
func (f *FileSettings) GetBruteForce() *BruteForceSection {
	if f == nil {
		return nil
	}

	return f.BruteForce
}

// GetLua retrieves the LuaSection from the FileSettings instance.
// Returns nil if the FileSettings instance is nil.
func (f *FileSettings) GetLua() *LuaSection {
	if f == nil {
		return nil
	}

	return f.Lua
}

// GetOauth2 returns the Oauth2Section of the FileSettings instance. Returns nil if the FileSettings instance is nil.
func (f *FileSettings) GetOauth2() *Oauth2Section {
	if f == nil {
		return nil
	}

	return f.Oauth2
}

// GetLDAP retrieves the LDAPSection from the FileSettings instance. Returns nil if the FileSettings is nil.
func (f *FileSettings) GetLDAP() *LDAPSection {
	if f == nil {
		return nil
	}

	return f.LDAP
}

/*
 * Backend server monitoring
 */

// GetBackendServerMonitoring is a method on the FileSettings struct.
// It returns the BackendServerMonitoring field from the FileSettings struct.
func (f *FileSettings) GetBackendServerMonitoring() *BackendServerMonitoring {
	if f == nil {
		return nil
	}

	if f.BackendServerMonitoring == nil {
		return nil
	}

	return f.BackendServerMonitoring
}

// GetBackendServers retrieves the list of backend servers for the FileSettings instance or returns an empty list if none are configured.
func (f *FileSettings) GetBackendServers() []*BackendServer {
	if f == nil {
		return []*BackendServer{}
	}

	if f.GetBackendServerMonitoring() != nil {
		return f.BackendServerMonitoring.BackendServers
	}

	return []*BackendServer{}
}

// GetBackendServer retrieves the first BackendServer that matches the specified protocol from the FileSettings's backend servers.
// Returns nil if no matching server is found or if the FileSettings object is nil.
func (f *FileSettings) GetBackendServer(protocol string) *BackendServer {
	if f == nil {
		return nil
	}

	for _, server := range f.GetBackendServers() {
		if server.Protocol == protocol {
			return server
		}
	}

	return nil
}

/*
 * LDAP Config
 */

// GetLDAPConfigStartTLS determines if StartTLS is enabled for the LDAP configuration in the provided file.
// Returns false if the file or configuration is nil or not of type *LDAPConf.
func (f *FileSettings) GetLDAPConfigStartTLS() bool {
	if f == nil {
		return false
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return false
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.StartTLS
	}

	return false
}

// GetLDAPConfigTLSSkipVerify retrieves the TLSSkipVerify value from the LDAP configuration in the file.
// Returns false if the file or configuration is nil or not of type *LDAPConf.
func (f *FileSettings) GetLDAPConfigTLSSkipVerify() bool {
	if f == nil {
		return false
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return false
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.TLSSkipVerify
	}

	return false
}

// GetLDAPConfigSASLExternal checks if the LDAP configuration uses SASL External authentication and returns its status.
// It returns false if the FileSettings receiver or the LDAP configuration is nil, or if the type assertion fails.
func (f *FileSettings) GetLDAPConfigSASLExternal() bool {
	if f == nil {
		return false
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return false
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.SASLExternal
	}

	return false
}

// GetLDAPConfigLookupIdlePoolSize returns the configured idle connection pool size for LDAP lookups or a default value if unset.
func (f *FileSettings) GetLDAPConfigLookupIdlePoolSize() int {
	if f == nil {
		return definitions.LDAPIdlePoolSize
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return definitions.LDAPIdlePoolSize
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.LookupIdlePoolSize
	}

	return definitions.LDAPIdlePoolSize
}

// GetLDAPConfigAuthIdlePoolSize retrieves the authentication idle pool size for the LDAP configuration.
// It returns the default value if the configuration is nil or not properly set.
func (f *FileSettings) GetLDAPConfigAuthIdlePoolSize() int {
	if f == nil {
		return definitions.LDAPIdlePoolSize
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return definitions.LDAPIdlePoolSize
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.AuthIdlePoolSize
	}

	return definitions.LDAPIdlePoolSize
}

// GetLDAPConfigLookupPoolSize returns the size of the LDAP lookup connection pool, or a default if no configuration exists.
func (f *FileSettings) GetLDAPConfigLookupPoolSize() int {
	if f == nil {
		return definitions.LDAPIdlePoolSize
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return definitions.LDAPIdlePoolSize
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.LookupPoolSize
	}

	return definitions.LDAPIdlePoolSize
}

// GetLDAPConfigAuthPoolSize returns the authentication pool size configured for an LDAP backend or a default value if not set.
func (f *FileSettings) GetLDAPConfigAuthPoolSize() int {
	if f == nil {
		return definitions.LDAPIdlePoolSize
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return definitions.LDAPIdlePoolSize
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.AuthPoolSize
	}

	return definitions.LDAPIdlePoolSize
}

// GetLDAPConfigBindDN returns the BindDN value from the LDAP configuration if available, otherwise it returns an empty string.
func (f *FileSettings) GetLDAPConfigBindDN() string {
	if f == nil {
		return ""
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return ""
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.BindDN
	}

	return ""
}

// GetLDAPConfigBindPW retrieves the BindPW (bind password) from the LDAP configuration if available, or returns an empty string.
func (f *FileSettings) GetLDAPConfigBindPW() string {
	if f == nil {
		return ""
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return ""
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.BindPW
	}

	return ""
}

// GetLDAPConfigTLSCAFile retrieves the TLS CA file for the LDAP configuration if available, returning an empty string if not.
func (f *FileSettings) GetLDAPConfigTLSCAFile() string {
	if f == nil {
		return ""
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return ""
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.TLSCAFile
	}

	return ""
}

// GetLDAPConfigTLSClientCert retrieves the TLS client certificate for the LDAP configuration.
// Returns an empty string if the file or configuration is nil, or if the assertion of the config type fails.
func (f *FileSettings) GetLDAPConfigTLSClientCert() string {
	if f == nil {
		return ""
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return ""
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.TLSClientCert
	}

	return ""
}

// GetLDAPConfigTLSClientKey retrieves the TLS client key for the LDAP configuration. Returns an empty string if not set.
func (f *FileSettings) GetLDAPConfigTLSClientKey() string {
	if f == nil {
		return ""
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return ""
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.TLSClientKey
	}

	return ""
}

// GetLDAPConfigServerURIs retrieves the LDAP server URIs from the configuration or returns "ldap://localhost" as a default value.
func (f *FileSettings) GetLDAPConfigServerURIs() []string {
	if f == nil {
		return []string{"ldap://localhost"}
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return []string{"ldap://localhost"}
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.ServerURIs
	}

	return []string{"ldap://localhost"}
}

// GetLDAPSearchProtocol retrieves the LDAPSearchProtocol configuration based on the specified protocol.
// If the protocol is not found, it falls back to the default protocol.
// Returns an error if the configuration or default protocol is missing.
func (f *FileSettings) GetLDAPSearchProtocol(protocol string) (*LDAPSearchProtocol, error) {
	if f == nil {
		return nil, errors.ErrLDAPConfig.WithDetail("Missing search::protocol section and no default")
	}

	getSearch := f.GetProtocols(definitions.BackendLDAP)
	if getSearch == nil {
		return nil, errors.ErrLDAPConfig.WithDetail("Missing search::protocol section and no default")
	}

	for index := range getSearch.([]LDAPSearchProtocol) {
		for protoIndex := range getSearch.([]LDAPSearchProtocol)[index].Protocols {
			if getSearch.([]LDAPSearchProtocol)[index].Protocols[protoIndex] == protocol {
				return &getSearch.([]LDAPSearchProtocol)[index], nil
			}
		}
	}

	if protocol == definitions.ProtoDefault {
		return nil, errors.ErrLDAPConfig.WithDetail("Missing search::protocol section and no default")
	}

	return f.GetLDAPSearchProtocol(definitions.ProtoDefault)
}

/*
 * Lua config
 */

// GetLuaScriptPath retrieves the backend Lua script file path from the configuration. Returns an empty string if unavailable.
func (f *FileSettings) GetLuaScriptPath() string {
	if f == nil {
		return ""
	}

	getConfig := f.GetConfig(definitions.BackendLua)
	if getConfig == nil {
		return ""
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		return luaConf.BackendScriptPath
	}

	return ""
}

// GetLuaInitScriptPath returns the path to the Lua init script specified in the configuration.
// If the configuration or LuaConf is nil, it returns an empty string.
func (f *FileSettings) GetLuaInitScriptPath() string {
	if f == nil {
		return ""
	}

	getConfig := f.GetConfig(definitions.BackendLua)
	if getConfig == nil {
		return ""
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		return luaConf.InitScriptPath
	}

	return ""
}

// GetLuaPackagePath returns the Lua package path based on the file configuration or a default path if not specified.
func (f *FileSettings) GetLuaPackagePath() string {
	if f == nil {
		return definitions.LuaPackagePath
	}

	getConfig := f.GetConfig(definitions.BackendLua)
	if getConfig == nil {
		return definitions.LuaPackagePath
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		return luaConf.PackagePath
	}

	return definitions.LuaPackagePath
}

// GetLuaSearchProtocol retrieves a LuaSearchProtocol configuration matching the specified protocol.
// Returns a default LuaSearchProtocol if the protocol cannot be found and protocol is set to ProtoDefault.
// Returns a DetailedError if the protocol cannot be found and no default is configured.
// Accepts a string representing the protocol to search for.
func (f *FileSettings) GetLuaSearchProtocol(protocol string) (*LuaSearchProtocol, error) {
	if f == nil {
		return nil, errors.ErrLuaConfig.WithDetail("Missing search::protocol section and no default")
	}

	getSearch := f.GetProtocols(definitions.BackendLua)
	if getSearch == nil {
		return nil, errors.ErrLuaConfig.WithDetail("Missing search::protocol section and no default")
	}

	for index := range getSearch.([]LuaSearchProtocol) {
		for protoIndex := range getSearch.([]LuaSearchProtocol)[index].Protocols {
			if getSearch.([]LuaSearchProtocol)[index].Protocols[protoIndex] == protocol {
				return &getSearch.([]LuaSearchProtocol)[index], nil
			}
		}
	}

	if protocol == definitions.ProtoDefault {
		return nil, errors.ErrLuaConfig.WithDetail("Missing search::protocol section and no default")
	}

	return f.GetLuaSearchProtocol(definitions.ProtoDefault)
}

// HaveLuaFilters is a method on the FileSettings struct.
// It checks if the FileSettings struct has Lua filters.
// It returns true if there are Lua filters, and false otherwise.
func (f *FileSettings) HaveLuaFilters() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		return len(f.Lua.Filters) > 0
	}

	return false
}

// HaveLuaFeatures is a method on the FileSettings struct.
// It checks if the FileSettings struct has Lua features.
// It returns true if there are Lua features, and false otherwise.
func (f *FileSettings) HaveLuaFeatures() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		return len(f.Lua.Features) > 0
	}

	return false
}

// HaveLuaHooks returns true if the FileSettings instance has Lua hooks associated with it, otherwise returns false.
func (f *FileSettings) HaveLuaHooks() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		return len(f.Lua.Hooks) > 0
	}

	return false
}

// HaveLuaActions is a method on the FileSettings struct.
// It checks if the FileSettings struct has Lua actions.
// It returns true if the FileSettings struct has Lua actions, otherwise returns false.
func (f *FileSettings) HaveLuaActions() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		return len(f.Lua.Actions) > 0
	}

	return false
}

// HaveLuaInit checks if the Lua initialization script path is set in the configuration.
// It first confirms that the FileSettings instance supports Lua by invoking HaveLua method.
// Then, it retrieves the Lua configuration using GetConfig with the definitions.BackendLua constant.
// If the retrieved configuration is of type *LuaConf and the InitScriptPath is not empty, it returns true.
// Otherwise, it returns false.
func (f *FileSettings) HaveLuaInit() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		getConfig := f.GetConfig(definitions.BackendLua)
		if getConfig == nil {
			return false
		}

		return getConfig.(*LuaConf).InitScriptPath != ""
	}

	return false
}

// HaveLua is a method on the FileSettings struct.
// It checks if the Lua field in the FileSettings struct is not nil.
// It returns a boolean value indicating whether Lua is present or not.
func (f *FileSettings) HaveLua() bool {
	if f == nil {
		return false
	}

	return f.Lua != nil
}

// HaveLDAPBackend checks if the configuration includes an LDAP backend and returns true if it exists, otherwise false.
func (f *FileSettings) HaveLDAPBackend() bool {
	if f == nil {
		return false
	}

	for _, backendType := range f.Server.Backends {
		if backendType.Get() == definitions.BackendLDAP {
			return true
		}
	}

	return false
}

/*
 * Dynamic server configuration
 */

// GetServerInsightsEnablePprof returns true if the ServerInsights configuration enables pprof; otherwise, returns false.
func (f *FileSettings) GetServerInsightsEnablePprof() bool {
	if f == nil {
		return false
	}

	if f.HaveServer() {
		return f.GetServerInsights().EnablePprof
	}

	return false
}

// GetServerInsightsEnableBlockProfile checks if the block profiling feature is enabled in the server insights configuration.
func (f *FileSettings) GetServerInsightsEnableBlockProfile() bool {
	if f == nil {
		return false
	}

	if f.HaveServer() {
		return f.GetServerInsights().EnableBlockProfile
	}

	return false
}

// GetServerInsights is a method on the FileSettings struct.
// It returns the Insights field from the Server struct, which is accessed through the GetServer() method on the FileSettings struct.
// If the FileSettings struct does not have a Server, it returns nil.
func (f *FileSettings) GetServerInsights() *Insights {
	if f == nil {
		return nil
	}

	if f.HaveServer() {
		return &f.GetServer().Insights
	}

	return nil
}

// GetServer retrieves the ServerSection from the FileSettings. Returns nil if the FileSettings is nil or if no Server is present.
func (f *FileSettings) GetServer() *ServerSection {
	if f == nil {
		return nil
	}

	if f.HaveServer() {
		return f.Server
	}

	return nil
}

// HaveServer is a method on the FileSettings struct.
// It returns true if the Server field in the FileSettings struct is not nil, indicating that a server exists.
func (f *FileSettings) HaveServer() bool {
	if f == nil {
		return false
	}

	return f.Server != nil
}

/*
 * Generic environment mapping
 */

// RetrieveGetterMap returns a map associating each supported backend with its corresponding GetterHandler implementation.
// This method initializes a new map for the backends, and populates it by checking if certain backend sections exist.
// If the provided FileSettings object is nil, it returns nil.
func (f *FileSettings) RetrieveGetterMap() map[definitions.Backend]GetterHandler {
	if f == nil {
		return nil
	}

	getterMap := make(map[definitions.Backend]GetterHandler, 3)

	if ldapSection, ok := f.GetSection(definitions.BackendLDAP).(*LDAPSection); ok {
		getterMap[definitions.BackendLDAP] = ldapSection
	}

	if luaSection, ok := f.GetSection(definitions.BackendLua).(*LuaSection); ok {
		getterMap[definitions.BackendLua] = luaSection
	}

	return getterMap
}

// GetConfig retrieves the configuration for a given backend from the FileSettings receiver or returns nil if unavailable.
func (f *FileSettings) GetConfig(backend definitions.Backend) any {
	if f == nil {
		return nil
	}

	getterMap := f.RetrieveGetterMap()

	if config, found := getterMap[backend]; found {
		if config == nil {
			return nil
		}

		return config.GetConfig()
	}

	return nil
}

// GetProtocols retrieves protocol configurations for the specified backend type.
// Returns nil if the backend is not found or has no associated protocols.
func (f *FileSettings) GetProtocols(backend definitions.Backend) any {
	if f == nil {
		return nil
	}

	getterMap := f.RetrieveGetterMap()

	if proto, found := getterMap[backend]; found {
		if proto == nil {
			return nil
		}

		return proto.GetProtocols()
	}

	return nil
}

// GetSection retrieves the section corresponding to the provided backend type from the FileSettings. Returns nil if not found.
func (f *FileSettings) GetSection(backend definitions.Backend) any {
	if f == nil {
		return nil
	}

	switch backend {
	case definitions.BackendLDAP:
		return f.LDAP
	case definitions.BackendLua:
		return f.Lua
	default:
		return nil
	}
}

// GetBruteForceRules retrieves the list of brute force rules defined in the configuration file.
// If no rules are defined or the FileSettings instance is nil, it returns nil.
func (f *FileSettings) GetBruteForceRules() (rules []BruteForceRule) {
	if f == nil {
		return nil
	}

	if f.BruteForce != nil {
		if len(f.BruteForce.Buckets) > 0 {
			rules = f.BruteForce.Buckets
		}
	}

	return
}

// GetAllProtocols returns a unique slice of strings (a Set) for all defined protocols in the database search sections.
func (f *FileSettings) GetAllProtocols() []string {
	if f == nil {
		return nil
	}

	protocols := NewStringSet()

	if ldapProtocols := f.GetProtocols(definitions.BackendLDAP); ldapProtocols != nil {
		for index := range ldapProtocols.([]LDAPSearchProtocol) {
			for protoIndex := range f.LDAP.Search[index].Protocols {
				protocols.Set(f.LDAP.Search[index].Protocols[protoIndex])
			}
		}
	}

	if luaProtocols := f.GetProtocols(definitions.BackendLua); luaProtocols != nil {
		for index := range luaProtocols.([]LuaSearchProtocol) {
			for protoIndex := range f.Lua.Search[index].Protocols {
				protocols.Set(f.Lua.Search[index].Protocols[protoIndex])
			}
		}
	}

	return protocols.GetStringSlice()
}

// getOAuth2ClientIndex returns the index and found status of an OAuth-2 client with the given client ID in the LoadableConfig.Oauth2.Clients slice. If the client is found, the index
func (f *FileSettings) getOAuth2ClientIndex(clientId string) (index int, found bool) {
	if f.Oauth2 != nil {
		for index = range GetFile().GetOauth2().Clients {
			if f.Oauth2.Clients[index].ClientId != clientId {
				continue
			}

			found = true

			break
		}
	}

	return
}

// GetSkipTOTP returns a boolean true, if TOTP two-factor authentication shall be skipped for an OAuth-2 client.
func (f *FileSettings) GetSkipTOTP(clientId string) (skip bool) {
	if index, found := f.getOAuth2ClientIndex(clientId); found {
		return f.Oauth2.Clients[index].SkipTOTP
	}

	return
}

// GetSkipConsent returns a boolean true, if the consent dialog shall be skipped for an OAuth-2 client.
func (f *FileSettings) GetSkipConsent(clientId string) (skip bool) {
	if index, found := f.getOAuth2ClientIndex(clientId); found {
		return f.Oauth2.Clients[index].SkipConsent
	}

	return
}

// GetUsername returns the HTTP request header for the username
func (f *FileSettings) GetUsername() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.Username
}

// GetPassword returns the HTTP request header for the password
func (f *FileSettings) GetPassword() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.Password
}

// GetPasswordEncoded returns the HTTP request header to indicate if the password was encoded
func (f *FileSettings) GetPasswordEncoded() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.PasswordEncoded
}

// GetProtocol returns the HTTP request header for the used protocol
func (f *FileSettings) GetProtocol() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.Protocol
}

// GetLoginAttempt returns the HTTP request header for login-attempts
func (f *FileSettings) GetLoginAttempt() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.LoginAttempt
}

// GetAuthMethod returns the HTTP request header for the auth mechanism LOGIN or PLAIN
func (f *FileSettings) GetAuthMethod() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.AuthMethod
}

// GetLocalIP returns the HTTP request header that represents the local IP address for the server that accepts client requests
func (f *FileSettings) GetLocalIP() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.LocalIP
}

// GetLocalPort returns the HTTP request header that represents the local TCP port for the server that accepts client requests
func (f *FileSettings) GetLocalPort() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.LocalPort
}

// GetClientIP returns the HTTP request header that holds the client IP of the request
func (f *FileSettings) GetClientIP() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.ClientIP
}

// GetClientPort returns the HTTP request header that holds the client TCP port of the request
func (f *FileSettings) GetClientPort() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.ClientPort
}

// GetClientHost returns the HTTP request header used to retrieve an optional client hostname
func (f *FileSettings) GetClientHost() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.ClientHost
}

// GetClientID returns the HTTP request header used to retrieve an optional client ID
func (f *FileSettings) GetClientID() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.ClientID
}

// GetSSL returns the HTTP request header used to indicate SSL security for the current client connection
func (f *FileSettings) GetSSL() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSL
}

// GetSSLSessionID retrieves the SSL session ID from the file's default HTTP request header. Returns an empty string
// if the file is nil.
func (f *FileSettings) GetSSLSessionID() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLSessionID
}

// GetSSLVerify retrieves the SSL verification status from the default HTTP request header configuration.
// If the FileSettings receiver is nil, it returns an empty string.
func (f *FileSettings) GetSSLVerify() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLVerify
}

// GetSSLSubject retrieves the SSL subject from the default HTTP request header. Returns an empty string if the file is nil.
func (f *FileSettings) GetSSLSubject() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLSubject
}

// GetSSLClientCN retrieves the SSL client common name (CN) from the default HTTP request header.
func (f *FileSettings) GetSSLClientCN() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLClientCN
}

// GetSSLIssuer retrieves the SSL certificate issuer from the default HTTP request header of the server configuration.
func (f *FileSettings) GetSSLIssuer() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLIssuer
}

// GetSSLClientNotBefore retrieves the "SSLClientNotBefore" value from the default HTTP request header of the server.
// Returns an empty string if the FileSettings instance is nil.
func (f *FileSettings) GetSSLClientNotBefore() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLClientNotBefore
}

// GetSSLClientNotAfter retrieves the SSL client certificate's "not after" expiration date as a string. Returns an empty
// string if the FileSettings is nil.
func (f *FileSettings) GetSSLClientNotAfter() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLClientNotAfter
}

// GetSSLSubjectDN returns the SSL subject distinguished name from the Server's default HTTP request header.
func (f *FileSettings) GetSSLSubjectDN() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLSubjectDN
}

// GetSSLIssuerDN retrieves the Distinguished Name (DN) of the SSL issuer from the default HTTP request header.
func (f *FileSettings) GetSSLIssuerDN() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLSubject
}

// GetSSLClientSubjectDN returns the SSL client subject distinguished name from the default HTTP request header.
// If the FileSettings receiver is nil, it returns an empty string.
func (f *FileSettings) GetSSLClientSubjectDN() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLClientSubjectDN
}

// GetSSLClientIssuerDN returns the distinguished name (DN) of the SSL client issuer from the default HTTP request header.
func (f *FileSettings) GetSSLClientIssuerDN() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLClientIssuerDN
}

// GetSSLCipher retrieves the SSL cipher from the default HTTP request header of the server configuration.
// Returns an empty string if the FileSettings instance is nil.
func (f *FileSettings) GetSSLCipher() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLCipher
}

// GetSSLProtocol retrieves the SSL protocol from the DefaultHTTPRequestHeader of the Server configuration.
func (f *FileSettings) GetSSLProtocol() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLProtocol
}

// GetSSLSerial retrieves the SSL serial number from the default HTTP request header of the server configuration.
// Returns an empty string if the FileSettings receiver is nil.
func (f *FileSettings) GetSSLSerial() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLSerial
}

// GetSSLFingerprint retrieves the SSL fingerprint from the server's default HTTP request header.
// If the FileSettings is nil, it returns an empty string.
func (f *FileSettings) GetSSLFingerprint() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLFingerprint
}

// validateBruteForce validates the brute force configuration rules in the FileSettings object.
// Returns an error if any rule is invalid or violates constraints; otherwise, returns nil.
func (f *FileSettings) validateBruteForce() error {
	if f.BruteForce != nil {
		for _, rule := range f.BruteForce.Buckets {
			if rule.IPv4 && rule.IPv6 {
				return fmt.Errorf("%w: %s", errors.ErrRuleNoIPv4AndIPv6, rule.String())
			}

			if !(rule.IPv4 || rule.IPv6) {
				return fmt.Errorf("%w: %s", errors.ErrRuleMissingIPv4AndIPv6, rule.String())
			}

			if rule.Period < time.Second {
				rule.Period = rule.Period * time.Second

				if rule.Period > definitions.DurationMaxPeriod {
					return fmt.Errorf("%w: %s", errors.ErrDurationTooHigh, rule.String())
				}
			}
		}
	}

	return nil
}

// LDAPHavePoolOnly checks if the LDAP configuration is set to use the `PoolOnly` mode. Returns false if any element is nil.
func (f *FileSettings) LDAPHavePoolOnly() bool {
	if f == nil || f.LDAP == nil || f.LDAP.Config == nil {
		return false
	}

	return f.LDAP.Config.PoolOnly
}

// validatePassDBBackends validates the configuration of password database backends defined in the server's configuration.
// It ensures required sections, such as 'ldap', are properly configured and assigns default values where applicable.
// If any backend has invalid or incomplete settings, it returns an appropriate error.
func (f *FileSettings) validatePassDBBackends() error {
	for _, backend := range f.Server.Backends {
		switch backend.Get() {
		case definitions.BackendLDAP:
			if f.LDAP == nil {
				return errors.ErrNoLDAPSection
			}

			if !f.LDAP.Config.PoolOnly && len(f.LDAP.Search) == 0 {
				return errors.ErrNoLDAPSearchSection
			}

			/*
			 + Checking LDAP settings
			*/

			if f.GetLDAPConfigLookupPoolSize() < 1 {
				f.LDAP.Config.LookupPoolSize = runtime.NumCPU()
			}

			if f.GetLDAPConfigLookupIdlePoolSize() < 1 {
				f.LDAP.Config.LookupIdlePoolSize = definitions.LDAPIdlePoolSize
			}

			if f.GetLDAPConfigLookupPoolSize() < f.GetLDAPConfigLookupIdlePoolSize() {
				f.LDAP.Config.LookupPoolSize = f.LDAP.Config.LookupIdlePoolSize
			}

			if f.GetLDAPConfigAuthPoolSize() < 1 {
				f.LDAP.Config.AuthPoolSize = runtime.NumCPU()
			}

			if f.GetLDAPConfigAuthIdlePoolSize() < 1 {
				f.LDAP.Config.AuthIdlePoolSize = definitions.LDAPIdlePoolSize
			}

			if f.GetLDAPConfigAuthPoolSize() < f.GetLDAPConfigAuthIdlePoolSize() {
				f.LDAP.Config.AuthPoolSize = f.LDAP.Config.AuthIdlePoolSize
			}
		case definitions.BackendLua:
		case definitions.BackendUnknown:
		case definitions.BackendCache:
		case definitions.BackendLocalCache:
		}
	}

	return nil
}

// validateOAuth2 validates and processes the OAuth2 configuration in the FileSettings struct, ensuring valid custom scope descriptions.
func (f *FileSettings) validateOAuth2() error {
	if f.Oauth2 != nil {
		var descriptions map[string]any

		for customScopeIndex := range f.Oauth2.CustomScopes {
			descriptions = make(map[string]any)

			for key, value := range f.Oauth2.CustomScopes[customScopeIndex].Other {
				if !strings.HasPrefix(key, "description_") {
					continue
				}

				for _, languageTag := range DefaultLanguageTags {
					baseName, _ := languageTag.Base()
					if key == "description_"+baseName.String() {
						if description, assertOk := value.(string); assertOk {
							descriptions[key] = description
						}
					}
				}
			}

			f.Oauth2.CustomScopes[customScopeIndex].Other = descriptions
		}
	}

	return nil
}

// checkAddress verifies the validity of a network address, returning an error if it is improperly formatted.
func checkAddress(address string) error {
	_, _, err := net.SplitHostPort(address)

	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	return nil
}

// validateAddress ensures the server address is set and valid, defaulting to HTTPAddress if unset. Returns an error if invalid.
func (f *FileSettings) validateAddress() error {
	if f.Server.Address == "" {
		f.Server.Address = definitions.HTTPAddress
	}

	return checkAddress(f.Server.Address)
}

// setDefaultHydraAdminUrl sets the Hydra admin URL to a default value if it is not already configured.
func (f *FileSettings) setDefaultHydraAdminUrl() error {
	if f.Server.HydraAdminUrl == "" {
		f.Server.HydraAdminUrl = "http://127.0.0.1:4445"
	}

	return nil
}

// setDefaultInstanceName ensures the Server.InstanceName field is set to a default value if it is currently empty.
func (f *FileSettings) setDefaultInstanceName() error {
	if f.Server.InstanceName == "" {
		f.Server.InstanceName = definitions.InstanceName
	}

	return nil
}

// setDefaultDnsTimeout sets the default DNS timeout value for the file's server if not already specified.
func (f *FileSettings) setDefaultDnsTimeout() error {
	if f.Server.DNS.Timeout == 0 {
		f.Server.DNS.Timeout = definitions.DNSResolveTimeout
	}

	return nil
}

// setDefaultPosCacheTTL sets a default Positive Cache TTL for Redis if it is not already configured.
func (f *FileSettings) setDefaultPosCacheTTL() error {
	if f.Server.Redis.PosCacheTTL <= 0 {
		f.Server.Redis.PosCacheTTL = definitions.RedisPosCacheTTL * time.Second
	}

	if f.Server.Redis.PosCacheTTL < time.Second {
		f.Server.Redis.PosCacheTTL = f.Server.Redis.PosCacheTTL * time.Second

		if f.Server.Redis.PosCacheTTL > definitions.DurationMaxPeriod {
			return fmt.Errorf("%w: %s", errors.ErrDurationTooHigh, f.Server.Redis.PosCacheTTL.String())
		}
	}

	return nil
}

// setDefaultNegCacheTTL sets the default TTL for negative cache entries in Redis if it is not already configured.
func (f *FileSettings) setDefaultNegCacheTTL() error {
	if f.Server.Redis.NegCacheTTL <= 0 {
		f.Server.Redis.NegCacheTTL = definitions.RedisNegCacheTTL * time.Second
	}

	if f.Server.Redis.NegCacheTTL < time.Second {
		f.Server.Redis.NegCacheTTL = f.Server.Redis.NegCacheTTL * time.Second

		if f.Server.Redis.NegCacheTTL > definitions.DurationMaxPeriod {
			return fmt.Errorf("%w: %s", errors.ErrDurationTooHigh, f.Server.Redis.NegCacheTTL.String())
		}
	}

	return nil
}

// setDefaultDelimiter sets the default delimiter for the master user if none has been defined and returns any error.
func (f *FileSettings) setDefaultDelimiter() error {
	if f.Server.MasterUser.Delimiter == "" {
		f.Server.MasterUser.Delimiter = "*"
	}

	return nil
}

// setDefaultHeaders ensures all default HTTP request headers are set. If any header is empty, it is replaced with its default value.
func (f *FileSettings) setDefaultHeaders() error {
	defaults := map[string]*string{
		"Auth-User":            &f.Server.DefaultHTTPRequestHeader.Username,
		"Auth-Pass":            &f.Server.DefaultHTTPRequestHeader.Password,
		"Auth-Protocol":        &f.Server.DefaultHTTPRequestHeader.Protocol,
		"Auth-Method":          &f.Server.DefaultHTTPRequestHeader.AuthMethod,
		"Auth-Login-Attempt":   &f.Server.DefaultHTTPRequestHeader.LoginAttempt,
		"Auth-SSL-Serial":      &f.Server.DefaultHTTPRequestHeader.SSLSerial,
		"Auth-SSL-Fingerprint": &f.Server.DefaultHTTPRequestHeader.SSLFingerprint,
		"Client-IP":            &f.Server.DefaultHTTPRequestHeader.ClientIP,

		"X-Auth-Password-Encoded": &f.Server.DefaultHTTPRequestHeader.PasswordEncoded,
		"X-Local-IP":              &f.Server.DefaultHTTPRequestHeader.LocalIP,
		"X-Auth-Port":             &f.Server.DefaultHTTPRequestHeader.LocalPort,
		"X-Client-Port":           &f.Server.DefaultHTTPRequestHeader.ClientPort,
		"X-Client-ID":             &f.Server.DefaultHTTPRequestHeader.ClientID,

		"X-SSL":                   &f.Server.DefaultHTTPRequestHeader.SSL,
		"X-SSL-Session-ID":        &f.Server.DefaultHTTPRequestHeader.SSLSessionID,
		"X-SSL-Client-Verify":     &f.Server.DefaultHTTPRequestHeader.SSLVerify,
		"X-SSL-Client-DN":         &f.Server.DefaultHTTPRequestHeader.SSLSubject,
		"X-SSL-Client-CN":         &f.Server.DefaultHTTPRequestHeader.SSLClientCN,
		"X-SSL-Issuer":            &f.Server.DefaultHTTPRequestHeader.SSLIssuer,
		"X-SSL-Client-NotBefore":  &f.Server.DefaultHTTPRequestHeader.SSLClientNotBefore,
		"X-SSL-Client-NotAfter":   &f.Server.DefaultHTTPRequestHeader.SSLClientNotAfter,
		"X-SSL-Subject-DN":        &f.Server.DefaultHTTPRequestHeader.SSLSubjectDN,
		"X-SSL-Issuer-DN":         &f.Server.DefaultHTTPRequestHeader.SSLIssuerDN,
		"X-SSL-Client-Subject-DN": &f.Server.DefaultHTTPRequestHeader.SSLClientSubjectDN,
		"X-SSL-Client-Issuer-DN":  &f.Server.DefaultHTTPRequestHeader.SSLClientIssuerDN,
		"X-SSL-Cipher":            &f.Server.DefaultHTTPRequestHeader.SSLCipher,
		"X-SSL-Protocol":          &f.Server.DefaultHTTPRequestHeader.SSLProtocol,
	}

	for defaultHeader, field := range defaults {
		if *field == "" {
			*field = defaultHeader
		}
	}

	return nil
}

// setDefaultMaxConcurrentRequests ensures that the MaxConcurrentRequests parameter is set to a valid value.
func (f *FileSettings) setDefaultMaxConcurrentRequests() error {
	if f.Server.MaxConcurrentRequests == 0 {
		f.Server.MaxConcurrentRequests = definitions.MaxConcurrentRequests
	}

	return nil
}

// setDefaultPasswordHistory sets MaxPasswordHistoryEntries to a default value if non-positive and returns an error if any.
func (f *FileSettings) setDefaultPasswordHistory() error {
	if f.Server.MaxPasswordHistoryEntries == 0 {
		f.Server.MaxPasswordHistoryEntries = definitions.MaxPasswordHistoryEntries
	}

	return nil
}

// validate ensures that the FileSettings object is correctly configured by running a series of validation and default-setting functions.
// Returns an error if any validation function fails, otherwise returns nil.
func (f *FileSettings) validate() (err error) {
	validators := []func() error{
		f.validateBruteForce,
		f.validatePassDBBackends,
		f.validateOAuth2,
		f.validateAddress,

		// Without errors, but fixing things
		f.setDefaultHydraAdminUrl,
		f.setDefaultInstanceName,
		f.setDefaultDnsTimeout,
		f.setDefaultPosCacheTTL,
		f.setDefaultNegCacheTTL,
		f.setDefaultDelimiter,
		f.setDefaultHeaders,
		f.setDefaultMaxConcurrentRequests,
		f.setDefaultPasswordHistory,
	}

	for _, validatorFunc := range validators {
		if err = validatorFunc(); err != nil {
			return err
		}
	}

	return nil
}

// HasFeature checks if the given feature exists in the LoadableConfig's Features list
func (f *FileSettings) HasFeature(feature string) bool {
	if f.Server.Features == nil {
		return false
	}

	for _, item := range f.Server.Features {
		if item.Get() == feature {
			return true
		}
	}

	return false
}

// processVerboseLevel parses the input, sets the verbosity level, and returns a Verbosity instance or an error.
func processVerboseLevel(input any) (any, error) {
	verbosity := Verbosity{}
	err := verbosity.Set(input.(string))

	return verbosity, err
}

// processDebugModules processes the input to generate a slice of DbgModule pointers or returns an error for invalid inputs.
// The input can be a string, a slice of strings, or a slice of any containing strings.
func processDebugModules(input any) (any, error) {
	var dbgModules []*DbgModule

	addDebugModule := func(data string) error {
		module := &DbgModule{}
		if err := module.Set(data); err != nil {
			return err
		}

		dbgModules = append(dbgModules, module)

		return nil
	}

	switch data := input.(type) {
	case string:
		if err := addDebugModule(data); err != nil {
			return nil, err
		}
	case []string:
		for _, dbgModule := range data {
			if err := addDebugModule(dbgModule); err != nil {
				return nil, err
			}
		}
	case []any:
		for _, dbgModule := range data {
			str, ok := dbgModule.(string)
			if !ok {
				return nil, fmt.Errorf("invalid value in array, expected string, got %T", dbgModule)
			}

			if err := addDebugModule(str); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("invalid type %T, expected string or []string", data)
	}

	return dbgModules, nil
}

// processFeatures converts input values into a slice of Feature pointers or returns an error for invalid input types or values.
func processFeatures(input any) (any, error) {
	var features []*Feature

	addFeature := func(data string) error {
		feature := &Feature{}
		if err := feature.Set(data); err != nil {
			return err
		}

		features = append(features, feature)

		return nil
	}

	switch data := input.(type) {
	case string:
		if err := addFeature(data); err != nil {
			return nil, err
		}
	case []string:
		for _, feature := range data {
			if err := addFeature(feature); err != nil {
				return nil, err
			}
		}
	case []any:
		for _, feature := range data {
			str, ok := feature.(string)
			if !ok {
				return nil, fmt.Errorf("invalid value in array, expected string, got %T", feature)
			}

			if err := addFeature(str); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("invalid type %T, expected string or []string", data)
	}

	return features, nil
}

// processProtocols processes the input to generate a slice of Protocol pointers or returns an error for invalid inputs.
// The input can be a string, a slice of strings, or a slice of any containing strings.
func processProtocols(input any) (any, error) {
	var protocols []*Protocol

	addProtocol := func(data string) {
		protocol := &Protocol{}

		protocol.Set(data)

		protocols = append(protocols, protocol)
	}

	switch data := input.(type) {
	case string:
		addProtocol(data)
	case []string:
		for _, protocol := range data {
			addProtocol(protocol)
		}
	case []any:
		for _, protocol := range data {
			str, ok := protocol.(string)
			if !ok {
				return nil, fmt.Errorf("invalid value in array, expected string, got %T", protocol)
			}

			addProtocol(str)
		}
	default:
		return nil, fmt.Errorf("invalid type %T, expected string or []string", data)
	}

	return protocols, nil
}

// processBackends processes the input to create and configure a list of Backend instances, returning them or an error.
func processBackends(input any) (any, error) {
	var backends []*Backend

	addBackend := func(data string) error {
		backend := &Backend{}
		if err := backend.Set(data); err != nil {
			return err
		}

		backends = append(backends, backend)

		return nil
	}

	switch data := input.(type) {
	case string:
		if err := addBackend(data); err != nil {
			return nil, err
		}
	case []string:
		for _, backend := range data {
			if err := addBackend(backend); err != nil {
				return nil, err
			}
		}
	case []any:
		for _, backend := range data {
			str, ok := backend.(string)
			if !ok {
				return nil, fmt.Errorf("invalid value in array, expected string, got %T", backend)
			}

			if err := addBackend(str); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("invalid type %T, expected string or []string", data)
	}

	return backends, nil
}

// createDecoderOption returns a viper.DecoderConfigOption to configure a mapstructure decoder with custom DecodeHook functions.
// The DecodeHook functions handle conversions to specific types such as Verbosity, DbgModule, Feature, Protocol, and Backend.
func createDecoderOption() viper.DecoderConfigOption {
	return func(config *mapstructure.DecoderConfig) {
		config.DecodeHook = mapstructure.ComposeDecodeHookFunc(
			config.DecodeHook,
			func(from reflect.Type, to reflect.Type, data any) (any, error) {
				switch {
				case to == reflect.TypeOf(Verbosity{}):
					return processVerboseLevel(data)
				case to == reflect.TypeOf([]*DbgModule{}):
					return processDebugModules(data)
				case to == reflect.TypeOf([]*Feature{}):
					return processFeatures(data)
				case to == reflect.TypeOf([]*Protocol{}):
					return processProtocols(data)
				case to == reflect.TypeOf([]*Backend{}):
					return processBackends(data)
				default:
					return data, nil
				}
			},
		)
	}
}

// toSnakeCase converts a given camelCase or PascalCase string to snake_case format.
func toSnakeCase(fieldName string) string {
	var result strings.Builder

	previousWasUpper := false

	for i, r := range fieldName {
		if unicode.IsUpper(r) {
			if i > 0 && !previousWasUpper {
				result.WriteByte('_')
			}

			previousWasUpper = true
		} else {
			previousWasUpper = false
		}

		result.WriteRune(unicode.ToLower(r))
	}

	return result.String()
}

// prettyFormatValidationErrors formats validation errors into a user-friendly error message string.
// It iterates through all validation errors, converting each into a descriptive string, including the failed rule and field.
func prettyFormatValidationErrors(validationErrors validator.ValidationErrors) error {
	var errorMessages []string

	for _, fieldErr := range validationErrors {
		message := fmt.Sprintf(
			"field '%s' (struct field: '%s') failed on the '%s' validation rule",
			toSnakeCase(fieldErr.Field()), // The field name configured (e.g., Server, Port)
			fieldErr.StructField(),        // Struct field name (e.g., Server, Port)
			fieldErr.Tag(),                // Validation rule (e.g., "required", "min")
		)

		// Include the rule parameter if it exists (e.g., "1" for "min=1")
		if fieldErr.Param() != "" {
			message = fmt.Sprintf("%s. Rule parameter: %s", message, fieldErr.Param())
		}

		errorMessages = append(errorMessages, message)
	}

	return stderrors.New("validation errors: " + strings.Join(errorMessages, "; "))
}

// HandleFile applies the configuration settings loaded from the configuration file. It does sanity checks to make sure
// Nauthilus has a working configuration.
func (f *FileSettings) HandleFile() (err error) {
	var validationErrors validator.ValidationErrors

	if f == nil {
		return nil
	}

	f.Mu.Lock()

	defer f.Mu.Unlock()

	if err = viper.UnmarshalExact(f, createDecoderOption()); err != nil {
		return err
	}

	if environment.GetDevMode() {
		dumpConfig(f)
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	validate.RegisterValidation("validateCookieStoreEncKey", validateCookieStoreEncKey)

	if err = validate.Struct(f); err != nil {
		if stderrors.As(err, &validationErrors) {
			return prettyFormatValidationErrors(validationErrors)
		}

		return err
	}

	if err = f.validate(); err != nil {
		return err
	}

	// Throw away unsupported keys
	f.Other = nil

	return nil
}

func dumpConfig(f *FileSettings) {
	var intermediateMap map[string]interface{}

	if f == nil {
		fmt.Println("Config is nil")

		return
	}

	err := mapstructure.Decode(f, &intermediateMap)
	if err != nil {
		fmt.Printf("Failed to convert config to map: %v\n", err)

		return
	}

	data, err := yaml.Marshal(intermediateMap)
	if err != nil {
		fmt.Printf("Failed to PrettyPrint config as YAML: %v\n", err)

		return
	}

	fmt.Println(string(data))
}

// bindEnvs recursively binds struct fields to environment variables using Viper, constructing keys from struct tags or field names.
// i is the pointer to the struct to process, and parts is a slice of strings used to construct nested keys recursively.
// Returns an error if environment variable binding fails for any key.
func bindEnvs(i any, parts ...string) error {
	ifv := reflect.ValueOf(i)
	if ifv.Kind() == reflect.Ptr {
		ifv = ifv.Elem()
	}

	ift := ifv.Type()

	for i := range ift.NumField() {
		v := ifv.Field(i)
		t := ift.Field(i)

		if !t.IsExported() {
			continue
		}

		tag := t.Tag.Get("mapstructure")
		if tag == "" {
			tag = t.Name
		}

		if t.Type.Kind() == reflect.Ptr && t.Type.Elem().Kind() == reflect.Struct {
			if v.IsNil() {
				v.Set(reflect.New(t.Type.Elem()))
			}

			err := bindEnvs(v.Interface(), append(parts, tag)...)
			if err != nil {
				return err
			}
		} else if v.Kind() == reflect.Struct {
			err := bindEnvs(v.Addr().Interface(), append(parts, tag)...)
			if err != nil {
				return err
			}
		} else {
			key := strings.Join(append(parts, tag), ".")

			err := viper.BindEnv(key)
			if err != nil {
				return fmt.Errorf("failed to bind %q: %w", key, err)
			}
		}
	}

	return nil
}

// NewFile is the constructor for a ConfigFile object.
func NewFile() (newCfg File, err error) {
	newCfg = &FileSettings{}

	viper.SetConfigName("nauthilus") // name of environment file (without extension)
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/usr/local/etc/nauthilus/")
	viper.AddConfigPath("/etc/nauthilus/")
	viper.AddConfigPath("$HOME/.nauthilus")
	viper.AddConfigPath(".")

	err = viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	// Register all known config variables with env variables.
	bindEnvs(&FileSettings{})

	err = newCfg.HandleFile()

	file = newCfg

	return newCfg, err
}

// ReloadConfigFile is a thread safe function to reload a ConfigFile object.
//
//nolint:forcetypeassert,gocognit // Ignore
func ReloadConfigFile() (err error) {
	newCfgReload := &FileSettings{}

	if err = viper.ReadInConfig(); err != nil {
		return
	}

	// Construct new configuration
	if err = newCfgReload.HandleFile(); err != nil {
		return
	}

	// Replace existing configuration
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&file)), unsafe.Pointer(newCfgReload))

	level.Info(log.Logger).Log(definitions.LogKeyMsg, "Reloading configuration file finished")

	return
}
