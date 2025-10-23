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
	"encoding/json"
	stderrors "errors"
	"fmt"
	"log/slog"
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
	"github.com/croessner/nauthilus/server/log/level"

	"github.com/go-playground/validator/v10"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// The configuration file is briefly documented in the markdown file Configuration-FileSettings.md.

// LoadableConfig is a variable of type *FileSettings that represents the configuration file that can be loaded.
var file File

// ConfigFilePath stores the path to the configuration file specified via the -config flag
var ConfigFilePath string

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

	// GetConfigFileAsJSON returns the configuration file contents as a JSON-formatted string. An error is returned if conversion fails.
	GetConfigFileAsJSON() ([]byte, error)

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

	// HaveLuaBackend returns a boolean indicating whether a Lua backend is available in the current configuration.
	HaveLuaBackend() bool

	// GetLuaInitScriptPath returns the path to the Lua initialization script.
	GetLuaInitScriptPath() string

	// GetLuaInitScriptPaths returns all paths to Lua initialization scripts.
	GetLuaInitScriptPaths() []string

	// GetLuaPackagePath retrieves the Lua package path from the configuration.
	GetLuaPackagePath() string

	// GetLuaNumberOfWorkers returns the number of Lua workers configured for handling Lua scripts.
	GetLuaNumberOfWorkers() int

	// GetLuaActionNumberOfWorkers returns the number of Lua Action workers.
	GetLuaActionNumberOfWorkers() int

	// GetLuaFeatureVMPoolSize returns the VM pool size for Lua features.
	GetLuaFeatureVMPoolSize() int

	// GetLuaFilterVMPoolSize returns the VM pool size for Lua filters.
	GetLuaFilterVMPoolSize() int

	// GetLuaHookVMPoolSize returns the VM pool size for Lua hooks.
	GetLuaHookVMPoolSize() int

	// GetLuaScriptPath returns the path to the Lua script.
	GetLuaScriptPath() string

	// GetLuaSearchProtocol retrieves the Lua search protocol for a given protocol name.
	GetLuaSearchProtocol(protocol string, backendName string) (*LuaSearchProtocol, error)

	// GetLuaOptionalBackends retrieves a map of Lua configurations for optional backends, indexed by their names.
	GetLuaOptionalBackends() map[string]*LuaConf

	/*
		LDAP-related methods
	*/

	// HaveLDAPBackend checks if an LDAP backend is being used.
	HaveLDAPBackend() bool

	// LDAPHavePoolOnly checks whether LDAP connections are only handled via a pool.
	LDAPHavePoolOnly(backendName string) bool

	// GetLDAPConfigLookupPoolSize returns the pool size for LDAP lookups.
	GetLDAPConfigLookupPoolSize() int

	// GetLDAPConfigAuthPoolSize returns the pool size for LDAP authentication.
	GetLDAPConfigAuthPoolSize() int

	// GetLDAPConfigConnectAbortTimeout retrieves the timeout duration for aborting LDAP connect attempts.
	GetLDAPConfigConnectAbortTimeout() time.Duration

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

	// GetLDAPConfigNumberOfWorkers returns the configured number of worker threads for LDAP processing.
	GetLDAPConfigNumberOfWorkers() int

	// GetLDAPConfigServerURIs retrieves a list of LDAP server URIs.
	GetLDAPConfigServerURIs() []string

	// GetLDAPConfigStartTLS indicates if StartTLS is enabled for LDAP.
	GetLDAPConfigStartTLS() bool

	// GetLDAPConfigTLSSkipVerify checks whether TLS verification for LDAP is skipped.
	GetLDAPConfigTLSSkipVerify() bool

	// GetLDAPConfigSASLExternal checks if SASL External is configured for LDAP.
	GetLDAPConfigSASLExternal() bool

	// GetLDAPSearchProtocol retrieves the LDAP search protocol for a given protocol name.
	GetLDAPSearchProtocol(protocol string, poolName string) (*LDAPSearchProtocol, error)

	// GetLDAPOptionalPools returns a map of optional LDAP pool configurations, indexed by their respective keys.
	GetLDAPOptionalPools() map[string]*LDAPConf

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

	/*
		Authentication and security methods
	*/

	// GetClientHost returns the client's hostname.
	GetClientHost() string

	// GetOIDCCID returns the OpenID Connect Client ID as a string.
	GetOIDCCID() string

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
	LDAP                    *LDAPSection             `mapstructure:"ldap" valdiate:"omitempty"`
	Oauth2                  *Oauth2Section           `mapstructure:"oauth2" valdiate:"omitempty"`
	Other                   map[string]any           `mapstructure:",remain"`
	Mu                      sync.Mutex
}

var _ File = (*FileSettings)(nil)

// GetConfigFileAsJSON returns the current configuration settings as a JSON string, ensuring thread safety with a mutex lock.
func (f *FileSettings) GetConfigFileAsJSON() ([]byte, error) {
	f.Mu.Lock()
	defer f.Mu.Unlock()

	allSettings := viper.AllSettings()

	jsonBytes, err := json.Marshal(allSettings)

	return jsonBytes, err
}

// GetRBLs retrieves the RBLSection configuration from the FileSettings instance.
// Returns nil if the FileSettings instance is nil.
func (f *FileSettings) GetRBLs() *RBLSection {
	if f == nil {
		return &RBLSection{}
	}

	return f.RBLs
}

// GetClearTextList retrieves a list of clear text strings from the FileSettings instance.
// Returns nil if the FileSettings instance is nil.
func (f *FileSettings) GetClearTextList() []string {
	if f == nil {
		return []string{}
	}

	return f.ClearTextList
}

// GetRelayDomains retrieves the RelayDomainsSection from the FileSettings. Returns nil if the FileSettings is nil.
func (f *FileSettings) GetRelayDomains() *RelayDomainsSection {
	if f == nil {
		return &RelayDomainsSection{}
	}

	return f.RelayDomains
}

// GetBruteForce returns the BruteForceSection associated with the FileSettings instance. Returns nil if the instance is nil.
func (f *FileSettings) GetBruteForce() *BruteForceSection {
	if f == nil {
		return &BruteForceSection{}
	}

	return f.BruteForce
}

// GetLua retrieves the LuaSection from the FileSettings instance.
// Returns nil if the FileSettings instance is nil.
func (f *FileSettings) GetLua() *LuaSection {
	if f == nil {
		return &LuaSection{}
	}

	return f.Lua
}

// GetOauth2 returns the Oauth2Section of the FileSettings instance. Returns nil if the FileSettings instance is nil.
func (f *FileSettings) GetOauth2() *Oauth2Section {
	if f == nil {
		return &Oauth2Section{}
	}

	return f.Oauth2
}

// GetLDAP retrieves the LDAPSection from the FileSettings instance. Returns nil if the FileSettings is nil.
func (f *FileSettings) GetLDAP() *LDAPSection {
	if f == nil {
		return &LDAPSection{}
	}

	return f.LDAP
}

/*
 * Backend server monitoring
 */

// GetBackendServerMonitoring is a method on the FileSettings struct.
// It returns the BackendServerMonitoring field from the FileSettings struct.
// Returns an empty BackendServerMonitoring if the FileSettings is nil or if the BackendServerMonitoring field is nil.
func (f *FileSettings) GetBackendServerMonitoring() *BackendServerMonitoring {
	if f == nil {
		return &BackendServerMonitoring{}
	}

	if f.BackendServerMonitoring == nil {
		return &BackendServerMonitoring{}
	}

	return f.BackendServerMonitoring
}

// GetBackendServers retrieves the list of backend servers for the FileSettings instance or returns an empty list if none are configured.
func (f *FileSettings) GetBackendServers() []*BackendServer {
	if f == nil {
		return []*BackendServer{}
	}

	if f.GetBackendServerMonitoring() != nil {
		return f.GetBackendServerMonitoring().GetBackendServers()
	}

	return []*BackendServer{}
}

// GetBackendServer retrieves the first BackendServer that matches the specified protocol from the FileSettings's backend servers.
// Returns an empty BackendServer if no matching server is found or if the FileSettings object is nil.
func (f *FileSettings) GetBackendServer(protocol string) *BackendServer {
	if f == nil {
		return &BackendServer{}
	}

	for _, server := range f.GetBackendServers() {
		if server.GetProtocol() == protocol {
			return server
		}
	}

	return &BackendServer{}
}

/*
 * LDAP Config
 */

// GetLDAPConfigNumberOfWorkers retrieves the number of workers for the LDAP configuration. Defaults to a predefined value.
func (f *FileSettings) GetLDAPConfigNumberOfWorkers() int {
	if f == nil {
		return definitions.DefaultNumberOfWorkers
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return definitions.DefaultNumberOfWorkers
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.GetNumberOfWorkers()
	}

	return definitions.DefaultNumberOfWorkers
}

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
		return ldapConf.IsStartTLS()
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
		return ldapConf.IsTLSSkipVerify()
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
		return ldapConf.IsSASLExternal()
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
		return ldapConf.GetLookupIdlePoolSize()
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
		return ldapConf.GetAuthIdlePoolSize()
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
		return ldapConf.GetLookupPoolSize()
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
		return ldapConf.GetAuthPoolSize()
	}

	return definitions.LDAPIdlePoolSize
}

// GetLDAPConfigConnectAbortTimeout retrieves the abort timeout duration from the LDAP configuration, or returns 0 if not applicable.
func (f *FileSettings) GetLDAPConfigConnectAbortTimeout() time.Duration {
	if f == nil {
		return 0
	}

	getConfig := f.GetConfig(definitions.BackendLDAP)
	if getConfig == nil {
		return 0
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.GetConnectAbortTimeout()
	}

	return 0
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
		return ldapConf.GetBindDN()
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
		return ldapConf.GetBindPW()
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
		return ldapConf.GetTLSCAFile()
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
		return ldapConf.GetTLSClientCert()
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
		return ldapConf.GetTLSClientKey()
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
		return ldapConf.GetServerURIs()
	}

	return []string{"ldap://localhost"}
}

// GetLDAPSearchProtocol retrieves the LDAPSearchProtocol configuration based on the specified protocol.
// If the protocol is not found, it falls back to the default protocol.
// Returns an error if the configuration or default protocol is missing.
// Returns nil if no matching protocol is found and there's no error.
func (f *FileSettings) GetLDAPSearchProtocol(protocol string, poolName string) (*LDAPSearchProtocol, error) {
	if f == nil {
		return nil, errors.ErrLDAPConfig.WithDetail("Missing search::protocol section and no default")
	}

	getProtocols := f.GetProtocols(definitions.BackendLDAP)
	if getProtocols == nil {
		return nil, errors.ErrLDAPConfig.WithDetail("Missing search::protocol section and no default")
	}

	ldapProtocols, ok := getProtocols.([]LDAPSearchProtocol)
	if !ok {
		return nil, errors.ErrLDAPConfig.WithDetail("Invalid protocol configuration type")
	}

	for index := range ldapProtocols {
		if ldapProtocols[index].GetPoolName() != poolName {
			continue
		}

		protocols := ldapProtocols[index].GetProtocols()
		for protoIndex := range protocols {
			if protocols[protoIndex] == protocol {
				return &ldapProtocols[index], nil
			}
		}
	}

	return nil, nil
}

// GetLDAPOptionalPools retrieves a map of optional LDAP pool configurations from the file settings.
// Returns an empty map if the file settings or LDAP section is not properly configured.
func (f *FileSettings) GetLDAPOptionalPools() map[string]*LDAPConf {
	if f == nil {
		return map[string]*LDAPConf{}
	}

	if f.GetLDAP() == nil {
		return map[string]*LDAPConf{}
	}

	pools := f.GetLDAP().GetOptionalLDAPPools()
	if pools == nil {
		return map[string]*LDAPConf{}
	}

	return pools
}

/*
 * Lua config
 */

// GetLuaNumberOfWorkers retrieves the number of workers configured for the Lua backend or returns the default if unset.
func (f *FileSettings) GetLuaNumberOfWorkers() int {
	if f == nil {
		return definitions.DefaultNumberOfWorkers
	}

	getConfig := f.GetConfig(definitions.BackendLua)
	if getConfig == nil {
		return definitions.DefaultNumberOfWorkers
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		return luaConf.GetNumberOfWorkers()
	}

	return definitions.DefaultNumberOfWorkers
}

// GetLuaActionNumberOfWorkers retrieves the number of workers configured for Lua actions or returns default (10) if unset.
func (f *FileSettings) GetLuaActionNumberOfWorkers() int {
	if f == nil {
		return definitions.MaxActionWorkers
	}

	getConfig := f.GetConfig(definitions.BackendLua)
	if getConfig == nil {
		return definitions.MaxActionWorkers
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		return luaConf.GetActionNumberOfWorkers()
	}

	return definitions.MaxActionWorkers
}

// GetLuaFeatureVMPoolSize returns the VM pool size for Lua features.
func (f *FileSettings) GetLuaFeatureVMPoolSize() int {
	if f == nil {
		return definitions.DefaultNumberOfWorkers
	}

	getConfig := f.GetConfig(definitions.BackendLua)
	if getConfig == nil {
		return definitions.DefaultNumberOfWorkers
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		return luaConf.GetFeatureVMPoolSize()
	}

	return definitions.DefaultNumberOfWorkers
}

// GetLuaFilterVMPoolSize returns the VM pool size for Lua filters.
func (f *FileSettings) GetLuaFilterVMPoolSize() int {
	if f == nil {
		return definitions.DefaultNumberOfWorkers
	}

	getConfig := f.GetConfig(definitions.BackendLua)
	if getConfig == nil {
		return definitions.DefaultNumberOfWorkers
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		return luaConf.GetFilterVMPoolSize()
	}

	return definitions.DefaultNumberOfWorkers
}

// GetLuaHookVMPoolSize returns the VM pool size for Lua hooks.
func (f *FileSettings) GetLuaHookVMPoolSize() int {
	if f == nil {
		return definitions.DefaultNumberOfWorkers
	}

	getConfig := f.GetConfig(definitions.BackendLua)
	if getConfig == nil {
		return definitions.DefaultNumberOfWorkers
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		return luaConf.GetHookVMPoolSize()
	}
	return definitions.DefaultNumberOfWorkers
}

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
		if luaConf == nil {
			return ""
		}

		return luaConf.GetBackendScriptPath()
	}

	return ""
}

// GetLuaInitScriptPath returns the path to the Lua init script specified in the configuration.
// If the configuration or LuaConf is nil, it returns an empty string.
// If InitScriptPaths is set, it returns the first path from that list.
// Otherwise, it returns the value of InitScriptPath.
func (f *FileSettings) GetLuaInitScriptPath() string {
	if f == nil {
		return ""
	}

	getConfig := f.GetConfig(definitions.BackendLua)
	if getConfig == nil {
		return ""
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		if luaConf == nil {
			return ""
		}

		initScriptPaths := luaConf.GetInitScriptPaths()
		if len(initScriptPaths) > 0 {
			return initScriptPaths[0]
		}

		return luaConf.GetInitScriptPath()
	}

	return ""
}

// GetLuaInitScriptPaths returns all paths to Lua init scripts specified in the configuration.
// It combines both the single InitScriptPath and the list in InitScriptPaths.
// If the configuration or LuaConf is nil, it returns an empty slice.
func (f *FileSettings) GetLuaInitScriptPaths() []string {
	if f == nil {
		return nil
	}

	getConfig := f.GetConfig(definitions.BackendLua)
	if getConfig == nil {
		return nil
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		if luaConf == nil {
			return nil
		}

		var paths []string

		// Add the single init script path if it's set
		initScriptPath := luaConf.GetInitScriptPath()
		if initScriptPath != "" {
			paths = append(paths, initScriptPath)
		}

		// Add all paths from the list
		initScriptPaths := luaConf.GetInitScriptPaths()
		if len(initScriptPaths) > 0 {
			paths = append(paths, initScriptPaths...)
		}

		return paths
	}

	return nil
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
		if luaConf == nil {
			return definitions.LuaPackagePath
		}

		packagePath := luaConf.GetPackagePath()
		if packagePath == "" {
			return definitions.LuaPackagePath
		}

		return packagePath
	}

	return definitions.LuaPackagePath
}

// GetLuaSearchProtocol retrieves a LuaSearchProtocol configuration matching the specified protocol.
// Returns a default LuaSearchProtocol if the protocol cannot be found and protocol is set to ProtoDefault.
// Returns a DetailedError if the protocol cannot be found and no default is configured.
// Returns nil if no matching protocol is found and there's no error.
// Accepts a string representing the protocol to search for.
func (f *FileSettings) GetLuaSearchProtocol(protocol string, backendName string) (*LuaSearchProtocol, error) {
	if f == nil {
		return nil, errors.ErrLuaConfig.WithDetail("Missing search::protocol section and no default")
	}

	getProtocols := f.GetProtocols(definitions.BackendLua)
	if getProtocols == nil {
		return nil, errors.ErrLuaConfig.WithDetail("Missing search::protocol section and no default")
	}

	luaProtocols, ok := getProtocols.([]LuaSearchProtocol)
	if !ok {
		return nil, errors.ErrLuaConfig.WithDetail("Invalid protocol configuration type")
	}

	for index := range luaProtocols {
		if luaProtocols[index].GetBackendName() != backendName {
			continue
		}

		protocols := luaProtocols[index].GetProtocols()
		for protoIndex := range protocols {
			if protocols[protoIndex] == protocol {
				return &luaProtocols[index], nil
			}
		}
	}

	return nil, nil
}

// GetLuaOptionalBackends retrieves the optional Lua backends configuration from FileSettings. Returns an empty map if unavailable.
func (f *FileSettings) GetLuaOptionalBackends() map[string]*LuaConf {
	if f == nil {
		return map[string]*LuaConf{}
	}

	if f.GetLua() == nil {
		return map[string]*LuaConf{}
	}

	backends := f.GetLua().GetOptionalLuaBackends()
	if backends == nil {
		return map[string]*LuaConf{}
	}

	return backends
}

// HaveLuaFilters is a method on the FileSettings struct.
// It checks if the FileSettings struct has Lua filters.
// It returns true if there are Lua filters, and false otherwise.
func (f *FileSettings) HaveLuaFilters() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		return len(f.GetLua().GetFilters()) > 0
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
		return len(f.GetLua().GetFeatures()) > 0
	}

	return false
}

// HaveLuaHooks returns true if the FileSettings instance has Lua hooks associated with it, otherwise returns false.
func (f *FileSettings) HaveLuaHooks() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		return len(f.GetLua().GetHooks()) > 0
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
		return len(f.GetLua().GetActions()) > 0
	}

	return false
}

// HaveLuaInit checks if any Lua initialization script paths are set in the configuration.
// It first confirms that the FileSettings instance supports Lua by invoking HaveLua method.
// Then, it retrieves the Lua configuration using GetConfig with the definitions.BackendLua constant.
// If the retrieved configuration is of type *LuaConf and either InitScriptPath is not empty
// or InitScriptPaths contains at least one entry, it returns true.
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

		luaConf, ok := getConfig.(*LuaConf)
		if !ok || luaConf == nil {
			return false
		}

		return luaConf.GetInitScriptPath() != "" || len(luaConf.GetInitScriptPaths()) > 0
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

// HaveLuaBackend checks if the FileSettings instance has a Lua backend configured and returns true if found, otherwise false.
func (f *FileSettings) HaveLuaBackend() bool {
	if f == nil {
		return false
	}

	if f.Server == nil {
		return false
	}

	for _, backendType := range f.GetServer().GetBackends() {
		if backendType.Get() == definitions.BackendLua {
			return true
		}
	}

	return false
}

// HaveLDAPBackend checks if the configuration includes an LDAP backend and returns true if it exists, otherwise false.
func (f *FileSettings) HaveLDAPBackend() bool {
	if f == nil {
		return false
	}

	if f.Server == nil {
		return false
	}

	for _, backendType := range f.GetServer().GetBackends() {
		if backendType.Get() == definitions.BackendLDAP {
			return true
		}
	}

	return false
}

/*
 * Dynamic server configuration
 */

// GetServer retrieves the ServerSection from the FileSettings. Returns an empty ServerSection if the FileSettings is nil or if no Server is present.
func (f *FileSettings) GetServer() *ServerSection {
	if f == nil {
		return &ServerSection{}
	}

	if f.Server == nil {
		return &ServerSection{}
	}

	return f.Server
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
// If the provided FileSettings object is nil, it returns an empty map.
func (f *FileSettings) RetrieveGetterMap() map[definitions.Backend]GetterHandler {
	if f == nil {
		return map[definitions.Backend]GetterHandler{}
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
		return f.GetLDAP()
	case definitions.BackendLua:
		return f.GetLua()
	default:
		return nil
	}
}

// GetBruteForceRules retrieves the list of brute force rules defined in the configuration file.
// If no rules are defined or the FileSettings instance is nil, it returns an empty slice.
func (f *FileSettings) GetBruteForceRules() []BruteForceRule {
	if f == nil {
		return []BruteForceRule{}
	}

	bruteForce := f.GetBruteForce()
	if bruteForce != nil {
		buckets := bruteForce.GetBuckets()
		if len(buckets) > 0 {
			return buckets
		}
	}

	return []BruteForceRule{}
}

// GetAllProtocols returns a unique slice of strings (a Set) for all defined protocols in the database search sections.
// Returns an empty slice if the FileSettings is nil.
func (f *FileSettings) GetAllProtocols() []string {
	if f == nil {
		return []string{}
	}

	protocols := NewStringSet()

	if ldapProtocols := f.GetProtocols(definitions.BackendLDAP); ldapProtocols != nil {
		for index := range ldapProtocols.([]LDAPSearchProtocol) {
			protoList := ldapProtocols.([]LDAPSearchProtocol)[index].GetProtocols()
			for protoIndex := range protoList {
				protocols.Set(protoList[protoIndex])
			}
		}
	}

	if luaProtocols := f.GetProtocols(definitions.BackendLua); luaProtocols != nil {
		for index := range luaProtocols.([]LuaSearchProtocol) {
			protoList := luaProtocols.([]LuaSearchProtocol)[index].GetProtocols()
			for protoIndex := range protoList {
				protocols.Set(protoList[protoIndex])
			}
		}
	}

	return protocols.GetStringSlice()
}

// getOAuth2ClientIndex returns the index and found status of an OAuth-2 client with the given client ID in the LoadableConfig.Oauth2.Clients slice. If the client is found, the index
func (f *FileSettings) getOAuth2ClientIndex(clientId string) (index int, found bool) {
	oauth2 := f.GetOauth2()
	if oauth2 != nil {
		clients := oauth2.GetClients()
		for index = range clients {
			if clients[index].GetClientId() != clientId {
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
		clients := f.GetOauth2().GetClients()

		return clients[index].IsSkipTOTP()
	}

	return
}

// GetSkipConsent returns a boolean true, if the consent dialog shall be skipped for an OAuth-2 client.
func (f *FileSettings) GetSkipConsent(clientId string) (skip bool) {
	if index, found := f.getOAuth2ClientIndex(clientId); found {
		clients := f.GetOauth2().GetClients()

		return clients[index].IsSkipConsent()
	}

	return
}

// GetUsername returns the HTTP request header for the username
func (f *FileSettings) GetUsername() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetUsername()
}

// GetPassword returns the HTTP request header for the password
func (f *FileSettings) GetPassword() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetPassword()
}

// GetPasswordEncoded returns the HTTP request header to indicate if the password was encoded
func (f *FileSettings) GetPasswordEncoded() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetPasswordEncoded()
}

// GetProtocol returns the HTTP request header for the used protocol
func (f *FileSettings) GetProtocol() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetProtocol()
}

// GetLoginAttempt returns the HTTP request header for login-attempts
func (f *FileSettings) GetLoginAttempt() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetLoginAttempt()
}

// GetAuthMethod returns the HTTP request header for the auth mechanism LOGIN or PLAIN
func (f *FileSettings) GetAuthMethod() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetAuthMethod()
}

// GetLocalIP returns the HTTP request header that represents the local IP address for the server that accepts client requests
func (f *FileSettings) GetLocalIP() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetLocalIP()
}

// GetLocalPort returns the HTTP request header that represents the local TCP port for the server that accepts client requests
func (f *FileSettings) GetLocalPort() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetLocalPort()
}

// GetOIDCCID retrieves the OIDC Client ID from the FileSettings' DefaultHTTPRequestHeader. Returns an empty string if nil.
func (f *FileSettings) GetOIDCCID() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetOIDCCID()
}

// GetClientIP returns the HTTP request header that holds the client IP of the request
func (f *FileSettings) GetClientIP() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetClientIP()
}

// GetClientPort returns the HTTP request header that holds the client TCP port of the request
func (f *FileSettings) GetClientPort() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetClientPort()
}

// GetClientHost returns the HTTP request header used to retrieve an optional client hostname
func (f *FileSettings) GetClientHost() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetClientHost()
}

// GetClientID returns the HTTP request header used to retrieve an optional client ID
func (f *FileSettings) GetClientID() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetClientID()
}

// GetSSL returns the HTTP request header used to indicate SSL security for the current client connection
func (f *FileSettings) GetSSL() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSL()
}

// GetSSLSessionID retrieves the SSL session ID from the file's default HTTP request header. Returns an empty string
// if the file is nil.
func (f *FileSettings) GetSSLSessionID() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLSessionID()
}

// GetSSLVerify retrieves the SSL verification status from the default HTTP request header configuration.
// If the FileSettings receiver is nil, it returns an empty string.
func (f *FileSettings) GetSSLVerify() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLVerify()
}

// GetSSLSubject retrieves the SSL subject from the default HTTP request header. Returns an empty string if the file is nil.
func (f *FileSettings) GetSSLSubject() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLSubject()
}

// GetSSLClientCN retrieves the SSL client common name (CN) from the default HTTP request header.
func (f *FileSettings) GetSSLClientCN() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLClientCN()
}

// GetSSLIssuer retrieves the SSL certificate issuer from the default HTTP request header of the server configuration.
func (f *FileSettings) GetSSLIssuer() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLIssuer()
}

// GetSSLClientNotBefore retrieves the "SSLClientNotBefore" value from the default HTTP request header of the server.
// Returns an empty string if the FileSettings instance is nil.
func (f *FileSettings) GetSSLClientNotBefore() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLClientNotBefore()
}

// GetSSLClientNotAfter retrieves the SSL client certificate's "not after" expiration date as a string. Returns an empty
// string if the FileSettings is nil.
func (f *FileSettings) GetSSLClientNotAfter() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLClientNotAfter()
}

// GetSSLSubjectDN returns the SSL subject distinguished name from the Server's default HTTP request header.
func (f *FileSettings) GetSSLSubjectDN() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLSubjectDN()
}

// GetSSLIssuerDN retrieves the Distinguished Name (DN) of the SSL issuer from the default HTTP request header.
func (f *FileSettings) GetSSLIssuerDN() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLIssuerDN()
}

// GetSSLClientSubjectDN returns the SSL client subject distinguished name from the default HTTP request header.
// If the FileSettings receiver is nil, it returns an empty string.
func (f *FileSettings) GetSSLClientSubjectDN() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLClientSubjectDN()
}

// GetSSLClientIssuerDN returns the distinguished name (DN) of the SSL client issuer from the default HTTP request header.
func (f *FileSettings) GetSSLClientIssuerDN() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLClientIssuerDN()
}

// GetSSLCipher retrieves the SSL cipher from the default HTTP request header of the server configuration.
// Returns an empty string if the FileSettings instance is nil.
func (f *FileSettings) GetSSLCipher() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLCipher()
}

// GetSSLProtocol retrieves the SSL protocol from the DefaultHTTPRequestHeader of the Server configuration.
func (f *FileSettings) GetSSLProtocol() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLProtocol()
}

// GetSSLSerial retrieves the SSL serial number from the default HTTP request header of the server configuration.
// Returns an empty string if the FileSettings receiver is nil.
func (f *FileSettings) GetSSLSerial() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLSerial()
}

// GetSSLFingerprint retrieves the SSL fingerprint from the server's default HTTP request header.
// If the FileSettings is nil, it returns an empty string.
func (f *FileSettings) GetSSLFingerprint() string {
	if f == nil {
		return ""
	}

	return f.GetServer().GetDefaultHTTPRequestHeader().GetSSLFingerprint()
}

// validateBruteForce validates the brute force configuration rules in the FileSettings object.
// Returns an error if any rule is invalid or violates constraints; otherwise, returns nil.
func (f *FileSettings) validateBruteForce() error {
	bruteForce := f.GetBruteForce()
	if bruteForce != nil {
		for _, rule := range bruteForce.GetBuckets() {
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
func (f *FileSettings) LDAPHavePoolOnly(backendName string) bool {
	if f == nil || f.LDAP == nil {
		return false
	}

	if backendName == definitions.DefaultBackendName {
		ldapConfig := f.GetLDAP().GetConfig()
		if ldapConfig == nil {
			return false
		}

		return ldapConfig.(*LDAPConf).IsPoolOnly()
	}

	if f.GetLDAP().GetOptionalLDAPPools() == nil {
		return false
	}

	for poolKey, poolSettings := range f.GetLDAP().GetOptionalLDAPPools() {
		if poolKey == backendName {
			if poolSettings == nil {
				return false
			}

			return poolSettings.IsPoolOnly()
		}
	}

	return false
}

// validatePassDBBackends validates the configuration of password database backends defined in the server's configuration.
// It ensures required sections, such as 'ldap', are properly configured and assigns default values where applicable.
// If any backend has invalid or incomplete settings, it returns an appropriate error.
func (f *FileSettings) validatePassDBBackends() error {
	if f == nil || f.Server == nil {
		return nil
	}

	for _, backend := range f.Server.Backends {
		switch backend.Get() {
		case definitions.BackendLDAP:
			if f.GetLDAP() == nil {
				return errors.ErrNoLDAPSection
			}

			if !f.GetLDAP().GetConfig().(*LDAPConf).IsPoolOnly() && len(f.GetLDAP().GetSearch()) == 0 {
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
	if f.GetOauth2() != nil {
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
	if f == nil || f.Server == nil {
		return nil
	}

	if f.GetServer().GetListenAddress() == "" {
		f.Server.Address = definitions.HTTPAddress
	}

	return checkAddress(f.Server.Address)
}

// setDefaultHydraAdminUrl sets the Hydra admin URL to a default value if it is not already configured.
func (f *FileSettings) setDefaultHydraAdminUrl() error {
	if f == nil || f.Server == nil {
		return nil
	}

	if f.GetServer().HydraAdminUrl == "" {
		f.Server.HydraAdminUrl = "http://127.0.0.1:4445"
	}

	return nil
}

// setDefaultInstanceName ensures the Server.InstanceName field is set to a default value if it is currently empty.
func (f *FileSettings) setDefaultInstanceName() error {
	if f == nil || f.Server == nil {
		return nil
	}

	if f.GetServer().GetInstanceName() == "" {
		f.Server.InstanceName = definitions.InstanceName
	}

	return nil
}

// setDefaultDnsTimeout sets the default DNS timeout value for the file's server if not already specified.
func (f *FileSettings) setDefaultDnsTimeout() error {
	if f == nil || f.Server == nil || f.Server.DNS == (DNS{}) {
		return nil
	}

	if f.GetServer().GetDNS().GetTimeout() == 0 {
		f.Server.DNS.Timeout = definitions.DNSResolveTimeout
	}

	return nil
}

// setDefaultPosCacheTTL sets a default Positive Cache TTL for Redis if it is not already configured.
func (f *FileSettings) setDefaultPosCacheTTL() error {
	if f == nil || f.Server == nil {
		return nil
	}

	redis := f.GetServer().GetRedis()

	if redis.GetPosCacheTTL() <= 0 {
		f.Server.Redis.PosCacheTTL = definitions.RedisPosCacheTTL * time.Second
	}

	if redis.GetPosCacheTTL() < time.Second {
		f.Server.Redis.PosCacheTTL = f.Server.Redis.PosCacheTTL * time.Second

		if redis.GetPosCacheTTL() > definitions.DurationMaxPeriod {
			return fmt.Errorf("%w: %s", errors.ErrDurationTooHigh, redis.GetPosCacheTTL().String())
		}
	}

	return nil
}

// setDefaultNegCacheTTL sets the default TTL for negative cache entries in Redis if it is not already configured.
func (f *FileSettings) setDefaultNegCacheTTL() error {
	if f == nil || f.Server == nil {
		return nil
	}

	redis := f.GetServer().GetRedis()

	if redis.GetNegCacheTTL() <= 0 {
		f.Server.Redis.NegCacheTTL = definitions.RedisNegCacheTTL * time.Second
	}

	if redis.GetNegCacheTTL() < time.Second {
		f.Server.Redis.NegCacheTTL = f.Server.Redis.NegCacheTTL * time.Second

		if redis.GetNegCacheTTL() > definitions.DurationMaxPeriod {
			return fmt.Errorf("%w: %s", errors.ErrDurationTooHigh, f.Server.Redis.NegCacheTTL.String())
		}
	}

	return nil
}

// setDefaultDelimiter sets the default delimiter for the master user if none has been defined and returns any error.
func (f *FileSettings) setDefaultDelimiter() error {
	if f == nil || f.Server == nil {
		return nil
	}

	masterUser := f.GetServer().GetMasterUser()

	if masterUser.GetDelimiter() == "" {
		f.Server.MasterUser.Delimiter = "*"
	}

	return nil
}

// setDefaultHeaders ensures all default HTTP request headers are set. If any header is empty, it is replaced with its default value.
func (f *FileSettings) setDefaultHeaders() error {
	if f == nil || f.Server == nil {
		return nil
	}

	// Initialize DefaultHTTPRequestHeader if it's nil
	if f.Server.DefaultHTTPRequestHeader == (DefaultHTTPRequestHeader{}) {
		f.Server.DefaultHTTPRequestHeader = DefaultHTTPRequestHeader{}
	}

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
		"X-OIDC-CID":              &f.Server.DefaultHTTPRequestHeader.OIDCCID,

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
	if f == nil || f.Server == nil {
		return nil
	}

	if f.GetServer().GetMaxConcurrentRequests() == 0 {
		f.Server.MaxConcurrentRequests = definitions.MaxConcurrentRequests
	}

	return nil
}

// setDefaultPasswordHistory sets MaxPasswordHistoryEntries to a default value if non-positive and returns an error if any.
func (f *FileSettings) setDefaultPasswordHistory() error {
	if f == nil || f.Server == nil {
		return nil
	}

	if f.GetServer().GetMaxPasswordHistoryEntries() <= 0 {
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

// warnDeprecatedConfig logs deprecation warnings for all known deprecated config fields.
func (f *FileSettings) warnDeprecatedConfig() {
	if f == nil {
		return
	}

	// LDAP: pool_only (deprecated) → lookup_pool_only
	if f.LDAP != nil {
		if cfg, _ := f.LDAP.GetConfig().(*LDAPConf); cfg != nil {
			warnDeprecatedLDAP("default", cfg)
		}

		for name, cfg := range f.LDAP.GetOptionalLDAPPools() {
			if cfg != nil {
				warnDeprecatedLDAP(name, cfg)
			}
		}
	}

	// Server-level deprecations
	srv := f.GetServer()
	if srv != nil {
		// TLS on server
		warnDeprecatedTLS("server.tls", &srv.TLS)
		// HTTP client TLS
		warnDeprecatedTLS("server.http_client.tls", &srv.HTTPClient.TLS)
		// Compression
		warnDeprecatedCompression("server.compression", &srv.Compression)
		// Redis Cluster
		warnDeprecatedRedisCluster("server.redis.cluster", &srv.Redis.Cluster)
		// Redis standalone replica
		warnDeprecatedRedisReplica("server.redis.replica", &srv.Redis.Replica)
		// Redis TLS
		warnDeprecatedTLS("server.redis.tls", &srv.Redis.TLS)
	}

	// RBL deprecations
	if rbl := f.GetRBLs(); rbl != nil {
		for i := range rbl.Lists {
			warnDeprecatedRBL(i, &rbl.Lists[i])
		}
	}
}

// safeWarn logs a warning using go-kit logger when available; otherwise falls back to slog.
func safeWarn(keyvals ...any) {
	var msg string

	args := make([]any, 0, len(keyvals))
	for i := 0; i+1 < len(keyvals); i += 2 {
		k, ok := keyvals[i].(string)
		if !ok {
			continue
		}

		if strings.EqualFold(k, "msg") {
			if s, ok := keyvals[i+1].(string); ok {
				msg = s

				continue
			}
		}

		args = append(args, slog.Any(k, keyvals[i+1]))
	}

	if msg == "" {
		msg = "deprecated configuration"
	}

	slog.Warn(msg, args...)
}

// warnDeprecatedLDAP logs a warning if the 'pool_only' field in the LDAP configuration is used, as it is deprecated.
func warnDeprecatedLDAP(backend string, cfg *LDAPConf) {
	if cfg == nil {
		return
	}

	if cfg.PoolOnly {
		safeWarn(
			"component", "config",
			"backend", backend,
			"deprecated", "ldap.config.pool_only",
			"msg", "'pool_only' is deprecated – please migrate to 'lookup_pool_only'",
		)
	}
}

// warnDeprecatedTLS checks if the deprecated field `http_client_skip_verify` is used in the provided TLS config and logs a warning.
func warnDeprecatedTLS(where string, t *TLS) {
	if t == nil {
		return
	}

	if t.HTTPClientSkipVerify {
		safeWarn(
			"component", "config",
			"location", where,
			"deprecated", "tls.http_client_skip_verify",
			"msg", "'http_client_skip_verify' is deprecated – please use 'skip_verify'",
		)
	}
}

// warnDeprecatedCompression logs warnings for deprecated compression fields in the provided compression configuration.
// It checks if compression.level and compression.content_types are used and issues warnings advising updates.
// Parameter where specifies the configuration context location, and c is the Compression object to evaluate.
func warnDeprecatedCompression(where string, c *Compression) {
	if c == nil {
		return
	}

	if c.Level > 0 {
		safeWarn(
			"component", "config",
			"location", where,
			"deprecated", "compression.level",
			"msg", "'level' is deprecated – please use 'level_gzip'",
		)
	}

	if len(c.ContentTypes) > 0 {
		safeWarn(
			"component", "config",
			"location", where,
			"deprecated", "compression.content_types",
			"msg", "'content_types' is deprecated and has no effect",
		)
	}
}

// warnDeprecatedRedisCluster logs a warning if the Redis Cluster `read_only` field is used, as it is deprecated.
func warnDeprecatedRedisCluster(where string, c *Cluster) {
	if c == nil {
		return
	}

	if c.ReadOnly {
		safeWarn(
			"component", "config",
			"location", where,
			"deprecated", "redis.cluster.read_only",
			"msg", "'read_only' is deprecated – please use 'route_reads_to_replicas'",
		)
	}
}

// warnDeprecatedRedisReplica logs a deprecation warning if the "address" field is used instead of "addresses" in Redis replica configuration.
func warnDeprecatedRedisReplica(where string, r *Replica) {
	if r == nil {
		return
	}

	if r.Address != "" {
		safeWarn(
			"component", "config",
			"location", where,
			"deprecated", "redis.replica.address",
			"msg", "'address' is deprecated – please use 'addresses'",
		)
	}
}

// warnDeprecatedRBL logs a deprecation warning if the RBL's "return_code" field is used instead of "return_codes".
func warnDeprecatedRBL(index int, r *RBL) {
	if r == nil {
		return
	}

	if r.ReturnCode != "" {
		safeWarn(
			"component", "config",
			"list_index", index,
			"deprecated", "rbl.lists[].return_code",
			"msg", "'return_code' is deprecated – please use 'return_codes'",
		)
	}
}

// HasFeature checks if the given feature exists in the LoadableConfig's Features list
func (f *FileSettings) HasFeature(feature string) bool {
	if f == nil || f.Server == nil || f.Server.Features == nil {
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

	validate := validator.New(validator.WithRequiredStructEnabled())

	validate.RegisterValidation("validateCookieStoreEncKey", validateCookieStoreEncKey)
	validate.RegisterValidation("validateOptionalLuaBackend", validateOptionalLuaBackend)
	validate.RegisterValidation("validateAuthPoolRequired", validateAuthPoolRequired)
	validate.RegisterValidation("validatDefaultBackendName", validatDefaultBackendName)
	// Register custom validator for alphanumeric characters and symbols
	validate.RegisterValidation("alphanumsymbol", isAlphanumSymbol)

	if err = validate.Struct(f); err != nil {
		if stderrors.As(err, &validationErrors) {
			return prettyFormatValidationErrors(validationErrors)
		}

		return err
	}

	if err = f.validate(); err != nil {
		return err
	}

	// Emit deprecation warnings once after successful load/validation
	f.warnDeprecatedConfig()

	// Throw away unsupported keys
	f.Other = nil

	return nil
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

	if ConfigFilePath == "" {
		viper.SetConfigName("nauthilus") // name of environment file (without extension)
		// Note: Config type is now set via command line flag in server.go
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.nauthilus")
		viper.AddConfigPath("/etc/nauthilus/")
		viper.AddConfigPath("/usr/local/etc/nauthilus/")
	}

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
