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
	"net"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/go-kit/log/level"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

// The configuration file is briefly documented in the markdown file Configuration-File.md.

// LoadableConfig is a variable of type *File that represents the configuration file that can be loaded.
var LoadableConfig *File //nolint:gochecknoglobals // System wide configuration from nauthilus.yml file

// GetterHandler is an interface that defines two methods: GetConfig and GetSearch.
// Any type that implements this interface must provide implementations for both methods.
// The GetConfig method takes a *File parameter and returns a value of any type.
// The GetSearch method also takes a *File parameter and returns a value of any type.
type GetterHandler interface {
	GetConfig() any
	GetProtocols() any
}

type File struct {
	Server                  *ServerSection           `mapstructure:"server"`
	RBLs                    *RBLSection              `mapstructure:"realtime_blackhole_lists"`
	ClearTextList           []string                 `mapstructure:"cleartext_networks"`
	RelayDomains            *RelayDomainsSection     `mapstructure:"relay_domains"`
	BackendServerMonitoring *BackendServerMonitoring `mapstructure:"backend_server_monitoring"`
	BruteForce              *BruteForceSection       `mapstructure:"brute_force"`
	Lua                     *LuaSection
	Oauth2                  *Oauth2Section
	LDAP                    *LDAPSection
	Other                   map[string]any `mapstructure:",remain"`
	Mu                      sync.Mutex
}

/*
 * Backend server monitoring
 */

// GetBackendServerMonitoring is a method on the File struct.
// It returns the BackendServerMonitoring field from the File struct.
func (f *File) GetBackendServerMonitoring() *BackendServerMonitoring {
	if f == nil {
		return nil
	}

	if f.BackendServerMonitoring == nil {
		return nil
	}

	return f.BackendServerMonitoring
}

// GetBackendServers method operates on a File receiver 'f'.
// It checks if the BackendServerMonitoring property is not null, it returns a pointer to an array of BackendServers,
// otherwise, it returns an empty array of BackendServer pointers.
// This method could be used when trying to get all backend servers of a configuration file.
func (f *File) GetBackendServers() []*BackendServer {
	if f == nil {
		return []*BackendServer{}
	}

	if f.GetBackendServerMonitoring() != nil {
		return f.BackendServerMonitoring.BackendServers
	}

	return []*BackendServer{}
}

// GetBackendServer is a method of the File struct.
// It takes a protocol as an argument and returns a BackendServer.
// The method iterates over the Backend Servers of the File instance and returns the first server that matches the provided protocol.
// If no such server is found, an emtpy instance of BackendServer is returned.
func (f *File) GetBackendServer(protocol string) *BackendServer {
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

// GetBackendServerIP is a method for the File struct which
// attempts to get the IP address of a backend server
// for a specified protocol. The method first calls
// GetBackendServer with the given protocol and checks
// if it returns a non-nil value. If the value is not nil,
// it retrieves the IP attribute of the backend server.
// If the returned value is nil, indicating that there is
// no backend server for the given protocol, the method
// returns an empty string.
//
// Parameters:
//
//	protocol: A string that specifies the protocol for
//	          which the backend server's IP address
//	          is to be retrieved. This could be "http",
//	          "https", etc.
//
// Returns:
//
//	A string representing the IP address of the backend
//	server for the given protocol. If there is no backend
//	server for the specified protocol, the method returns
//	an empty string.
func (f *File) GetBackendServerIP(protocol string) string {
	if f == nil {
		return ""
	}

	if f.GetBackendServer(protocol) != nil {
		return f.GetBackendServer(protocol).IP
	}

	return ""
}

// GetBackendServerPort checks the specific protocol's backend server in the File structure.
// If the server exists, it returns the port of the server.
// If the server does not exist, it returns 0.
func (f *File) GetBackendServerPort(protocol string) int {
	if f == nil {
		return 0
	}

	if f.GetBackendServer(protocol) != nil {
		return f.GetBackendServer(protocol).Port
	}

	return 0
}

/*
 * LDAP Config
 */

// GetLDAPConfigStartTLS is a receiver function for the File struct that retrieves LDAP configuration.
// Specifically, it checks if the configuration recommends starting a TLS (Transport Layer Security) connection.
// The function returns a boolean value; true if the configuration recommends starting a TLS connection and false otherwise.
// It first gets the global LDAP configuration by calling the GetConfig function of the File receiver.
// If the configuration is nil, then the function immediately returns false.
// If the configuration is not nil, it tries to assert the configuration to be of type LDAPConf.
// If the assertion is successful (i.e., the configuration is of type LDAPConf), the StartTLS variable of the LDAPConf instance is returned.
// If the assertion is not successful, the function returns false.
func (f *File) GetLDAPConfigStartTLS() bool {
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

// GetLDAPConfigTLSSkipVerify is a method of the File struct. It attempts to retrieve the LDAP
// configuration and then checks whether TLSSkipVerify is enabled in the LDAP configuration.
//
// It follows the steps:
// 1. Get the LDAP specific configuration by calling GetConfig with 'definitions.BackendLDAP'.
// 2. If no configuration is found, it defaults to returning false.
// 3. If a configuration is found, it checks whether it can be asserted to a LDAPConf type.
// 4. If it is successfully asserted to a LDAPConf type, it returns the value of 'TLSSkipVerify'.
// 5. If the assertion to LDAPConf is unsuccessful, it defaults to returning false.
//
// Returns:
// The function returns a boolean indicating whether TLSSkipVerify is enabled (true) or not (false).
func (f *File) GetLDAPConfigTLSSkipVerify() bool {
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

// GetLDAPConfigSASLExternal checks if SASL External is enabled in the LDAP configuration.
// It attempts to fetch the global BackendLDAP configuration using the GetConfig method.
// If the configuration is found and can be asserted as *LDAPConf, it returns the value of the SASLExternal field.
// If the configuration is not found or can't be asserted as *LDAPConf, it returns false.
func (f *File) GetLDAPConfigSASLExternal() bool {
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

// GetLDAPConfigLookupIdlePoolSize retrieves the idle pool size
// for LDAP connections from the config file. If the returned configuration
// from the config file is nil or if it's not of type *LDAPConf,
// it will return the default global LDAP idle pool size.
func (f *File) GetLDAPConfigLookupIdlePoolSize() int {
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

// GetLDAPConfigAuthIdlePoolSize is a method that operates on a File struct.
// It retrieves the 'AuthIdlePoolSize' configuration from the LDAP
// configuration if it exists. If no such configuration is found
// or the type assertion for LDAPConf fails, it returns a default
// global LDAP idle pool size.
func (f *File) GetLDAPConfigAuthIdlePoolSize() int {
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

// GetLDAPConfigLookupPoolSize retrieves the number of connections
// that should be maintained in the LDAP lookup pool.
// If the LDAP configuration can be asserted successfully, it
// returns the LookupPoolSize from the retrieved LDAP configuration.
// If not, it returns the global constant LDAPIdlePoolSize.
func (f *File) GetLDAPConfigLookupPoolSize() int {
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

// GetLDAPConfigAuthPoolSize is a method of File struct.
// It returns the LDAP configuration authentication pool size.
// If the configuration for LDAP backend is nil or not assertable,
// it returns the default definitions.LDAPIdlePoolSize value. Otherwise,
// it returns the AuthPoolSize from the LDAP configuration.
func (f *File) GetLDAPConfigAuthPoolSize() int {
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

// GetLDAPConfigBindDN is a method on the File struct.
// It retrieves the BindDN field from the LDAP configuration in the File's configuration settings.
// It will return an empty string if either the config can't be retrieved (nil is returned), or in case
// the type assertion to an LDAPConf object fails.
func (f *File) GetLDAPConfigBindDN() string {
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

// GetLDAPConfigBindPW retrieves the binding password from the LDAP Configuration.
// This method belongs to the File struct and it operates as follows:
// It retrieves the LDAP configuration using the GetConfig method.
// If that configuration does not exist, it returns an empty string.
// If it exists, it attempts to assert this configuration as a pointer to LDAPConf.
// If this assertion is successful, it returns the BindPW of the LDAPConf.
// If the assertion fails, it also returns an empty string.
func (f *File) GetLDAPConfigBindPW() string {
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

// GetLDAPConfigTLSCAFile is a method on the File struct.
// It retrieves the TLS CA file path for the LDAP configuration.
// It first retrieves the LDAP configuration using the GetConfig method, passing in the definitions.BackendLDAP value.
// If the LDAP configuration is not found or is not of type *LDAPConf, it returns an empty string.
// Otherwise, it casts the retrieved configuration to *LDAPConf and returns the TLSCAFile field.
// If the TLSCAFile field is empty, it also returns an empty string.
// Example usage:
// filePath := file.GetLDAPConfigTLSCAFile()
func (f *File) GetLDAPConfigTLSCAFile() string {
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

// GetLDAPConfigTLSClientCert is a method on the File struct.
// It returns the TLS client certificate path from the LDAP configuration in the File struct.
// If the LDAP configuration is not found or the TLS client certificate is empty, it returns an empty string.
func (f *File) GetLDAPConfigTLSClientCert() string {
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

// GetLDAPConfigTLSClientKey is a method on the File struct.
// It tries to get the LDAP configuration from the file's current configuration.
// If the configuration is successfully retrieved and is of type LDAPConf,
// it returns the TLSClientKey from the LDAP configuration.
func (f *File) GetLDAPConfigTLSClientKey() string {
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

// GetLDAPConfigServerURIs is a method on the File struct.
// It returns an array of LDAP server URIs.
// It first gets the LDAP configuration using the GetConfig method from definitions.BackendLDAP.
// If no LDAP configuration is found, it returns an array with a default URI "ldap://localhost".
// If a valid LDAP configuration is found, it returns the ServerURIs field from the LDAPConf struct.
// If the configuration is not of type LDAPConf, it also returns an array with a default URI "ldap://localhost".
// Example usage:
//
//	file := &File{}
//	serverURIs := file.GetLDAPConfigServerURIs()
//	for _, uri := range serverURIs {
//	    fmt.Println(uri)
//	}
//
// Output:
//
//	ldap://localhost
//	ldap://example.com:389
func (f *File) GetLDAPConfigServerURIs() []string {
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

// GetLDAPSearchProtocol is a method for the File type.
// It accepts a string which represents the protocol.
// The function searches for this protocol in the LDAP protocol list.
// If it finds it, the method returns a pointer to LDAPSearchProtocol and no error.
// If it cannot find the protocol, it checks if the default protocol is in use. If not, it returns nil and an error.
// If the default protocol is used, this method calls itself recursively with the default protocol parameter.
func (f *File) GetLDAPSearchProtocol(protocol string) (*LDAPSearchProtocol, error) {
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

// GetLuaScriptPath is a method on the File struct.
// It returns the Lua script path from the LuaConf field in the File struct.
// It first calls the GetConfig method with the definitions.BackendLua parameter to obtain the Lua configuration.
// If the Lua configuration is nil, it returns an empty string.
// If the Lua configuration is not nil, it asserts the retrieved configuration as a *LuaConf type.
// If the assertion is successful, it returns the BackendScriptPath field from the Lua configuration.
// If the assertion fails, it returns an empty string.
func (f *File) GetLuaScriptPath() string {
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
func (f *File) GetLuaInitScriptPath() string {
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

// GetLuaPackagePath is a method on the File struct.
// It retrieves the Lua package path based on the configuration.
// If the Lua backend configuration is not found, it returns the global Lua package path.
// If the Lua backend configuration is found, it returns the package path from the LuaConf struct.
// If the LuaConf struct is not of type *LuaConf, it also returns the global Lua package path.
func (f *File) GetLuaPackagePath() string {
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

// GetLuaSearchProtocol is a method on the File struct.
// It takes a protocol string as input and returns a pointer to a LuaSearchProtocol struct and an error.
// This method searches for the specified protocol in the search::protocol sections of the Lua configuration.
// If the protocol is found, it returns the LuaSearchProtocol containing that protocol.
// If the protocol is not found and the input protocol is not the default protocol,
// it recursively calls itself with the default protocol as the input.
// If the protocol is not found and the input protocol is the default protocol,
// it returns nil and an error indicating that the search::protocol section is missing and there is no default.
func (f *File) GetLuaSearchProtocol(protocol string) (*LuaSearchProtocol, error) {
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

// HaveLuaFilters is a method on the File struct.
// It checks if the File struct has Lua filters.
// It returns true if there are Lua filters, and false otherwise.
func (f *File) HaveLuaFilters() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		return len(f.Lua.Filters) > 0
	}

	return false
}

// HaveLuaFeatures is a method on the File struct.
// It checks if the File struct has Lua features.
// It returns true if there are Lua features, and false otherwise.
func (f *File) HaveLuaFeatures() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		return len(f.Lua.Features) > 0
	}

	return false
}

// HaveLuaHooks returns true if the File instance has Lua hooks associated with it, otherwise returns false.
func (f *File) HaveLuaHooks() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		return len(f.Lua.Hooks) > 0
	}

	return false
}

// HaveLuaActions is a method on the File struct.
// It checks if the File struct has Lua actions.
// It returns true if the File struct has Lua actions, otherwise returns false.
func (f *File) HaveLuaActions() bool {
	if f == nil {
		return false
	}

	if f.HaveLua() {
		return len(f.Lua.Actions) > 0
	}

	return false
}

// HaveLuaInit checks if the Lua initialization script path is set in the configuration.
// It first confirms that the File instance supports Lua by invoking HaveLua method.
// Then, it retrieves the Lua configuration using GetConfig with the definitions.BackendLua constant.
// If the retrieved configuration is of type *LuaConf and the InitScriptPath is not empty, it returns true.
// Otherwise, it returns false.
func (f *File) HaveLuaInit() bool {
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

// HaveLua is a method on the File struct.
// It checks if the Lua field in the File struct is not nil.
// It returns a boolean value indicating whether Lua is present or not.
func (f *File) HaveLua() bool {
	if f == nil {
		return false
	}

	return f.Lua != nil
}

func (f *File) HaveLDAPBackend() bool {
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

// GetServerInsightsEnablePprof is a method on the File struct.
// It checks if the File struct has a server and returns the value of EnablePprof from the ServerInsights field of the File struct.
// If the File struct does not have a server, it returns false.
//
// Example usage:
//
//	if config.LoadableConfig.GetServerInsightsEnablePprof() {
//	    pprof.Register(router)
//	}
func (f *File) GetServerInsightsEnablePprof() bool {
	if f == nil {
		return false
	}

	if f.HaveServer() {
		return f.GetServerInsights().EnablePprof
	}

	return false
}

// GetServerInsightsEnableBlockProfile is a method on the File struct.
// It returns the value of the EnableBlockProfile field from the ServerInsights field of the File struct.
// If the HaveServer method returns false, it will return false.
//
// Example usage:
//
//	func enableBlockProfile() {
//	    if config.LoadableConfig.GetServerInsightsEnableBlockProfile() {
//	        runtime.SetBlockProfileRate(1)
//	    } else {
//	        runtime.SetBlockProfileRate(-1)
//	    }
//	}
func (f *File) GetServerInsightsEnableBlockProfile() bool {
	if f == nil {
		return false
	}

	if f.HaveServer() {
		return f.GetServerInsights().EnableBlockProfile
	}

	return false
}

// GetServerInsights is a method on the File struct.
// It returns the Insights field from the Server struct, which is accessed through the GetServer() method on the File struct.
// If the File struct does not have a Server, it returns nil.
func (f *File) GetServerInsights() *Insights {
	if f == nil {
		return nil
	}

	if f.HaveServer() {
		return &f.GetServer().Insights
	}

	return nil
}

// GetServer is a method on the File struct.
// It checks if the File struct has a ServerSection.
// If it does, it returns the ServerSection.
// Otherwise, it returns nil.
// Example usage:
//
//	server := file.GetServer()
//	if server != nil {
//	    // do something with server
//	}
func (f *File) GetServer() *ServerSection {
	if f == nil {
		return nil
	}

	if f.HaveServer() {
		return f.Server
	}

	return nil
}

// HaveServer is a method on the File struct.
// It returns true if the Server field in the File struct is not nil, indicating that a server exists.
func (f *File) HaveServer() bool {
	if f == nil {
		return false
	}

	return f.Server != nil
}

/*
 * Generic EnvConfig mapping
 */

// RetrieveGetterMap returns a map of GetterHandler interfaces for each supported backend.
// It creates a getterMap with a length of 3.
// If an LDAPSection is found for the LDAP backend, it adds it to the getterMap.
// If an SQLSection is found for the SQL backend, it adds it to the getterMap.
// If a LuaSection is found for the Lua backend, it adds it to the getterMap.
// Finally, it returns the getterMap.
func (f *File) RetrieveGetterMap() map[definitions.Backend]GetterHandler {
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

// GetConfig returns the configuration handler for the specified backend.
// The configuration handler is determined based on the backend type.
// If the backend is found, it retrieves the configuration handler associated with it
// and returns the result of calling the GetterHandler() method on the configuration handler.
// If the configuration handler is not found, it returns nil.
func (f *File) GetConfig(backend definitions.Backend) any {
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

// GetProtocols returns the protocol handler for the specified backend.
// The protocol handler is determined based on the backend type.
// If the backend is found, it retrieves the protocol handler associated with it
// and returns the result of calling the ProtoHandler() method on the protocol handler.
// If the protocol handler is not found, it returns nil.
func (f *File) GetProtocols(backend definitions.Backend) any {
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

// GetSection is a method on the File struct.
// It takes a backend of type definitions.Backend as parameter and returns the corresponding section.
// The method checks the value of the backend parameter and returns the appropriate section.
// If the backend is definitions.BackendLDAP, it returns f.LDAP.
// If the backend is global.BackendMySQL, global.BackendPostgres, or global.BackendSQL, it returns f.SQL.
// If the backend is definitions.BackendLua, it returns f.Lua.
// For any other value of the backend parameter, it returns nil.
func (f *File) GetSection(backend definitions.Backend) any {
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

// GetBruteForceRules is a method on the File struct.
// It retrieves the brute force rules from the LoadableConfig.BruteForce.Buckets field.
//
// The method checks if LoadableConfig.BruteForce is not nil and
// if LoadableConfig.BruteForce.Buckets is not empty.
// If both conditions are met, it assigns LoadableConfig.BruteForce.Buckets
// to the rules variable and returns it.
// If the conditions are not met, the method returns an empty []BruteForceRule.
func (f *File) GetBruteForceRules() (rules []BruteForceRule) {
	if f == nil {
		return nil
	}

	if f.BruteForce != nil {
		if len(LoadableConfig.BruteForce.Buckets) > 0 {
			rules = LoadableConfig.BruteForce.Buckets
		}
	}

	return
}

// GetAllProtocols returns a unique slice of strings (a Set) for all defined protocols in the database search sections.
func (f *File) GetAllProtocols() []string {
	if f == nil {
		return nil
	}

	protocols := NewStringSet()

	if ldapProtocols := f.GetProtocols(definitions.BackendLDAP); ldapProtocols != nil {
		for index := range ldapProtocols.([]LDAPSearchProtocol) {
			for protoIndex := range LoadableConfig.LDAP.Search[index].Protocols {
				protocols.Set(LoadableConfig.LDAP.Search[index].Protocols[protoIndex])
			}
		}
	}

	if luaProtocols := f.GetProtocols(definitions.BackendLua); luaProtocols != nil {
		for index := range luaProtocols.([]LuaSearchProtocol) {
			for protoIndex := range LoadableConfig.Lua.Search[index].Protocols {
				protocols.Set(LoadableConfig.Lua.Search[index].Protocols[protoIndex])
			}
		}
	}

	return protocols.GetStringSlice()
}

// getOAuth2ClientIndex returns the index and found status of an OAuth-2 client with the given client ID in the LoadableConfig.Oauth2.Clients slice. If the client is found, the index
func getOAuth2ClientIndex(clientId string) (index int, found bool) {
	if LoadableConfig.Oauth2 != nil {
		for index = range LoadableConfig.Oauth2.Clients {
			if LoadableConfig.Oauth2.Clients[index].ClientId != clientId {
				continue
			}

			found = true

			break
		}
	}

	return
}

// GetSkipTOTP returns a boolean true, if TOTP two-factor authentication shall be skipped for an OAuth-2 client.
func GetSkipTOTP(clientId string) (skip bool) {
	if index, found := getOAuth2ClientIndex(clientId); found {
		return LoadableConfig.Oauth2.Clients[index].SkipTOTP
	}

	return
}

// GetSkipConsent returns a boolean true, if the consent dialog shall be skipped for an OAuth-2 client.
func GetSkipConsent(clientId string) (skip bool) {
	if index, found := getOAuth2ClientIndex(clientId); found {
		return LoadableConfig.Oauth2.Clients[index].SkipConsent
	}

	return
}

// GetUsername returns the HTTP request header for the username
func (f *File) GetUsername() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.Username
}

// GetPassword returns the HTTP request header for the password
func (f *File) GetPassword() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.Password
}

// GetPasswordEncoded returns the HTTP request header to indicate if the password was encoded
func (f *File) GetPasswordEncoded() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.PasswordEncoded
}

// GetProtocol returns the HTTP request header for the used protocol
func (f *File) GetProtocol() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.Protocol
}

// GetLoginAttempt returns the HTTP request header for login-attempts
func (f *File) GetLoginAttempt() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.LoginAttempt
}

// GetAuthMethod returns the HTTP request header for the auth mechanism LOGIN or PLAIN
func (f *File) GetAuthMethod() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.AuthMethod
}

// GetLocalIP returns the HTTP request header that represents the local IP address for the server that accepts client requests
func (f *File) GetLocalIP() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.LocalIP
}

// GetLocalPort returns the HTTP request header that represents the local TCP port for the server that accepts client requests
func (f *File) GetLocalPort() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.LocalPort
}

// GetClientIP returns the HTTP request header that holds the client IP of the request
func (f *File) GetClientIP() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.ClientIP
}

// GetClientPort returns the HTTP request header that holds the client TCP port of the request
func (f *File) GetClientPort() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.ClientPort
}

// GetClientHost returns the HTTP request header used to retrieve an optional client hostname
func (f *File) GetClientHost() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.ClientHost
}

// GetClientID returns the HTTP request header used to retrieve an optional client ID
func (f *File) GetClientID() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.ClientID
}

// GetSSL returns the HTTP request header used to indicate SSL security for the current client connection
func (f *File) GetSSL() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSL
}

func (f *File) GetSSLSessionID() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLSessionID
}

func (f *File) GetSSLVerify() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLVerify
}

func (f *File) GetSSLSubject() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLSubject
}

func (f *File) GetSSLClientCN() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLClientCN
}

func (f *File) GetSSLIssuer() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLIssuer
}

func (f *File) GetSSLClientNotBefore() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLClientNotBefore
}

func (f *File) GetSSLClientNotAfter() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLClientNotAfter
}

func (f *File) GetSSLSubjectDN() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLSubjectDN
}

func (f *File) GetSSLIssuerDN() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLSubject
}

func (f *File) GetSSLClientSubjectDN() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLClientSubjectDN
}

func (f *File) GetSSLClientIssuerDN() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLClientIssuerDN
}

func (f *File) GetSSLCipher() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLCipher
}

func (f *File) GetSSLProtocol() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLProtocol
}

func (f *File) GetSSLSerial() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLSerial
}

func (f *File) GetSSLFingerprint() string {
	if f == nil {
		return ""
	}

	return f.Server.DefaultHTTPRequestHeader.SSLFingerprint
}

// validateBackends is a method on the File struct.
// It checks if the Server struct has any configured backends.
// If there are no backends configured, it returns the error ErrNoBackendsConfigured.
func (f *File) validateBackends() error {
	if len(f.Server.Backends) == 0 {
		return errors.ErrNoBackendsConfigured
	}

	return nil
}

// validateRBLs is a method on the File struct.
// It validates the RBLs field in the File struct.
// If the RBLs field is not nil, it checks if the Threshold value is greater than math.MaxInt and logs a warning if it is.
// Then, it iterates over each RBL in the Lists field and checks if the Weight value is greater than math.MaxUint8 or less than -math.MaxUint8, logging a warning in each case.
// Finally, it logs the RBLs field with Debug level.
//
// If there are no errors, it returns nil.
//
// Example usage:
//
//	err := validateRBLs()
//	if err != nil {
//	  log.Fatal(err)
//	}
func (f *File) validateRBLs() error {
	if f.RBLs != nil {
		if f.RBLs.Threshold > math.MaxInt {
			level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, "Please use a smaller RBL threshold!",
				"rbl_threshold", f.RBLs.Threshold)
		}

		for _, rbl := range f.RBLs.Lists {
			if rbl.Weight > math.MaxUint8 {
				level.Warn(log.Logger).Log(
					definitions.LogKeyMsg, "Please use a lower RBL weight!",
					"rbl_threshold", rbl.Weight,
					"rbl", rbl.RBL)
			} else if rbl.Weight < -math.MaxUint8 {
				level.Warn(log.Logger).Log(
					definitions.LogKeyMsg, "Please use a higher RBL weight!",
					"rbl_threshold", rbl.Weight,
					"rbl", rbl.RBL)
			}
		}
	}

	return nil
}

// validateBruteForce is a method on the File struct.
//
// It validates the BruteForce field in the File struct.
// If the BruteForce field is not nil, it checks each rule in the Buckets slice.
//
// The validation rules for each rule are as follows:
// - The rule must have a non-empty Name field, otherwise it returns errors.ErrRuleNoName.
// - The rule cannot have both IPv4 and IPv6 flags set to true at the same time, otherwise it returns errors.ErrRuleNoIPv4AndIPv6.
// - The rule must have either IPv4 or IPv6 flag set to true, otherwise it returns errors.ErrRuleMissingIPv4AndIPv6.
// - The rule must have a non-zero CIDR value, otherwise it returns errors.ErrRuleNoCIDR.
// - The rule must have a non-zero Period value, otherwise it returns errors.ErrRuleNoPeriod.
// - The rule must have a non-zero FailedRequests value, otherwise it returns errors.ErrRuleNoFailedRequests.
//
// After validating each rule, it checks the total count of IPv4 and IPv6 rules.
// If the count of either IPv4 or IPv6 rules is more than one, it returns errors.ErrBruteForceTooManyRules.
//
// Finally, it logs the BruteForce struct using the global logger with the key "brute_force".
//
// If the BruteForce field is nil, it returns nil indicating that the field is valid.
func (f *File) validateBruteForce() error {
	if f.BruteForce != nil {
		for _, rule := range f.BruteForce.Buckets {
			if rule.Name == "" {
				return errors.ErrRuleNoName
			}

			if rule.IPv4 && rule.IPv6 {
				return errors.ErrRuleNoIPv4AndIPv6
			}

			if !(rule.IPv4 || rule.IPv6) {
				return errors.ErrRuleMissingIPv4AndIPv6
			}

			if rule.CIDR == 0 {
				return errors.ErrRuleNoCIDR
			}

			if rule.Period == 0 {
				return errors.ErrRuleNoPeriod
			}

			if rule.FailedRequests == 0 {
				return errors.ErrRuleNoFailedRequests
			}
		}

		countIPv4Rules := uint8(0)
		countIPv6Rules := uint8(0)

		if countIPv4Rules > 1 || countIPv6Rules > 1 {
			return errors.ErrBruteForceTooManyRules
		}
	}

	return nil
}

// validateSecrets is a method on the File struct.
// It validates the secrets used in the File struct.
// If any of the secrets have incorrect sizes or are missing, it returns an error.
// Possible error values:
// - ErrCSRFSecretWrongSize: returned if the CSRFSecret length is not 32.
// - ErrCookieStoreAuthSize: returned if the CookieStoreAuthKey length is not 32.
// - ErrCookieStoreEncSize: returned if the CookieStoreEncKey length is not 16, 24 or 32.
// - ErrNoPasswordNonce: returned if the PasswordNonce is empty.
// It returns nil if all secrets are valid.
func (f *File) validateSecrets() error {
	if f.Server.Frontend.Enabled {
		if len(f.Server.Frontend.CSRFSecret) != 32 {
			return errors.ErrCSRFSecretWrongSize
		}

		if len(f.Server.Frontend.CookieStoreAuthKey) != 32 {
			return errors.ErrCookieStoreAuthSize
		}

		if !(len(f.Server.Frontend.CookieStoreEncKey) == 16 || len(f.Server.Frontend.CookieStoreEncKey) == 24 || len(f.Server.Frontend.CookieStoreEncKey) == 32) {
			return errors.ErrCookieStoreEncSize
		}
	}

	if f.Server.Redis.PasswordNonce == "" {
		return errors.ErrNoPasswordNonce
	}

	return nil
}

// validatePrometheusLabels is a method on the File struct that validates the Prometheus labels used in the server's Prometheus timer configuration.
// If the Prometheus timer is enabled, it checks that each label is one of the predefined constants:
// - definitions.PromAction
// - definitions.PromAccount
// - definitions.PromBackend
// - definitions.PromBruteForce
// - definitions.PromFeature
// - definitions.PromFilter
// - definitions.PromPostAction
// - definitions.PromRequest
// - definitions.PromStoreTOTP
// - definitions.PromDNS
// If any label is unknown, it returns an error with a message indicating the unknown label.
// If the Prometheus timer is not enabled, it returns nil.
func (f *File) validatePrometheusLabels() error {
	if f.Server.PrometheusTimer.Enabled {
		for _, label := range f.Server.PrometheusTimer.Labels {
			switch label {
			case definitions.PromAction, definitions.PromAccount, definitions.PromBackend, definitions.PromBruteForce, definitions.PromFeature, definitions.PromFilter, definitions.PromPostAction, definitions.PromRequest, definitions.PromStoreTOTP, definitions.PromDNS:
				continue
			}

			return fmt.Errorf("the prometheus_timer::label name '%s' is unknown", label)
		}
	}

	return nil
}

// LDAPHavePoolOnly is a method on the File struct.
// It checks if the LDAP field and LDAP.Config field are not nil,
// and returns the value of LDAP.Config.PoolOnly.
// Otherwise, it returns false.
func (f *File) LDAPHavePoolOnly() bool {
	if f == nil || f.LDAP == nil || f.LDAP.Config == nil {
		return false
	}

	return f.LDAP.Config.PoolOnly
}

// validatePassDBBackends is a method on the File struct.
// It validates the Backend backends defined in the EnvConfig.
// If any of the validations fail, it returns the corresponding error.
// The method checks the specific configurations and settings for each backend.
// It also sets default values for certain fields if they are not provided.
//
// The method uses the EnvConfig and Backend structs defined in the codebase.
// The Backend constants from the global package are also used for comparison.
// The method logs debug information using the Logger from the logging package.
// The errors package is used to define and return the error messages.
func (f *File) validatePassDBBackends() error {
	for _, backend := range f.Server.Backends {
		switch backend.Get() {
		case definitions.BackendLDAP:
			if f.LDAP == nil {
				return errors.ErrNoLDAPSection
			}

			if f.LDAP.Config == nil {
				return errors.ErrNoLDAPConfig
			}

			if !f.LDAP.Config.PoolOnly && len(f.LDAP.Search) == 0 {
				return errors.ErrNoLDAPSearchSection
			}

			if len(f.LDAP.Config.ServerURIs) == 0 {
				return errors.ErrNoLDAPServerURIs
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
			if f.GetLuaScriptPath() == "" {
				return errors.ErrNoLuaScriptPath
			}
		case definitions.BackendUnknown:
		case definitions.BackendCache:
		case definitions.BackendLocalCache:
		}
	}

	return nil
}

// validateOAuth2 is a method for a File struct that checks if its OAuth2 field is not nil.
// If it is not nil, it iterate through 'CustomScopes' of OAuth2 and searches for any 'description_' prefixed keys.
// Each found key (that matches "description_"+baseName.String()) is stored in a map 'descriptions' along with their values,
// after asserting they are of type string. Updated 'Other' map of each 'CustomScopes' with 'descriptions'.
// Finally, it logs the whole OAuth2 field in a debug level log.
//
// It doesn't return any value, and it doesn't trigger any side effects other than logging.
func (f *File) validateOAuth2() error {
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

// checkAddress validates if the given address is in the correct format.
// It checks if the address can be split into host and port using net.SplitHostPort.
// If the address is invalid, it returns an error; otherwise, it returns nil.
func checkAddress(address string) error {
	_, _, err := net.SplitHostPort(address)

	return err
}

// validateAddress is a method on the File struct.
// It validates the Server.Address field, if it is empty it assigns definitions.HTTPAddress to it.
// It then checks if the Server.Address is a valid address by using net.SplitHostPort function.
// It returns any error that occurs during the validation process.
func (f *File) validateAddress() error {
	if f.Server.Address == "" {
		f.Server.Address = definitions.HTTPAddress
	}

	return checkAddress(f.Server.Address)
}

// validateHydraAdminURL is a method on the File struct.
// It validates the HydraAdminUrl field in the Server struct
// and returns an error if the URL is invalid.
// If the HydraAdminUrl field is empty, it sets a default value of "http://127.0.0.1:4445".
func (f *File) validateHydraAdminURL() error {
	if f.Server.HydraAdminUrl == "" {
		f.Server.HydraAdminUrl = "http://127.0.0.1:4445"
	}

	_, err := url.ParseRequestURI(f.Server.HydraAdminUrl)

	return err
}

// validateTLSCertAndKey is a method on the File struct.
// It validates the readability of the TLS certificate and key files specified in the Server struct.
// If any of the files are not readable, it returns an error indicating the file that is not readable.
// Otherwise, it returns nil.
// It uses the isFileReadable function to check the validity of each file.
// The function takes a file path as an argument and checks if the file exists and is readable.
// If the file is not readable, it returns an error.
// The validateTLSCertAndKey method iterates over the Cert and Key file paths in the Server struct.
// For each path, it calls the isFileReadable function.
// If any of the files are not readable, it returns an error message indicating the file that is not readable.
// The error message is formatted using the fmt.Errorf function.
// If all files are readable, it returns nil to indicate that the validation was successful.
func (f *File) validateTLSCertAndKey() error {
	if !f.Server.TLS.Enabled {
		return nil
	}

	isFileReadable := func(file string) error {
		_, err := os.Stat(file)

		return err
	}

	for _, file := range []string{f.Server.TLS.Cert, f.Server.TLS.Key} {
		if err := isFileReadable(file); err != nil {
			return fmt.Errorf("TLS certificate or key file %s is not readable: %w", file, err)
		}
	}

	return nil
}

// validateDNSResolver checks whether the provided DNS resolver in the Server configuration is valid.
// It returns an error if the DNS resolver is not in the correct host:port format, or if either host or port is empty.
func (f *File) validateDNSResolver() error {
	if f.Server.DNS.Resolver == "" {
		return nil
	}

	host, port, err := net.SplitHostPort(f.Server.DNS.Resolver)
	if err != nil {
		return fmt.Errorf("DNS resolver %s is not valid: %w", f.Server.DNS.Resolver, err)
	}

	if host == "" {
		return fmt.Errorf("DNS resolver %s is not valid: host is empty", f.Server.DNS.Resolver)
	}

	if port == "" {
		return fmt.Errorf("DNS resolver %s is not valid: port is empty", f.Server.DNS.Resolver)
	}

	return nil
}

// validateInstanceName is a method on the File struct.
// It checks if the Server's InstanceName field is empty.
// If it is empty, it sets the InstanceName to the definitions.InstanceName constant value.
// It returns an error if any error occurred during the validation process.
func (f *File) validateInstanceName() error {
	if f.Server.InstanceName == "" {
		f.Server.InstanceName = definitions.InstanceName
	}

	return nil
}

// validateDNSTimeout is a method on the File struct.
// It validates the DNS timeout value to ensure it is not less than 1 second and not more than 30 seconds.
// If the timeout is less than 1 second, it sets it to 1 second.
// If the timeout is more than 32 seconds, it sets it to 32 seconds.
// This method does not return any errors.
func (f *File) validateDNSTimeout() error {
	if f.Server.DNS.Timeout == 0 {
		f.Server.DNS.Timeout = definitions.DNSResolveTimeout
	}

	// Not less than 1 second
	if f.Server.DNS.Timeout < 1 {
		f.Server.DNS.Timeout = 1
	}

	// Not more than 30 seconds
	if f.Server.DNS.Timeout > 30 {
		f.Server.DNS.Timeout = 30
	}

	return nil
}

// validateRedisMasterAddress is a method on the File struct.
// It validates the Redis master address and returns an error if it is invalid.
// The function first checks if there are multiple sentinel addresses and a specified sentinel master.
// If so, it assumes that the Redis master address is valid and returns nil.
// If the Redis master address is empty, it constructs a new address using the global RedisAddress and RedisPort constants.
// Finally, it calls the checkAddress function to validate the Redis master address and returns any errors.
// Example usage of the validateRedisMasterAddress method can be found in the validate method of the File struct.
// Package and other declarations are not shown here for brevity.
func (f *File) validateRedisMasterAddress() error {
	if len(f.Server.Redis.Sentinels.Addresses) > 1 && f.Server.Redis.Sentinels.Master != "" {
		return nil
	}

	if f.Server.Redis.Master.Address == "" {
		f.Server.Redis.Master.Address = fmt.Sprintf("%s:%d", definitions.RedisAddress, definitions.RedisPort)
	}

	return checkAddress(f.Server.Redis.Master.Address)
}

// validateRedisSentinels is a method on the File struct.
// It checks if the Redis sentinels addresses are valid and if the Redis master is specified.
// If the addresses are valid, it calls the checkAddress function for each address.
// If any of the addresses is invalid, it returns an error.
// If there is no error or the sentinels addresses are not specified, it returns nil.
func (f *File) validateRedisSentinels() error {
	if len(f.Server.Redis.Sentinels.Addresses) > 1 && f.Server.Redis.Sentinels.Master != "" {
		for _, address := range f.Server.Redis.Sentinels.Addresses {
			if err := checkAddress(address); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateRedisDatabaseNumber is a method on the File struct.
// It validates the Redis database number and returns an error if the number is out of range.
// If the number is less than 0, it returns errors.ErrRedisDatabaseNumber.
// If the number is greater than 15, it also returns errors.ErrRedisDatabaseNumber.
// Otherwise, it returns nil indicating no error.
func (f *File) validateRedisDatabaseNumber() error {
	if f.Server.Redis.DatabaseNmuber < 0 {
		return errors.ErrRedisDatabaseNumber
	}

	if f.Server.Redis.DatabaseNmuber > 15 {
		return errors.ErrRedisDatabaseNumber
	}

	return nil
}

// validateRedisPoolSize is a method on the File struct.
// It validates the Redis pool size and returns an error if it is less than or equal to 0.
// If the Redis pool size is valid, it returns nil.
// The method uses the ErrRedisPoolSize error from the errors package.
func (f *File) validateRedisPoolSize() error {
	if f.Server.Redis.PoolSize <= 0 {
		return errors.ErrRedisPoolSize
	}

	// Silently ignore negative values!
	if f.Server.Redis.IdlePoolSize < 0 {
		f.Server.Redis.IdlePoolSize = 0
	}

	return nil
}

// validateRedisPosCacheTTL is a method on the File struct.
// It checks if the RedisPosCacheTTL field in the Server.Redis struct is set to 0.
// If it is, it assigns the value of definitions.RedisPosCacheTTL to it before returning.
// This method ensures that a default value is set for RedisPosCacheTTL if it was not explicitly provided.
// The function does not return any errors.
func (f *File) validateRedisPosCacheTTL() error {
	if f.Server.Redis.PosCacheTTL == 0 {
		f.Server.Redis.PosCacheTTL = definitions.RedisPosCacheTTL
	}

	return nil
}

// validateRedisNegCacheTTL is a method on the File struct.
// It validates the RedisNegCacheTTL field of the Server.Redis struct.
// If the RedisNegCacheTTL field is 0, it sets it to the definitions.RedisNegCacheTTL constant.
// Returns nil error.
func (f *File) validateRedisNegCacheTTL() error {
	if f.Server.Redis.NegCacheTTL == 0 {
		f.Server.Redis.NegCacheTTL = definitions.RedisNegCacheTTL
	}

	return nil
}

// validateMasterUserDelimiter is a method on the File struct.
// It validates the MasterUser.Delimiter field.
// If the delimiter is empty, it sets it to "+".
// If the delimiter has more than one character, it truncates it to the first character.
// Return nil error.
func (f *File) validateMasterUserDelimiter() error {
	if f.Server.MasterUser.Delimiter == "" {
		f.Server.MasterUser.Delimiter = "*"
	}

	if len(f.Server.MasterUser.Delimiter) != 1 {
		f.Server.MasterUser.Delimiter = f.Server.MasterUser.Delimiter[:1]
	}

	return nil
}

// validateHTTPRequestHeaders ensures all default HTTP request headers are set. If any header is empty, it is replaced with its default value.
func (f *File) validateHTTPRequestHeaders() error {
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

// validateMaxConnections ensures that the MaxConcurrentRequests parameter is set to a valid value.
func (f *File) validateMaxConnections() error {
	if f.Server.MaxConcurrentRequests == 0 {
		f.Server.MaxConcurrentRequests = definitions.MaxConcurrentRequests
	}

	if f.Server.MaxConcurrentRequests < 0 {
		f.Server.MaxConcurrentRequests = definitions.MaxConcurrentRequests
	}

	return nil
}

// validateMaxPasswordHistoryEntries sets MaxPasswordHistoryEntries to a default value if non-positive and returns an error if any.
func (f *File) validateMaxPasswordHistoryEntries() error {
	if f.Server.MaxPasswordHistoryEntries <= 0 {
		f.Server.MaxPasswordHistoryEntries = definitions.MaxPasswordHistoryEntries
	}

	return nil
}

// validate is a method on the File struct that validates various aspects of the file.
// It uses a list of validator functions and calls each of them in order.
// If any of the validators return an error, the validation process stops and the error is returned.
// If all validators pass, nil is returned.
func (f *File) validate() (err error) {
	validators := []func() error{
		f.validateBackends,
		f.validateRBLs,
		f.validateBruteForce,
		f.validateSecrets,
		f.validatePassDBBackends,
		f.validateOAuth2,
		f.validateAddress,
		f.validateHydraAdminURL,
		f.validateTLSCertAndKey,
		f.validateRedisMasterAddress,
		f.validateRedisSentinels,
		f.validateRedisDatabaseNumber,
		f.validateRedisPoolSize,
		f.validatePrometheusLabels,
		f.validateDNSResolver,

		// Without errors, but fixing things
		f.validateInstanceName,
		f.validateDNSTimeout,
		f.validateRedisPosCacheTTL,
		f.validateRedisNegCacheTTL,
		f.validateMasterUserDelimiter,
		f.validateHTTPRequestHeaders,
		f.validateMaxConnections,
		f.validateMaxPasswordHistoryEntries,
	}

	for _, validator := range validators {
		if err = validator(); err != nil {
			return err
		}
	}

	return nil
}

// HasFeature checks if the given feature exists in the LoadableConfig's Features list
func (f *File) HasFeature(feature string) bool {
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

// processVerboseLevel sets the verbosity level based on the input value.
// It takes an input of type `any` and returns a value of type `any` and an error.
// The function uses the `Verbosity` struct to assign the appropriate verbosity level.
//
// If the input is a string, it is passed to the `Set` method of the `Verbosity` struct, which sets the verbosity level based on the input value.
// If the input is not a string, an error is returned indicating that the input type is invalid.
//
// The processVerboseLevel function is used in the createDecoderOption function, where it is used as a mapstructure.DecodeHookFunc.
//
// Example usage:
//
//	verbosity, err := processVerboseLevel("debug")
func processVerboseLevel(input any) (any, error) {
	verbosity := Verbosity{}
	err := verbosity.Set(input.(string))

	return verbosity, err
}

// processDebugModules processes the input data and returns a slice of DbgModule pointers and an error.
// The function accepts inputs of type string, []string, or []any.
// If the input is a string, it creates a new DbgModule and adds it to the dbgModules slice using the addDebugModule function.
// If the input is a []string, it iterates over each string and adds a DbgModule to the dbgModules slice for each string using the addDebugModule function.
// If the input is a []any, it checks if each element is a string and then adds a DbgModule to the dbgModules slice for each string using the addDebugModule function.
// If the input type is not supported, an error is returned.
// The function returns the dbgModules slice and nil if successful, or nil and an error if an error occurred during processing.
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

// processFeatures processes the input and returns a slice of Feature pointers and an error.
// The function accepts an `any` as input, which can be either a string, a slice of strings, or a slice of `any` values.
// If the input is a string, a single Feature is created with the input as its name and added to the features slice.
// If the input is a slice of strings, each string is processed as a separate Feature, and all the Features are added to the features slice.
// If the input is a slice of `any` values, each value is checked if it is a string. If it is not a string, an error is returned.
// If the value is a string, it is processed as a Feature and added to the features slice.
// If the input is of any other type, an error is returned.
// The function returns the features slice and any error that occurred during processing.
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

// processProtocols processes the input data and returns a slice of Protocol pointers and an error.
//
// The function takes an input of type `any`, which can be either a string, a slice of strings, or a slice of `any`.
// If the input is a string, it creates a new Protocol with the given data and appends it to the protocols slice.
// If the input is a slice of strings, it iterates over each string, creates a new Protocol with the string as data, and appends it to the protocols slice.
// If the input is a slice of `any`, it iterates over each element and checks if it is a string. If it is, it creates a new Protocol with the string as data and appends it to the protocols
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

// processBackends takes an input of any type and processes it to return an array of Backend objects.
// The input can be a string, a slice of strings, or a slice of interface{} objects.
// If the input is a string, a single Backend object is created from it and added to the array.
// If the input is a slice of strings, each string is converted to a Backend object and added to the array.
// If the input is a slice of interface{} objects, each object is checked to be of type string, and if so, converted to a Backend object and added to the array.
// If the input is of any other type, an error is returned.
// The function returns the array of Backend objects and an error, if any occurred during processing.
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

// createDecoderOption returns a viper.DecoderConfigOption function that sets the DecodeHook of the input DecoderConfig.
// The DecodeHook is set using mapstructure.ComposeDecodeHookFunc to compose multiple DecodeHook functions.
// The DecodeHook function performs custom decoding based on the target type:
// - If the target type is reflect.TypeOf(Verbosity{}), it calls processVerboseLevel to process the input data and return a Verbosity value.
// - If the target type is reflect.TypeOf([]*DbgModule{}), it calls processDebugModules to process the input data and return a slice of DbgModule values.
// - For any other target type, it returns the input data unchanged.
// The resulting function is then used as a DecoderConfigOption in the viper.UnmarshalExact function.
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

// handleFile applies the configuration settings loaded from the configuration file. It does sanity checks to make sure
// Nauthilus has a working configuration.
func (f *File) handleFile() (err error) {
	if f == nil {
		return nil
	}

	f.Mu.Lock()

	defer f.Mu.Unlock()

	if err = viper.UnmarshalExact(f, createDecoderOption()); err != nil {
		return
	}

	err = f.validate()
	if err != nil {
		return
	}

	// Throw away unsupported keys
	f.Other = nil

	return
}

// bindEnvs binds environment variables to the provided struct fields.
//
// 'i' is the struct that should have its fields populated with environment variable values.
// The field values are determined by the value of the 'mapstructure' tag of each field. If the 'mapstructure' tag is empty,
// the field's name will be used as the key to fetch the value from the environment variables.
// Struct tags offer a convenient way to specify metadata associated with the struct field.
//
// 'parts' is optional and can be used to provide parent keys when dealing with nested struct fields.
// This makes it easy to bind nested keys in structures.
//
// For each field in 'i', it checks the field's type. If the field type is pointer to a struct or
// the field is a struct, then it recursively collects the environment variable mappings.
//
// If the field type is a primitive type, it attempts to bind the environment variable using the viper library's BindEnv function.
// The environment variable key is constructed by concatenating 'parts' and 'tag' or field name as needed.
//
// The function returns an error when the viper's BindEnv fails to bind the environment variable. If no errors are encountered during binding,
// it will return nil indicating a successful binding of environment variables to struct fields.
func bindEnvs(i any, parts ...string) error {
	ifv := reflect.ValueOf(i)
	if ifv.Kind() == reflect.Ptr {
		ifv = ifv.Elem()
	}

	ift := ifv.Type()

	for i := range ift.NumField() {
		v := ifv.Field(i)
		t := ift.Field(i)

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

// NewConfigFile is the constructor for a ConfigFile object.
func NewConfigFile() (newCfg *File, err error) {
	newCfg = &File{}

	viper.SetConfigName("nauthilus") // name of EnvConfig file (without extension)
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
	bindEnvs(&File{})

	err = newCfg.handleFile()

	return newCfg, err
}

// ReloadConfigFile is a thread safe function to reload a ConfigFile object.
//
//nolint:forcetypeassert,gocognit // Ignore
func ReloadConfigFile() (err error) {
	newCfgReload := &File{}

	if err = viper.ReadInConfig(); err != nil {
		return
	}

	// Construct new configuration
	if err = newCfgReload.handleFile(); err != nil {
		return
	}

	// Replace existing configuration
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&LoadableConfig)), unsafe.Pointer(newCfgReload))

	level.Info(log.Logger).Log(definitions.LogKeyMsg, "Reloading configuration file finished")

	return
}
