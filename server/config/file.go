package config

import (
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/go-kit/log/level"
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
	RBLs               *RBLSection          `mapstructure:"realtime_blackhole_lists"`
	ClearTextList      []string             `mapstructure:"cleartext_networks"`
	RelayDomains       *RelayDomainsSection `mapstructure:"relay_domains"`
	NginxMonitoring    *NginxMonitoring     `mapstructure:"nginx_monitoring"`
	BruteForce         *BruteForceSection   `mapstructure:"brute_force"`
	CSRFSecret         string               `mapstructure:"csrf_secret"`
	CookieStoreAuthKey string               `mapstructure:"cookie_store_auth_key"`
	CookieStoreEncKey  string               `mapstructure:"cookie_store_encryption_key"`
	PasswordNonce      string               `mapstructure:"password_nonce"`
	Lua                *LuaSection
	Oauth2             *Oauth2Section
	SQL                *SQLSection
	LDAP               *LDAPSection
	Other              map[string]any `mapstructure:",remain"`
	Mu                 sync.Mutex
}

/*
 * Nginx monitoring
 */

// GetNginxMonitoring is a method on the File struct.
// It returns the NginxMonitoring field from the File struct.
func (f *File) GetNginxMonitoring() *NginxMonitoring {
	return f.NginxMonitoring
}

// GetNginxBackendServers method operates on a File receiver 'f'.
// It checks if the NginxMonitoring property is not null, it returns a pointer to an array of NginxBackendServers,
// otherwise, it returns an empty array of NginxBackendServer pointers.
// This method could be used when trying to get all backend servers of an Nginx configuration file.
func (f *File) GetNginxBackendServers() []*NginxBackendServer {
	if f.GetNginxMonitoring() != nil {
		return f.NginxMonitoring.NginxBackendServer
	}

	return []*NginxBackendServer{}
}

// GetNginxBackendServer is a method of the File struct.
// It takes a protocol as an argument and returns a pointer to a NginxBackendServer.
// The method iterates over the Backend Servers of the File instance and returns the first server that matches the provided protocol.
// If no such server is found, nil is returned.
func (f *File) GetNginxBackendServer(protocol string) *NginxBackendServer {
	for _, server := range f.GetNginxBackendServers() {
		if server.Protocol == protocol {
			return server
		}
	}

	return nil
}

// GetNginxBackendServerIP is a method for the File struct which
// attempts to get the IP address of an Nginx backend server
// for a specified protocol. The method first calls
// GetNginxBackendServer with the given protocol and checks
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
func (f *File) GetNginxBackendServerIP(protocol string) string {
	if f.GetNginxBackendServer(protocol) != nil {
		return f.GetNginxBackendServer(protocol).IP
	}

	return ""
}

// GetNginxBackendServerPort checks the specific protocol's backend server in the File structure.
// If the server exists, it returns the port of the server.
// If the server does not exist, it returns 0.
func (f *File) GetNginxBackendServerPort(protocol string) int {
	if f.GetNginxBackendServer(protocol) != nil {
		return f.GetNginxBackendServer(protocol).Port
	}

	return 0
}

/*
 * SQL Config
 */

func (f *File) GetSQLConfigDSN() string {
	getConfig := f.GetConfig(global.BackendSQL)
	if getConfig == nil {
		return ""
	}

	if sqlConf, assertOk := getConfig.(*SQLConf); assertOk {
		return sqlConf.DSN
	}

	return ""
}

func (f *File) GetSQLConfigCrypt() bool {
	getConfig := f.GetConfig(global.BackendSQL)
	if getConfig == nil {
		return false
	}

	if sqlConf, assertOk := getConfig.(*SQLConf); assertOk {
		return sqlConf.Crypt
	}

	return false
}

func (f *File) GetSQLSearchProtocol(protocol string) (*SQLSearchProtocol, error) {
	getSearch := f.GetProtocols(global.BackendSQL)
	if getSearch == nil {
		return nil, errors.ErrSQLConfig.WithDetail("Missing search::protocol section and no default")
	}

	for index := range getSearch.([]SQLSearchProtocol) {
		for protoIndex := range getSearch.([]SQLSearchProtocol)[index].Protocols {
			if getSearch.([]SQLSearchProtocol)[index].Protocols[protoIndex] == protocol {
				return &getSearch.([]SQLSearchProtocol)[index], nil
			}
		}
	}

	if protocol == global.ProtoDefault {
		return nil, errors.ErrSQLConfig.WithDetail("Missing search::protocol section and no default")
	}

	return f.GetSQLSearchProtocol(global.ProtoDefault)
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
	getConfig := f.GetConfig(global.BackendLDAP)
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
// 1. Get the LDAP specific configuration by calling GetConfig with 'global.BackendLDAP'.
// 2. If no configuration is found, it defaults to returning false.
// 3. If a configuration is found, it checks whether it can be asserted to a LDAPConf type.
// 4. If it is successfully asserted to a LDAPConf type, it returns the value of 'TLSSkipVerify'.
// 5. If the assertion to LDAPConf is unsuccessful, it defaults to returning false.
//
// Returns:
// The function returns a boolean indicating whether TLSSkipVerify is enabled (true) or not (false).
func (f *File) GetLDAPConfigTLSSkipVerify() bool {
	getConfig := f.GetConfig(global.BackendLDAP)
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
	getConfig := f.GetConfig(global.BackendLDAP)
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
	getConfig := f.GetConfig(global.BackendLDAP)
	if getConfig == nil {
		return global.LDAPIdlePoolSize
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.LookupIdlePoolSize
	}

	return global.LDAPIdlePoolSize
}

// GetLDAPConfigAuthIdlePoolSize is a method that operates on a File struct.
// It retrieves the 'AuthIdlePoolSize' configuration from the LDAP
// configuration if it exists. If no such configuration is found
// or the type assertion for LDAPConf fails, it returns a default
// global LDAP idle pool size.
func (f *File) GetLDAPConfigAuthIdlePoolSize() int {
	getConfig := f.GetConfig(global.BackendLDAP)
	if getConfig == nil {
		return global.LDAPIdlePoolSize
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.AuthIdlePoolSize
	}

	return global.LDAPIdlePoolSize
}

// GetLDAPConfigLookupPoolSize retrieves the number of connections
// that should be maintained in the LDAP lookup pool.
// If the LDAP configuration can be asserted successfully, it
// returns the LookupPoolSize from the retrieved LDAP configuration.
// If not, it returns the global constant LDAPIdlePoolSize.
func (f *File) GetLDAPConfigLookupPoolSize() int {
	getConfig := f.GetConfig(global.BackendLDAP)
	if getConfig == nil {
		return global.LDAPIdlePoolSize
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.LookupPoolSize
	}

	return global.LDAPIdlePoolSize
}

// GetLDAPConfigAuthPoolSize is a method of File struct.
// It returns the LDAP configuration authentication pool size.
// If the configuration for LDAP backend is nil or not assertable,
// it returns the default global.LDAPIdlePoolSize value. Otherwise,
// it returns the AuthPoolSize from the LDAP configuration.
func (f *File) GetLDAPConfigAuthPoolSize() int {
	getConfig := f.GetConfig(global.BackendLDAP)
	if getConfig == nil {
		return global.LDAPIdlePoolSize
	}

	if ldapConf, assertOk := getConfig.(*LDAPConf); assertOk {
		return ldapConf.AuthPoolSize
	}

	return global.LDAPIdlePoolSize
}

// GetLDAPConfigBindDN is a method on the File struct.
// It retrieves the BindDN field from the LDAP configuration in the File's configuration settings.
// It will return an empty string if either the config can't be retrieved (nil is returned), or in case
// the type assertion to an LDAPConf object fails.
func (f *File) GetLDAPConfigBindDN() string {
	getConfig := f.GetConfig(global.BackendLDAP)
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
	getConfig := f.GetConfig(global.BackendLDAP)
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
// It first retrieves the LDAP configuration using the GetConfig method, passing in the global.BackendLDAP value.
// If the LDAP configuration is not found or is not of type *LDAPConf, it returns an empty string.
// Otherwise, it casts the retrieved configuration to *LDAPConf and returns the TLSCAFile field.
// If the TLSCAFile field is empty, it also returns an empty string.
// Example usage:
// filePath := file.GetLDAPConfigTLSCAFile()
func (f *File) GetLDAPConfigTLSCAFile() string {
	getConfig := f.GetConfig(global.BackendLDAP)
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
	getConfig := f.GetConfig(global.BackendLDAP)
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
	getConfig := f.GetConfig(global.BackendLDAP)
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
// It first gets the LDAP configuration using the GetConfig method from global.BackendLDAP.
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
	getConfig := f.GetConfig(global.BackendLDAP)
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
	getSearch := f.GetProtocols(global.BackendLDAP)
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

	if protocol == global.ProtoDefault {
		return nil, errors.ErrLDAPConfig.WithDetail("Missing search::protocol section and no default")
	}

	return f.GetLDAPSearchProtocol(global.ProtoDefault)
}

/*
 * Lua config
 */

// GetLuaScriptPath is a method on the File struct.
// It returns the Lua script path from the LuaConf field in the File struct.
// It first calls the GetConfig method with the global.BackendLua parameter to obtain the Lua configuration.
// If the Lua configuration is nil, it returns an empty string.
// If the Lua configuration is not nil, it asserts the retrieved configuration as a *LuaConf type.
// If the assertion is successful, it returns the ScriptPath field from the Lua configuration.
// If the assertion fails, it returns an empty string.
func (f *File) GetLuaScriptPath() string {
	getConfig := f.GetConfig(global.BackendLua)
	if getConfig == nil {
		return ""
	}

	if luaConf, assertOk := getConfig.(*LuaConf); assertOk {
		return luaConf.ScriptPath
	}

	return ""
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
	getSearch := f.GetProtocols(global.BackendLua)
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

	if protocol == global.ProtoDefault {
		return nil, errors.ErrLuaConfig.WithDetail("Missing search::protocol section and no default")
	}

	return f.GetLuaSearchProtocol(global.ProtoDefault)
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
func (f *File) RetrieveGetterMap() map[global.Backend]GetterHandler {
	getterMap := make(map[global.Backend]GetterHandler, 3)

	if ldapSection, ok := f.GetSection(global.BackendLDAP).(*LDAPSection); ok {
		getterMap[global.BackendLDAP] = ldapSection
	}

	if sqlSection, ok := f.GetSection(global.BackendSQL).(*SQLSection); ok {
		getterMap[global.BackendSQL] = sqlSection
	}

	if luaSection, ok := f.GetSection(global.BackendLua).(*LuaSection); ok {
		getterMap[global.BackendLua] = luaSection
	}

	return getterMap
}

// GetConfig returns the configuration handler for the specified backend.
// The configuration handler is determined based on the backend type.
// If the backend is found, it retrieves the configuration handler associated with it
// and returns the result of calling the GetterHandler() method on the configuration handler.
// If the configuration handler is not found, it returns nil.
func (f *File) GetConfig(backend global.Backend) any {
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
func (f *File) GetProtocols(backend global.Backend) any {
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
// It takes a backend of type global.Backend as parameter and returns the corresponding section.
// The method checks the value of the backend parameter and returns the appropriate section.
// If the backend is global.BackendLDAP, it returns f.LDAP.
// If the backend is global.BackendMySQL, global.BackendPostgres, or global.BackendSQL, it returns f.SQL.
// If the backend is global.BackendLua, it returns f.Lua.
// For any other value of the backend parameter, it returns nil.
func (f *File) GetSection(backend global.Backend) any {
	switch backend {
	case global.BackendLDAP:
		return f.LDAP
	case global.BackendMySQL, global.BackendPostgres, global.BackendSQL:
		return f.SQL
	case global.BackendLua:
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
func (*File) GetBruteForceRules() (rules []BruteForceRule) {
	if LoadableConfig.BruteForce != nil {
		if len(LoadableConfig.BruteForce.Buckets) > 0 {
			rules = LoadableConfig.BruteForce.Buckets
		}
	}

	return
}

// GetAllProtocols returns a unique slice of strings (a Set) for all defined protocols in the database search sections.
func (f *File) GetAllProtocols() []string {
	protocols := NewStringSet()

	if ldapProtocols := f.GetProtocols(global.BackendLDAP); ldapProtocols != nil {
		for index := range ldapProtocols.([]LDAPSearchProtocol) {
			for protoIndex := range LoadableConfig.LDAP.Search[index].Protocols {
				protocols.Set(LoadableConfig.LDAP.Search[index].Protocols[protoIndex])
			}
		}
	}

	if sqlProtocols := f.GetProtocols(global.BackendSQL); sqlProtocols != nil {
		for index := range sqlProtocols.([]SQLSearchProtocol) {
			for protoIndex := range LoadableConfig.SQL.Search[index].Protocols {
				protocols.Set(LoadableConfig.SQL.Search[index].Protocols[protoIndex])
			}
		}
	}

	if luaProtocols := f.GetProtocols(global.BackendLua); luaProtocols != nil {
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
			level.Warn(logging.DefaultLogger).Log(
				global.LogKeyWarning, "Please use a smaller RBL threshold!",
				"rbl_threshold", f.RBLs.Threshold)
		}

		for _, rbl := range f.RBLs.Lists {
			if rbl.Weight > math.MaxUint8 {
				level.Warn(logging.DefaultLogger).Log(
					global.LogKeyWarning, "Please use a lower RBL weight!",
					"rbl_threshold", rbl.Weight,
					"rbl", rbl.RBL)
			} else if rbl.Weight < -math.MaxUint8 {
				level.Warn(logging.DefaultLogger).Log(
					global.LogKeyWarning, "Please use a higher RBL weight!",
					"rbl_threshold", rbl.Weight,
					"rbl", rbl.RBL)
			}
		}

		level.Debug(logging.DefaultLogger).Log(global.FeatureRBL, fmt.Sprintf("%+v", f.RBLs))
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

		level.Debug(logging.DefaultLogger).Log(global.LogKeyBruteForce, fmt.Sprintf("%+v", f.BruteForce))
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
	if len(f.CSRFSecret) != 32 {
		return errors.ErrCSRFSecretWrongSize
	}

	if len(f.CookieStoreAuthKey) != 32 {
		return errors.ErrCookieStoreAuthSize
	}

	if !(len(f.CookieStoreEncKey) == 16 || len(f.CookieStoreEncKey) == 24 || len(f.CookieStoreEncKey) == 32) {
		return errors.ErrCookieStoreEncSize
	}

	if f.PasswordNonce == "" {
		return errors.ErrNoPasswordNonce
	}

	return nil
}

// validatePassDBBackends is a method on the File struct.
// It validates the PassDB backends defined in the EnvConfig.
// If any of the validations fail, it returns the corresponding error.
// The method checks the specific configurations and settings for each backend.
// It also sets default values for certain fields if they are not provided.
//
// The method uses the EnvConfig and PassDB structs defined in the codebase.
// The Backend constants from the global package are also used for comparison.
// The method logs debug information using the DefaultLogger from the logging package.
// The errors package is used to define and return the error messages.
func (f *File) validatePassDBBackends() error {
	for _, passDB := range EnvConfig.PassDBs {
		switch passDB.Get() {
		case global.BackendLDAP:
			if f.LDAP == nil {
				return errors.ErrNoLDAPSection
			}

			if f.LDAP.Config == nil {
				return errors.ErrNoLDAPConfig
			}

			if len(f.LDAP.Search) == 0 {
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
				f.LDAP.Config.LookupIdlePoolSize = global.LDAPIdlePoolSize
			}

			if f.GetLDAPConfigLookupPoolSize() < f.GetLDAPConfigLookupIdlePoolSize() {
				f.LDAP.Config.LookupPoolSize = f.LDAP.Config.LookupIdlePoolSize
			}

			if f.GetLDAPConfigAuthPoolSize() < 1 {
				f.LDAP.Config.AuthPoolSize = runtime.NumCPU()
			}

			if f.GetLDAPConfigAuthIdlePoolSize() < 1 {
				f.LDAP.Config.AuthIdlePoolSize = global.LDAPIdlePoolSize
			}

			if f.GetLDAPConfigAuthPoolSize() < f.GetLDAPConfigAuthIdlePoolSize() {
				f.LDAP.Config.AuthPoolSize = f.LDAP.Config.AuthIdlePoolSize
			}

			level.Debug(logging.DefaultLogger).Log("ldap", fmt.Sprintf("%+v", f.LDAP.Config))
		case global.BackendMySQL, global.BackendPostgres:
			if f.SQL == nil {
				return errors.ErrNoSQLSection
			}

			level.Debug(logging.DefaultLogger).Log("sql", fmt.Sprintf("%+v", f.SQL.Config))
		case global.BackendLua:
			if f.GetLuaScriptPath() == "" {
				return errors.ErrNoLuaScriptPath
			}
		case global.BackendUnknown:
		case global.BackendCache:
		case global.BackendSQL:
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

		level.Debug(logging.DefaultLogger).Log("oauth2", fmt.Sprintf("%+v", f.Oauth2))
	}

	return nil
}

// validate is a method on the File struct that validates various aspects of the file.
// It uses a list of validator functions and calls each of them in order.
// If any of the validators return an error, the validation process stops and the error is returned.
// If all validators pass, nil is returned.
// The validators used in this method are:
// - validateRBLs
// - validateBruteForce
// - validateSecrets
// - validatePassDBBackends
// - validateOAuth2
func (f *File) validate() (err error) {
	validators := []func() error{
		f.validateRBLs,
		f.validateBruteForce,
		f.validateSecrets,
		f.validatePassDBBackends,
		f.validateOAuth2,
	}

	for _, validator := range validators {
		if err = validator(); err != nil {
			return err
		}
	}

	return nil
}

// logDebug is a method on the File struct.
// It logs debug messages based on the values of the ClearTextList, RelayDomains, and NginxMonitoring fields.
func (f *File) logDebug() {
	if f.ClearTextList != nil {
		level.Debug(logging.DefaultLogger).Log(global.FeatureTLSEncryption, fmt.Sprintf("%+v", f.ClearTextList))
	}

	if f.RelayDomains != nil {
		level.Debug(logging.DefaultLogger).Log(global.FeatureRelayDomains, fmt.Sprintf("%+v", f.RelayDomains))
	}

	if f.NginxMonitoring != nil {
		level.Debug(logging.DefaultLogger).Log(global.FeatureNginxMonitoring, fmt.Sprintf("%+v", f.NginxMonitoring))
	}
}

// handleFile applies the configuration settings loaded from the configuration file. It does sanity checks to make sure
// Nauthilus has a working configuration.
func (f *File) handleFile() (err error) {
	f.Mu.Lock()

	defer f.Mu.Unlock()

	if err = viper.UnmarshalExact(f); err != nil {
		return
	}

	err = f.validate()
	if err != nil {
		return
	}

	f.logDebug()

	// Throw away unsupported keys
	f.Other = nil

	return
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

	level.Info(logging.DefaultLogger).Log(global.LogKeyMsg, "Reloading configuration file finished")

	return
}
