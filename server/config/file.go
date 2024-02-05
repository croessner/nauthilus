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

func (f *File) GetNginxMonitoring() *NginxMonitoring {
	return f.NginxMonitoring
}

func (f *File) GetNginxBackendServers() []*NginxBackendServer {
	if f.GetNginxMonitoring() != nil {
		return f.NginxMonitoring.NginxBackendServer
	}

	return []*NginxBackendServer{}
}

func (f *File) GetNginxBackendServer(protocol string) *NginxBackendServer {
	for _, server := range f.GetNginxBackendServers() {
		if server.Protocol == protocol {
			return server
		}
	}

	return nil
}

func (f *File) GetNginxBackendServerIP(protocol string) string {
	if f.GetNginxBackendServer(protocol) != nil {
		return f.GetNginxBackendServer(protocol).IP
	}

	return ""
}

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

func (*File) GetBruteForceRules() (rules []BruteForceRule) {
	if LoadableConfig.BruteForce != nil {
		if len(LoadableConfig.BruteForce.Buckets) > 0 {
			rules = LoadableConfig.BruteForce.Buckets
		}
	}

	return
}

// GetAllProtocols returns a unique slice of strings ( a Set) for all defined protocols in the database search sections.
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

// MapToStruct applies the configuration settings loaded from the configuration file. It does sanity checks to make sure
// Nauthilus has a working configuration.
//
//nolint:gocognit // Ignore
func (f *File) MapToStruct() (err error) {
	f.Mu.Lock()
	defer f.Mu.Unlock()

	if err = viper.UnmarshalExact(f); err != nil {
		return
	}

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

	level.Debug(logging.DefaultLogger).Log("cleartext_networks", fmt.Sprintf("%+v", f.ClearTextList))
	level.Debug(logging.DefaultLogger).Log("nginx_monitoring", fmt.Sprintf("%+v", f.NginxMonitoring))

	if f.RelayDomains != nil {
		level.Debug(logging.DefaultLogger).Log(global.FeatureRelayDomains, fmt.Sprintf("%+v", f.RelayDomains))
	}

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

	err = newCfg.MapToStruct()

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
	if err = newCfgReload.MapToStruct(); err != nil {
		return
	}

	// Replace existing configuration
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&LoadableConfig)), unsafe.Pointer(newCfgReload))

	level.Info(logging.DefaultLogger).Log(global.LogKeyMsg, "Reloading configuration file finished")

	return
}
