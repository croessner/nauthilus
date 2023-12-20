package errors

import "errors"

type DetailedError struct {
	err      error
	guid     string
	details  string
	instance string
}

func (d *DetailedError) Error() string {
	return d.err.Error()
}

func (d *DetailedError) WithGUID(guid string) *DetailedError {
	if d == nil {
		return nil
	}

	d.guid = guid

	return d
}

func (d *DetailedError) WithDetail(detail string) *DetailedError {
	if d == nil {
		return nil
	}

	d.details = detail

	return d
}

func (d *DetailedError) WithInstance(instance string) *DetailedError {
	if d == nil {
		return nil
	}

	d.instance = instance

	return d
}

func (d *DetailedError) GetGUID() string {
	return d.guid
}

func (d *DetailedError) GetDetails() string {
	return d.details
}

func (d *DetailedError) GetInstance() string {
	return d.instance
}

func NewDetailedError(err string) *DetailedError {
	return &DetailedError{err: errors.New(err)}
}

// auth.

var (
	ErrNoPassDBs             = errors.New("assertion len(passDBs)>0 count=0")
	ErrUnknownService        = errors.New("unknown service")
	ErrAllBackendConfigError = errors.New("configuration errors in all Database sections")
)

// env.

var (
	ErrWrongVerboseLevel = errors.New("wrong verbose level")
	ErrWrongLDAPScope    = errors.New("wrong LDAP scope")
	ErrWrongPassDB       = errors.New("wrong passdb backend")
	ErrWrongFeature      = errors.New("wrong feature")
	ErrWrongDebugModule  = errors.New("wrong debug module")
)

// file.

var (
	ErrNoLDAPSection          = errors.New("no 'ldap:' section found")
	ErrNoLDAPSearchSection    = errors.New("no 'ldap::search:' section found")
	ErrNoSQLSection           = errors.New("no 'sql:' section found")
	ErrNoLDAPConfig           = errors.New("no 'ldap::config:' section found")
	ErrNoLDAPServerURIs       = errors.New("no 'ldap::config::server_uri' definition")
	ErrBruteForceTooManyRules = errors.New("too many rules in 'user'account' section")
	ErrCSRFSecretWrongSize    = errors.New("csrf secret must exactly be 32 bytes long")
	ErrCookieStoreAuthSize    = errors.New("cookie store auth key must exactly be 32 bytes")
	ErrCookieStoreEncSize     = errors.New("cookie store encryption key must exactly be 16, 24 or 32 bytes")
	ErrNoPasswordNonce        = errors.New("no 'password_nonce' defined")
	ErrNoLuaScriptPath        = errors.New("no 'lua::config:script_path' definition")
)

// ldap.

var (
	ErrLDAPConnect        = NewDetailedError("ldap_servers_connect_error")
	ErrLDAPConfig         = NewDetailedError("ldap_config_error")
	ErrNoLDAPSearchResult = NewDetailedError("ldap_no_search_result")
	ErrLDAPConnectTimeout = NewDetailedError("ldap_connect_timeout")
)

// sql.

var (
	ErrNoDatabaseConnection = NewDetailedError("no_database_connection")
	ErrUnsupportedSQLDriver = NewDetailedError("unsupported_sql_driver")
	ErrSQLConfig            = NewDetailedError("sql_config_error")
	ErrNoSQLRowsUpdated     = NewDetailedError("no_sql_updates")
)

// lua.

var (
	ErrLuaConfig               = NewDetailedError("lua_config_error")
	ErrBackendLuaWrongUserData = NewDetailedError("wrong_user_data_result")
	ErrBackendLua              = NewDetailedError("script_execution_failed")
)

// util.

var (
	ErrUnsupportedAlgorithm      = errors.New("unsupported hash algorithm")
	ErrUnsupportedPasswordOption = errors.New("unsupported password option")
)

// common.

var (
	ErrNoPassDBResult = errors.New("no pass Database result")
	ErrUnknownCause   = errors.New("something went wrong")
)

// bruteforce.

var (
	ErrRuleNoName             = errors.New("missing 'name' field in rule")
	ErrRuleNoIPv4AndIPv6      = errors.New("do not set 'ipv4' and 'ipv6' at the same time in a rule")
	ErrRuleMissingIPv4AndIPv6 = errors.New("neither 'ipv4' nor 'ipv6' specified in rule")
	ErrRuleNoCIDR             = errors.New("missing 'cidr' in rule")
	ErrRuleNoPeriod           = errors.New("missing 'period' in rule")
	ErrRuleNoFailedRequests   = errors.New("missing 'failed_requests' in rule")
	ErrWrongIPAddress         = errors.New("unable to parse IP address")
)

// hydra.

var (
	ErrNoLoginChallenge = errors.New("missing login challenge")
	ErrNoAccount        = errors.New("no account found")
	ErrUnknownJSON      = errors.New("unable to parse JSON response")
	ErrHTTPRequestGone  = errors.New("http request gone")
	ErrHydraNoClientId  = errors.New("no client_id returned from hydra server")
	ErrNoTLS            = errors.New("no tls connection")
	ErrTOTPCodeInvalid  = errors.New("totp code invalid")
	ErrNoTOTPCode       = errors.New("totp code not found")
)

// features.

var (
	ErrDNSResolver = errors.New("resolver failed")
)

// http.

var (
	ErrLanguageNotFound = errors.New("requested language not found")
	ErrUnauthorized     = errors.New("unauthorized")
)

// register.

var (
	ErrNotLoggedIn = errors.New("user not logged in")
	ErrNoTOTPURL   = errors.New("no TOTP URL found")
)

// webauthn.

var (
	ErrWebAuthnSessionData    = errors.New("no webauthn session data found")
	ErrNoDisplayName          = errors.New("no display name found")
	ErrUnknownDatabaseBackend = errors.New("unknown Database backend")
)

// Lua features.

var (
	ErrFeatureLuaNameMissing     = errors.New("feature 'name' sttribute missing")
	ErrFeatureLuaScriptPathEmpty = errors.New("feature 'script_path' attribute missing")
)

// Lua filters.

var (
	ErrNoFiltersDefined         = errors.New("no filters defined")
	ErrFilterLuaNameMissing     = errors.New("filter 'name' sttribute missing")
	ErrFilterLuaScriptPathEmpty = errors.New("filter 'script_path' attribute missing")
)
