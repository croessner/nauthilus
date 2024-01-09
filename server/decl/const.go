package decl

// Logging strings.
const (
	LogKeyGUID                   = "session"
	LogKeyMsg                    = "msg"
	LogKeyError                  = "error"
	LogKeyErrorDetails           = "error_details"
	LogKeyWarning                = "warn"
	LogKeyInstance               = "instance"
	LogKeyProtocol               = "protocol"
	LogKeyLocalIP                = "local_ip"
	LogKeyPort                   = "port"
	LogKeyTLSSecure              = "tls_protocol"
	LogKeyTLSCipher              = "tls_cipher"
	LogKeyAuthMethod             = "auth_method"
	LogKeyUsername               = "username"
	LogKeyOrigUsername           = "orig_username"
	LogKeyClientIP               = "client_ip"
	LogKeyClientPort             = "client_port"
	LogKeyClientHost             = "client_host"
	LogKeyLoginAttempts          = "current_password_retries"
	LogKeyGeoIPISOCode           = "geoip_iso_code"
	LogKeyGeoIPCountryName       = "geoip_country_name"
	LogKeyGeoIPCityName          = "geoip_city_name"
	LogKeyGeoIPIsInEuropeanUnion = "geoip_is_in_european_union"
	LogKeyGeoIPAccuracyRadius    = "geoip_accuracy_radius"
	LogKeyGeoIPLatitude          = "geoip_latitude"
	LogKeyGeoIPLongitude         = "geoip_longitude"
	LogKeyGeoIPMetroCode         = "geoip_metro_code"
	LogKeyGeoIPTimeZone          = "geoip_timezone"
	LogKeyUserAgent              = "user_agent"
	LogKeyClientID               = "client_id"
	LogKeyClientName             = "client_name"
	LogKeyPasswordsAccountSeen   = "account_passwords_seen"
	LogKeyPasswordsTotalSeen     = "total_passwords_seen"
	LogKeyUsedPassdbBackend      = "passdb_backend"
	LogKeyBruteForce             = "brute_force"
	LogKeyBruteForceName         = "brute_force_bucket"
	LogKeyFeatureName            = "feature"
	LogKeyStatusMessage          = "status_message"
	LogKeyStatus                 = "authenticated"
	LogKeyMode                   = "mode"
	LogKeySkip                   = "skip"
	LogKeyUriPath                = "uri_path"
	LogKeyAuthStatus             = "status"
	LogKeyAuthAccept             = "accept"
	LogKeyAuthReject             = "reject"
	LogKeyAuthChallenge          = "challenge"
	LogKeyAuthSubject            = "subject"
	LogKeyRedirectTo             = "redirect_to"
	LogKeyMethod                 = "http_method"
	LogKeyHTTPStatus             = "http_status"
	LogKeyLatency                = "latency"
	LogKeyStatsAlloc             = "alloc"
	LogKeyStatsHeapAlloc         = "heap_alloc"
	LogKeyStatsHeapInUse         = "heap_in_use"
	LogKeyStatsHeapIdle          = "heap_idle"
	LogKeyStatsStackInUse        = "stack_in_use"
	LogKeyStatsStackSys          = "stack_sys"
	LogKeyStatsSys               = "sys"
	LogKeyStatsTotalAlloc        = "total_alloc"
	LogKeyStatsNumGC             = "num_gc"
	LogKeyLDAPPoolName           = "pool"
	LogKeyLoginSkip              = "login_skip"

	NotAvailable = "N/A"
)

// Defaults.
const (
	Localhost4 = "127.0.0.1"
	Localhost6 = "::1"

	HTTPAddress = "127.0.0.1:9080"

	PasswordFail = "Invalid login or password"

	TempFailDefault   = "Temporary server problem, try again later"
	TempFailNoTLS     = "TLS transport encryption required"
	TempFailEmptyUser = "No username given"

	TempFailCode = "451 4.3.0"

	InstanceName       = "nauthilus1"
	SMTPBackendAddress = Localhost4
	SMTPBackendPort    = 5871
	IMAPBackendAddress = Localhost4
	IMAPBackendPort    = 9931
	WaitDelay          = 1
	MaxLoginAttempts   = 15
	GeoIPPath          = "/usr/share/GeoIP/GeoLite2-City.mmdb"

	LDAPIdlePoolSize = 2
	LDAPMaxRetries   = 9

	SQLMaxConns     = 10
	SQLMaxIdleConns = 10

	RedisAddress     = Localhost4
	RedisPort        = 6379
	RedisPrefix      = "nt_"
	RedisPosCacheTTL = 3600
	RedisNegCacheTTL = 3600

	StatsDelay = 60

	MaxChannelSize = 500
)

// Log level.
const (
	LogLevelNone  = iota
	LogLevelError = iota
	LogLevelWarn  = iota
	LogLevelInfo  = iota
	LogLevelDebug = iota
)

// Supported backends.
const (
	BackendUnknown  Backend = iota
	BackendCache    Backend = iota
	BackendLDAP     Backend = iota
	BackendSQL      Backend = iota
	BackendMySQL    Backend = iota
	BackendPostgres Backend = iota
	BackendLua      Backend = iota
)

const (
	BackendUnknownName  = "unknown"
	BackendCacheName    = "cache"
	BackendLDAPName     = "ldap"
	BackendSQLName      = "sql"
	BackendMySQLName    = "mysql"
	BackendPostgresName = "postgresql"
	BackendLuaName      = "lua"
)

// Supported features.
const (
	FeatureTLSEncryption = "tls_encryption"
	FeatureGeoIP         = "geoip"
	FeatureRBL           = "rbl"
	FeatureRelayDomains  = "relay_domains"
	FeatureLua           = "lua"
)

// Statistics label for the loin counter.
const (
	LabelSuccess = "success"
	LabelFailure = "failure"
)

// Custom defined types for claims.
const (
	ClaimTypeString  = "string"
	ClaimTypeBoolean = "boolean"
	ClaimTypeFloat   = "float"
	ClaimTypeInteger = "integer"
)

// Pre-definied protocols with a fixed semantic.
const (
	ProtoSMTP     = "smtp"
	ProtoHTTP     = "http"
	ProtoOryHydra = "ory-hydra"
	ProtoDefault  = "default"
)

const SliceWithOneElement = 0

// Authentication results.
const (
	AuthResultUnset    AuthResult = iota
	AuthResultOK       AuthResult = iota
	AuthResultFail     AuthResult = iota
	AuthResultTempFail AuthResult = iota

	AuthResultEmptyUsername AuthResult = iota
	AuthResultEmptyPassword AuthResult = iota

	AuthResultFeatureRBL         AuthResult = iota
	AuthResultFeatureTLS         AuthResult = iota
	AuthResultFeatureRelayDomain AuthResult = iota
	AuthResultFeatureLua         AuthResult = iota
)

// Redis hash keys.
const (
	RedisBruteForceHashKey     = "BRUTEFORCE"
	RedisUserHashKey           = "USER"
	RedisMetricsCounterHashKey = "COUNTER"
	RedisPwHashKey             = "PW_HIST"
)

const ImageCopyright = "Logo (c) by Roessner-Network-Solutions"

// Categories and services.
const (
	CatMail       = "mail"
	CatHTTP       = "http"
	CatGeneric    = "generic"
	CatCache      = "cache"
	CatBruteForce = "bruteforce"

	ServNginx     = "nginx"
	ServSaslauthd = "saslauthd"
	ServDovecot   = "dovecot"
	ServBasicAuth = "basicauth"
	ServOryHydra  = "ory_hydra"
	ServUserInfo  = "user"
	ServFlush     = "flush"
	ServList      = "list"
)

const TwoFAv1Root = "/2fa/v1"

const (
	ScopeOpenId        = "openid"
	ScopeOfflineAccess = "offline_access"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeAddress       = "address"
	ScopePhone         = "phone"
	ScopeGroups        = "groups"
)

const (
	ClaimName                = "name"
	ClaimGivenName           = "given_name"
	ClaimFamilyName          = "family_name"
	ClaimMiddleName          = "middle_name"
	ClaimNickName            = "nickname"
	ClaimPreferredUserName   = "preferred_username"
	ClaimWebsite             = "website"
	ClaimProfile             = "profile"
	ClaimPicture             = "picture"
	ClaimEmail               = "email"
	ClaimEmailVerified       = "email_verified"
	ClaimGender              = "gender"
	ClaimBirtDate            = "birthdate"
	ClaimZoneInfo            = "zoneinfo"
	ClaimLocale              = "locale"
	ClaimPhoneNumber         = "phone_number"
	ClaimPhoneNumberVerified = "phone_number_verified"
	ClaimAddress             = "address"
	ClaimUpdatedAt           = "updated_at"
	ClaimGroups              = "groups"
)

// Keys for the encrypted session cookie.
const (
	CookieAccount      = "account"
	CookieHaveTOTP     = "already_have_totp"
	CookieTOTPURL      = "totp_url"
	CookieUserBackend  = "user_backend"
	CookieUniqueUserID = "unique_userid"
	CookieDisplayName  = "display_name"
	CookieLang         = "lang"
	CookieUsername     = "username"
	CookieAuthResult   = "auth_result"
	CookieSubject      = "subject"
	CookieRemember     = "remember"
	CookieRegistration = "webauthn_registration"

	SessionName = "Nauthilus_session"
)

const (
	GUIDKey         = "guid"
	CSRFTokenKey    = "csrf"
	LocalizedKey    = "localizer"
	ClientIPKey     = "client_ip"
	DataExchangeKey = "data_exchange"
)

const LDAPSingleValue = 0

const DistinguishedName = "dn"

// LDAP change types.
const (
	LDAPSearch    LDAPCommand = iota
	LDAPModifyAdd LDAPCommand = iota
)

// Tri-state for LDAP connections.
const (
	LDAPStateClosed LDAPState = iota
	LDAPStateFree   LDAPState = iota
	LDAPStateBusy   LDAPState = iota
)

const (
	LDAPPoolUnknown = iota
	LDAPPoolLookup  = iota
	LDAPPoolAuth    = iota
)

const LDAPPoolExhausted = -1

const InvalidCode = "The TOTP code is invalid"

// Supported salted hashes.
const (
	SSHA256 Algorithm = iota
	SSHA512 Algorithm = iota
)

// Encoding schema for encrypted passwords.
const (
	B64 PasswordOption = iota
	HEX PasswordOption = iota
)

const (
	DbgNone      DbgModule = iota
	DbgAll       DbgModule = iota
	DbgAuth      DbgModule = iota
	DbgHydra     DbgModule = iota
	DbgWebAuthn  DbgModule = iota
	DbgStats     DbgModule = iota
	DbgWhitelist DbgModule = iota
	DbgLDAP      DbgModule = iota
	DbgLDAPPool  DbgModule = iota
	DbgSQL       DbgModule = iota
	DbgCache     DbgModule = iota
	DbgBf        DbgModule = iota
	DbgRBL       DbgModule = iota
	DbgAction    DbgModule = iota
	DbgFeature   DbgModule = iota
	DbgLua       DbgModule = iota
	DbgFilter    DbgModule = iota
)

const (
	DbgNoneName      = "none"
	DbgAllName       = "all"
	DbgAuthName      = "auth"
	DbgHydraName     = "hydra"
	DbgWebAuthnName  = "webauthn"
	DbgStatsName     = "statistics"
	DbgWhitelistName = "whitelist"
	DbgLDAPName      = "ldap"
	DbgLDAPPoolName  = "ldappool"
	DbgSQLName       = "sql"
	DbgCacheName     = "cache"
	DbgBfName        = "brute_force"
	DbgRBLName       = "rbl"
	DbgActionName    = "action"
	DbgFeatureName   = "feature"
	DbgLuaName       = "lua"
	DbgFilterName    = "filter"
)

const (
	LuaActionNone         LuaAction = iota
	LuaActionBruteForce   LuaAction = iota
	LuaActionRBL          LuaAction = iota
	LuaActionTLS          LuaAction = iota
	LuaActionRelayDomains LuaAction = iota
	LuaActionLua          LuaAction = iota
	LuaActionPost         LuaAction = iota
)

const (
	LuaActionBruteForceName   = "brute_force"
	LuaActionRBLName          = "rbl"
	LuaActionTLSName          = "tls_encryption"
	LuaActionRelayDomainsName = "relay_domains"
	LuaActionLuaName          = "lua"
	LuaActionPostName         = "post"
)

const SamePasswordsDifferentAccountLimit = uint(5)

const LuaMaxExecutionTime = 120

const (
	LuaCommandPassDB       LuaCommand = iota
	LuaCommandListAccounts LuaCommand = iota
	LuaCommandAddMFAValue  LuaCommand = iota
)

const (
	LuaFnCtxSet       = "context_set"
	LuaFnCtxGet       = "context_get"
	LuaFnCtxDelete    = "context_delete"
	LuaFnAddCustomLog = "custom_log_add"

	LuaFnBackendVerifyPassword = "nauthilus_backend_verify_password"
	LuaFnBackendListAccounts   = "nauthilus_backend_list_accounts"
	LuaFnBackendAddTOTPSecret  = "nauthilus_backend_add_totp"

	LuaModUtil = "nauthilus_util"

	LuaFnCallFeature = "nauthilus_call_feature"
	LuaFnCallAction  = "nauthilus_call_action"
	LuaFnCallFilter  = "nauthilus_call_filter"
)

const (
	LuaDefaultTable = "nauthilus"
	LuaSuccess      = "success"
	LuaFail         = "fail"

	LuaFeatureTriggerNo  = "FEATURE_TRIGGER_NO"
	LuaFeatureTriggerYes = "FEATURE_TRIGGER_YES"
	LuaFeatureAbortNo    = "FEATURES_ABORT_NO"
	LuaFeatureAbortYes   = "FEATURES_ABORT_YES"
	LuaFeatureResultOk   = "FEATURE_RESULT_OK"
	LuaFeatureResultFail = "FEATURE_RESULT_FAIL"

	LuaActionResultOk   = "ACTION_RESULT_OK"
	LuaActionResultFail = "ACTION_RESULT_FAIL"

	LuaBackendResultOk   = "BACKEND_RESULT_OK"
	LuaBackendResultFail = "BACKEND_RESULT_FAIL"

	LuaFilterAccept     = "FILTER_ACCEPT"
	LuaFilterREJECT     = "FILTER_REJECT"
	LuaFilterResultOk   = "FILTER_RESULT_OK"
	LuaFilterResultFail = "FILTER_RESULT_FAIL"
)

const (
	LuaRequestDebug               = "debug"
	LuaRequestNoAuth              = "no_auth"
	LuaRequestService             = "service"
	LuaRequestRepeating           = "repeating"
	LuaRequestAuthenticated       = "authenticated"
	LuaRequestUserFound           = "user_found"
	LuaRequestBruteForceCounter   = "brute_force_counter"
	LuaRequestBruteForceBucket    = "brute_force_bucket"
	LuaRequestFeature             = "feature"
	LuaRequestSession             = "session"
	LuaRequestClientIP            = "client_ip"
	LuaRequestClientPort          = "client_port"
	LuaRequestClientNet           = "client_net"
	LuaRequestClientHost          = "client_hostname"
	LuaRequestClientID            = "client_id"
	LuaRequestLocalIP             = "local_ip"
	LuaRequestLocalPort           = "local_port"
	LuaRequestUsername            = "username"
	LuaRequestAccount             = "account"
	LuaRequestUniqueUserID        = "unique_user_id"
	LuaRequestDisplayName         = "display_name"
	LuaRequestPassword            = "password"
	LuaRequestProtocol            = "protocol"
	LuaRequestUserAgent           = "user_agent"
	LuaRequestXSSL                = "ssl"
	LuaRequestXSSSLSessionID      = "ssl_session_id"
	LuaRequestXSSLClientVerify    = "ssl_client_verify"
	LuaRequestXSSLClientDN        = "ssl_client_dn"
	LuaRequestXSSLClientCN        = "ssl_client_cn"
	LuaRequestXSSLIssuer          = "ssl_issuer"
	LuaRequestXSSLClientNotBefore = "ssl_client_not_before"
	LuaRequestXSSLClientNotAfter  = "ssl_client_not_after"
	LuaRequestXSSLSubjectDN       = "ssl_subject_dn"
	LuaRequestXSSLIssuerDN        = "ssl_issuer_dn"
	LuaRequestXSSLClientSubjectDN = "ssl_client_subject_dn"
	LuaRequestXSSLClientIssuerDN  = "ssl_client_issuer_dn"
	LuaRequestXSSLProtocol        = "ssl_protocol"
	LuaRequestXSSLCipher          = "ssl_cipher"
	LuaRequestTOTPSecret          = "totp_secret"
)
