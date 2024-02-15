package global

const (
	// LogKeyGUID represents the session identifier used in log entries.
	LogKeyGUID = "session"

	// LogKeyMsg represents the message content in log entries.
	LogKeyMsg = "msg"

	// LogKeyError represents error information in log entries.
	LogKeyError = "error"

	// LogKeyErrorDetails represents additional error details in log entries.
	LogKeyErrorDetails = "error_details"

	// LogKeyWarning represents warning information in log entries.
	LogKeyWarning = "warn"

	// LogKeyInstance represents instance identification in log entries.
	LogKeyInstance = "instance"

	// LogKeyProtocol represents the network protocol used, logged in log entries.
	LogKeyProtocol = "protocol"

	// LogKeyLocalIP represents the local IP address, logged in log entries.
	LogKeyLocalIP = "local_ip"

	// LogKeyPort identifies the port where an operation occurred.
	LogKeyPort = "port"

	// LogKeyTLSSecure represents whether a TLS secure connection is being used, logged in log entries.
	LogKeyTLSSecure = "tls_protocol"

	// LogKeyTLSCipher represents the cipher used in the TLS connection, logged in log entries.
	LogKeyTLSCipher = "tls_cipher"

	// LogKeyAuthMethod represents the authentication method used for a session.
	LogKeyAuthMethod = "auth_method"

	// LogKeyUsername represents the username being used for authentication during a session.
	LogKeyUsername = "username"

	// LogKeyOrigUsername represents the original username (prior to any modifications) used for a session.
	LogKeyOrigUsername = "orig_username"

	// LogKeyClientIP represents the IP address of the client.
	LogKeyClientIP = "client_ip"

	// LogKeyClientPort represents the port number of the client.
	LogKeyClientPort = "client_port"

	// LogKeyClientHost represents the hostname of the client.
	LogKeyClientHost = "client_host"

	// LogKeyLoginAttempts represents the number of current password retry attempts.
	LogKeyLoginAttempts = "current_password_retries"

	// LogKeyUserAgent represents the user-agent string of the client.
	LogKeyUserAgent = "user_agent"

	// LogKeyClientID represents the unique client ID.
	LogKeyClientID = "client_id"

	// LogKeyClientName represents the client name.
	LogKeyClientName = "client_name"

	// LogKeyPasswordsAccountSeen represents the number of passwords seen for an account.
	LogKeyPasswordsAccountSeen = "account_passwords_seen"

	// LogKeyPasswordsTotalSeen represents the total number of passwords seen.
	LogKeyPasswordsTotalSeen = "total_passwords_seen"

	// LogKeyUsedPassdbBackend represents the backend used for password database operations.
	LogKeyUsedPassdbBackend = "passdb_backend"

	// LogKeyBruteForce indicates whether a brute force attempt has been detected.
	LogKeyBruteForce = "brute_force"

	// LogKeyBruteForceName represents the name of the bucket used for brute force detection.
	LogKeyBruteForceName = "brute_force_bucket"

	// LogKeyFeatureName represents the name of a feature for feature status logging.
	LogKeyFeatureName = "feature"

	// LogKeyStatusMessage represents a status message for an operation.
	LogKeyStatusMessage = "status_message"

	// LogKeyStatus represents the general status (like authentication) for logging.
	LogKeyStatus = "authenticated"

	// LogKeyMode represents the mode of the operation.
	LogKeyMode = "mode"

	// LogKeySkip indicates whether an operation was skipped.
	LogKeySkip = "skip"

	// LogKeyUriPath represents the URI path of a request.
	LogKeyUriPath = "uri_path"

	// LogKeyAuthStatus represents the status of the authentication process.
	LogKeyAuthStatus = "status"

	// LogKeyAuthAccept indicates if the authentication was accepted.
	LogKeyAuthAccept = "accept"

	// LogKeyAuthReject indicates if the authentication was rejected.
	LogKeyAuthReject = "reject"

	// LogKeyAuthChallenge represents any challenges issued during an authentication process.
	LogKeyAuthChallenge = "challenge"

	// LogKeyAuthSubject represents the subject identifier in an authentication process.
	LogKeyAuthSubject = "subject"

	// LogKeyRedirectTo represents the target of a redirection operation.
	LogKeyRedirectTo = "redirect_to"

	// LogKeyMethod represents the HTTP method for request logging.
	LogKeyMethod = "http_method"

	// LogKeyHTTPStatus represents the HTTP status code for logging.
	LogKeyHTTPStatus = "http_status"

	// LogKeyLatency represents the latency of a network operation for performance logging.
	LogKeyLatency = "latency"

	// LogKeyStatsAlloc represents the stats for allocations logged.
	LogKeyStatsAlloc = "stats_alloc"

	// LogKeyStatsHeapAlloc represents the heap allocations in memory stats logging.
	LogKeyStatsHeapAlloc = "stats_heap_alloc"

	// LogKeyStatsHeapInUse represents heap memory currently in use for memory stats logging.
	LogKeyStatsHeapInUse = "stats_heap_in_use"

	// LogKeyStatsHeapIdle represents heap memory currently idling for memory stats logging.
	LogKeyStatsHeapIdle = "stats_heap_idle"

	// LogKeyStatsStackInUse represents stack memory currently in use for memory stats logging.
	LogKeyStatsStackInUse = "stats_stack_in_use"

	// LogKeyStatsStackSys represents system level stats about the program's stack.
	LogKeyStatsStackSys = "stats_stack_sys"

	// LogKeyStatsSys represents general system level stats about the program.
	LogKeyStatsSys = "stats_sys"

	// LogKeyStatsTotalAlloc represents total allocation in memory stats logging.
	LogKeyStatsTotalAlloc = "stats_total_alloc"

	// LogKeyStatsNumGC indicates the number of GC runs.
	LogKeyStatsNumGC = "stats_num_gc"

	// LogKeyStatsMallocs represents the number of allocations done by 'malloc' system call
	LogKeyStatsMallocs = "stats_mallocs"

	// LogKeyStatsFrees represents the number of deallocations done by 'free' system call
	LogKeyStatsFrees = "stats_frees"

	// LogKeyStatsHeapSys represents the heap stats of a system
	LogKeyStatsHeapSys = "stats_heap_sys"

	// LogKeyStatsHeapReleased represents the amount of heap memory released back to the OS
	LogKeyStatsHeapReleased = "stats_heap_released"

	// LogKeyStatsGCSys represents stats about the Go runtime's garbage collector
	LogKeyStatsGCSys = "stats_gc_sys"

	// LogKeyLDAPPoolName represents the name of the LDAP pool
	LogKeyLDAPPoolName = "pool"

	// LogKeyLoginSkip indicates whether login was skipped.
	LogKeyLoginSkip = "login_skip"

	// LogKeyLuaScripttimeout represents timeout setting for lua scripts
	LogKeyLuaScripttimeout = "lua_script_timeout"

	// LogKeyNgxBackendIP represents the IP address of the nginx backend server.
	LogKeyNgxBackendIP = "nginx_backend_ip"

	// LogKeyNgxBackendPort represents the port of the nginx backend server.
	LogKeyNgxBackendPort = "nginx_backend_port"

	// NotAvailable is used when data for a particular field is not available.
	NotAvailable = "N/A"
)

// Defaults.
const (

	// Localhost4 is a shorthand for IPv4 localhost address
	Localhost4 = "127.0.0.1"

	// Localhost6 is a shorthand for IPv6 localhost address
	Localhost6 = "::1"

	// HTTPAddress is the default address for the HTTP server
	HTTPAddress = "127.0.0.1:9080"

	// PasswordFail is the message when user authentication fails
	PasswordFail = "Invalid login or password"

	// TempFailDefault is the default temporary failure message
	TempFailDefault = "Temporary server problem, try again later"

	// TempFailNoTLS is the failure message when TLS encryption is required but not provided
	TempFailNoTLS = "TLS transport encryption required"

	// TempFailEmptyUser is the failure message when no username is provided
	TempFailEmptyUser = "No username given"

	// TempFailCode is the SMTP error code for a temporary failure
	TempFailCode = "451 4.3.0"

	// InstanceName is the name of the server instance
	InstanceName = "nauthilus1"

	// SMTPBackendAddress is the default SMTP backend address
	SMTPBackendAddress = Localhost4

	// SMTPBackendPort is the default SMTP backend port
	SMTPBackendPort = 5871

	// IMAPBackendAddress is the default IMAP backend address
	IMAPBackendAddress = Localhost4

	// IMAPBackendPort is the default IMAP backend port
	IMAPBackendPort = 9931

	// POP3BackendAddress is the default POP3 backend address
	POP3BackendAddress = Localhost4

	// POP3BackendPort is the default POP3 backend port
	POP3BackendPort = 9951

	// WaitDelay is the default delay (in seconds) between reconnection attempts
	WaitDelay = 1

	// MaxLoginAttempts is the maximum allowed number of login attempts
	MaxLoginAttempts = 15

	// LDAPIdlePoolSize is the number of idle connections in LDAP connection pool
	LDAPIdlePoolSize = 2

	// LDAPMaxRetries is the maximum number of retries for a failed LDAP operation
	LDAPMaxRetries = 9

	// RedisAddress is the default Redis server address
	RedisAddress = Localhost4

	// RedisPort is the default Redis server port
	RedisPort = 6379

	// RedisPrefix is the prefix for keys stored in Redis
	RedisPrefix = "nt_"

	// RedisPosCacheTTL is the expiry time (in seconds) for positive cache entries in Redis
	RedisPosCacheTTL = 3600

	// RedisNegCacheTTL is the expiry time (in seconds) for negative cache entries in Redis
	RedisNegCacheTTL = 3600

	// StatsDelay is the delay (in seconds) between collecting statistical data
	StatsDelay = 60

	// NginxMonitoringDelay is the delay (in seconds) between keep-alive checks
	NginxMonitoringDelay = 60

	// LDAPConnectTimeout is the connection timeout (in seconds) for the LDAP server
	LDAPConnectTimeout = 30

	// MaxChannelSize is the maximum size of message channels
	MaxChannelSize = 500

	// MaxLuaStatePoolSize is the maximum size of the Lua state pool
	MaxLuaStatePoolSize = 10000

	// MaxActionWorkers is the maximum number of action workers
	MaxActionWorkers = 10
)

// Log level.
const (
	// LogLevelNone is the iota constant representing no logs
	LogLevelNone = iota

	// LogLevelError is the iota constant for error logs
	LogLevelError

	// LogLevelWarn is the iota constant for warning logs
	LogLevelWarn

	// LogLevelInfo is the iota constant for info logs
	LogLevelInfo

	// LogLevelDebug is the iota constant for debug logs
	LogLevelDebug
)

// Supported backends.
const (
	// BackendUnknown represents an unknown backend
	BackendUnknown Backend = iota

	// BackendCache represents a Cache backend
	BackendCache

	// BackendLDAP represents an LDAP backend
	BackendLDAP

	// BackendLua represents a Lua backend
	BackendLua

	// BackendLocalCache represents the local in-memory cache localcache.LocalCache
	BackendLocalCache
)

const (
	// BackendUnknownName refers to an unidentified backend
	BackendUnknownName = "unknown"

	// BackendCacheName represents a cache backend
	BackendCacheName = "cache"

	// BackendLDAPName indicates an LDAP backend
	BackendLDAPName = "ldap"

	// BackendLuaName refers to a Lua backend
	BackendLuaName = "lua"

	// BackendLocalCacheName refers to th elocal in memory localcache.LocalCache.
	BackendLocalCacheName = "memory"
)

// Supported features.
const (
	// FeatureTLSEncryption is a constant for the string "tls_encryption"
	FeatureTLSEncryption = "tls_encryption"

	// FeatureRBL is a constant for the string "rbl"
	FeatureRBL = "rbl"

	// FeatureRelayDomains is a constant for the string "relay_domains"
	FeatureRelayDomains = "relay_domains"

	// FeatureLua is a constant for the string "lua"
	FeatureLua = "lua"

	// FeatureNginxMonitoring enables custom a Nginx backend list with fail-state monitoring
	FeatureNginxMonitoring = "nginx_monitoring"
)

// Statistics label for the loin counter.
const (
	// LabelSuccess represents a success label.
	LabelSuccess = "success"

	// LabelFailure represents a failure label.
	LabelFailure = "failure"
)

// Custom defined types for claims.
const (
	// ClaimTypeString constant represents a string claim type
	ClaimTypeString = "string"

	// ClaimTypeBoolean constant represents a boolean claim type
	ClaimTypeBoolean = "boolean"

	// ClaimTypeFloat constant represents a float claim type
	ClaimTypeFloat = "float"

	// ClaimTypeInteger constant represents an integer claim type
	ClaimTypeInteger = "integer"
)

// Pre-definied protocols with a fixed semantic.
const (
	// ProtoSMTP corresponds to the "smtp" protocol
	ProtoSMTP = "smtp"

	// ProtoIMAP corresponds to the "smtp" protocol
	ProtoIMAP = "imap"

	// ProtoPOP3 corresponds to the "smtp" protocol
	ProtoPOP3 = "pop3"

	// ProtoHTTP corresponds to the "http" protocol
	ProtoHTTP = "http"

	// ProtoOryHydra corresponds to the "ory-hydra" protocol
	ProtoOryHydra = "ory-hydra"

	// ProtoDefault corresponds to the default protocol
	ProtoDefault = "default"
)

// SliceWithOneElement is a constant representing the index used to access a single element from a slice or array.
// It is used in various places throughout the code to retrieve a single element from a slice or array,
// assuming that the slice or array contains only one element.
const SliceWithOneElement = 0

// Authentication results.
const (
	// AuthResultUnset is the unset state for authentication.
	AuthResultUnset AuthResult = iota

	// AuthResultOK denotes successful authentication.
	AuthResultOK

	// AuthResultFail denotes unsuccessful/failure in authentication.
	AuthResultFail

	// AuthResultTempFail denotes a temporary failure in authentication.
	AuthResultTempFail

	// AuthResultEmptyUsername denotes a failure due to an empty username.
	AuthResultEmptyUsername

	// AuthResultEmptyPassword denotes a failure due to an empty password.
	AuthResultEmptyPassword

	// AuthResultFeatureRBL represents a status linked with a Real-time Blackhole List feature.
	AuthResultFeatureRBL

	// AuthResultFeatureTLS represents a status linked with a Transport Layer Security feature.
	AuthResultFeatureTLS

	// AuthResultFeatureRelayDomain represents a status linked with a relay domain feature.
	AuthResultFeatureRelayDomain

	// AuthResultFeatureLua denotes a status linked with a Lua scripting feature.
	AuthResultFeatureLua
)

// Redis hash keys.
const (
	// RedisBruteForceHashKey represents the key used for brute force attempts in Redis.
	RedisBruteForceHashKey = "BRUTEFORCE"

	// RedisUserHashKey represents the key used for user data in Redis.
	RedisUserHashKey = "USER"

	// RedisMetricsCounterHashKey represents the key used for a metrics counter in Redis.
	RedisMetricsCounterHashKey = "COUNTER"

	// RedisPwHashKey represents the key used for password history in Redis.
	RedisPwHashKey = "PW_HIST"
)

// ImageCopyright represents the copyright statement for a logo.
const ImageCopyright = "Logo (c) by Roessner-Network-Solutions"

// Categories and services.
const (
	// CatMail is a constant for the "mail" category.
	CatMail = "mail"

	// CatHTTP is a constant for the "http" category.
	CatHTTP = "http"

	// CatGeneric is a constant for the "generic" category.
	CatGeneric = "generic"

	// CatCache is a constant for the "cache" category.
	CatCache = "cache"

	// CatBruteForce is a constant for the "bruteforce" category.
	CatBruteForce = "bruteforce"

	// ServNginx is a constant for the "nginx" service.
	ServNginx = "nginx"

	// ServSaslauthd is a constant for the "saslauthd" service.
	ServSaslauthd = "saslauthd"

	// ServDovecot is a constant for the "dovecot" service.
	ServDovecot = "dovecot"

	// ServBasicAuth is a constant for the "basicauth" service.
	ServBasicAuth = "basicauth"

	// ServOryHydra is a constant for the "ory_hydra" service.
	ServOryHydra = "ory_hydra"

	// ServUserInfo is a constant for the "user" service.
	ServUserInfo = "user"

	// ServJSON is a constant for the "json" service.
	ServJSON = "json"

	// ServFlush is a constant for the "flush" service.
	ServFlush = "flush"

	// ServList is a constant for the "list" service.
	ServList = "list"
)

// TwoFAv1Root is the root path for the two-factor authentication (2FA) version 1 endpoints.
const TwoFAv1Root = "/2fa/v1"

const (
	// ScopeOpenId constant represents the OAuth 2.0 OpenID scope.
	ScopeOpenId = "openid"

	// ScopeOfflineAccess constant represents the OAuth 2.0 offline access scope.
	ScopeOfflineAccess = "offline_access"

	// ScopeProfile constant represents the OAuth 2.0 user profile access scope.
	ScopeProfile = "profile"

	// ScopeEmail constant represents the OAuth 2.0 user email access scope.
	ScopeEmail = "email"

	// ScopeAddress constant represents the OAuth 2.0 user address access scope.
	ScopeAddress = "address"

	// ScopePhone constant represents the OAuth 2.0 user phone access scope.
	ScopePhone = "phone"

	// ScopeGroups constant represents the OAuth 2.0 user group access scope.
	ScopeGroups = "groups"
)

const (
	// ClaimName represents the name claim
	ClaimName = "name"

	// ClaimGivenName represents the given name claim
	ClaimGivenName = "given_name"

	// ClaimFamilyName represents the family name claim
	ClaimFamilyName = "family_name"

	// ClaimMiddleName represents the middle name claim
	ClaimMiddleName = "middle_name"

	// ClaimNickName represents the nickname claim
	ClaimNickName = "nickname"

	// ClaimPreferredUserName represents the preferred username claim
	ClaimPreferredUserName = "preferred_username"

	// ClaimWebsite represents the website claim
	ClaimWebsite = "website"

	// ClaimProfile represents the profile claim
	ClaimProfile = "profile"

	// ClaimPicture represents the picture claim
	ClaimPicture = "picture"

	// ClaimEmail represents the email claim
	ClaimEmail = "email"

	// ClaimEmailVerified represents the email verified claim
	ClaimEmailVerified = "email_verified"

	// ClaimGender represents the gender claim
	ClaimGender = "gender"

	// ClaimBirtDate represents the birth date claim
	ClaimBirtDate = "birthdate"

	// ClaimZoneInfo represents the zone information claim
	ClaimZoneInfo = "zoneinfo"

	// ClaimLocale represents the locale claim
	ClaimLocale = "locale"

	// ClaimPhoneNumber represents the phone number claim
	ClaimPhoneNumber = "phone_number"

	// ClaimPhoneNumberVerified represents the phone number verified claim
	ClaimPhoneNumberVerified = "phone_number_verified"

	// ClaimAddress represents the address claim
	ClaimAddress = "address"

	// ClaimUpdatedAt represents the update time claim
	ClaimUpdatedAt = "updated_at"

	// ClaimGroups represents the groups claim
	ClaimGroups = "groups"
)

// Keys for the encrypted session cookie.
const (
	// CookieAccount constant refers to the user's account
	CookieAccount = "account"

	// CookieHaveTOTP constant indicates whether the user has Time-Based One-Time Password (TOTP) already
	CookieHaveTOTP = "already_have_totp"

	// CookieTOTPURL constant is used for the URL related to TOTP
	CookieTOTPURL = "totp_url"

	// CookieUserBackend constant is related to the user backend
	CookieUserBackend = "user_backend"

	// CookieUniqueUserID constant represents a unique ID of the user
	CookieUniqueUserID = "unique_userid"

	// CookieDisplayName constant keeps track of the user's display name
	CookieDisplayName = "display_name"

	// CookieLang constant specifies the language preference of the user
	CookieLang = "lang"

	// CookieUsername constant keeps track of the user's username
	CookieUsername = "username"

	// CookieAuthResult constant stores the result of authentication
	CookieAuthResult = "auth_result"

	// CookieSubject constant can store the subject related to an authentication or authorization process
	CookieSubject = "subject"

	// CookieRemember constant indicates whether the user chose to be remembered in the session
	CookieRemember = "remember"

	// CookieRegistration constant could be used during the web authentication registration process
	CookieRegistration = "webauthn_registration"

	// SessionName constant is for the name of the session
	SessionName = "Nauthilus_session"
)

const (
	// CtxGUIDKey is used as a key to store the session's unique identifier in session.Store
	CtxGUIDKey = "guid"

	// CtxCSRFTokenKey is used as a key to store the session's CSRF token in session.Store
	CtxCSRFTokenKey = "csrf"

	// CtxLocalizedKey is used as a key to store the session's localization data in session.Store
	CtxLocalizedKey = "localizer"

	// CtxClientIPKey is used as a key to store the session's client IP address in session.Store
	CtxClientIPKey = "client_ip"

	// CtxDataExchangeKey is used as a key to store the session's data exchange information in session.Store
	CtxDataExchangeKey = "data_exchange"

	// CtxLocalCacheAuthKey is used as a key to store an Authentication structure for an authenticated user.
	CtxLocalCacheAuthKey = "local_cache_auth"
)

// LDAPSingleValue represents the index used to access the single value of an attribute in the LDAP response.
const LDAPSingleValue = 0

// DistinguishedName represents the distinguished name attribute used in LDAP operations.
const DistinguishedName = "dn"

// LDAP change types.
const (
	// LDAPSearch is a constant representing a command used for LDAP search
	LDAPSearch LDAPCommand = iota

	// LDAPModifyAdd is a constant representing a command used for LDAP add modification
	LDAPModifyAdd
)

// Tri-state for LDAP connections.
const (
	// LDAPStateClosed represents the state of an LDAP when it's not connected
	LDAPStateClosed LDAPState = iota

	// LDAPStateFree represents the state of an LDAP connection that is available for use
	LDAPStateFree

	// LDAPStateBusy represents the state of an LDAP connection that is currently in use
	LDAPStateBusy
)

const (
	// LDAPPoolUnknown represents an unknown LDAP pool value
	LDAPPoolUnknown = iota

	// LDAPPoolLookup is used to specify an LDAP pool for lookups
	LDAPPoolLookup

	// LDAPPoolAuth is used to specify an LDAP pool for authentication
	LDAPPoolAuth
)

// LDAPPoolExhausted represents the constant value used to indicate that the LDAP connection pool is exhausted and there are no available connections.
// When the connection pool is exhausted, the application needs to wait for a free connection before continuing.
// Example usage:
// In the `waitForFreeConnection` function:
//
//	if ldapConnIndex == global.LDAPPoolExhausted {
//	    // Pool exhausted. Waiting for a free connection.
//	    ldapWaitGroup.Wait()
//	    // Pool got free connections.
//	}
//
// In the `getConnection` function:
//
//	for {
//	    // ...
//	    connNumber = l.processConnection(index, guid)
//	    if connNumber != global.LDAPPoolExhausted {
//	        break
//	    }
//	    l.waitForFreeConnection(guid, connNumber, ldapWaitGroup)
//	}
//
// In the `processConnection` function:
//
//	if l.conn[index].state == global.LDAPPoolExhausted {
//	    // Connection is already in use. Skip to the next.
//	    return global.LDAPPoolExhausted
//	}
//	// ... (additional code omitted for brevity)
const LDAPPoolExhausted = -1

// InvalidCode represents the error message for an invalid TOTP code.
const InvalidCode = "The TOTP code is invalid"

// Supported salted hashes.
const (
	// SSHA256 is a constant for choosing the SHA-256 algorithm
	SSHA256 Algorithm = iota

	// SSHA512 is a constant for choosing the SHA-512 algorithm
	SSHA512
)

// Encoding schema for encrypted passwords.
const (
	B64 PasswordOption = iota
	HEX
)

const (
	// DbgNone is used when no debugging module is selected.
	DbgNone DbgModule = iota

	// DbgAll is used for indicating all debugging modules.
	DbgAll

	// DbgAuth is the debugging module for authentication processes.
	DbgAuth

	// DbgHydra is the debugging module for Hydra service related debugging.
	DbgHydra

	// DbgWebAuthn is the debugging module for WebAuthn related processes.
	DbgWebAuthn

	// DbgStats used for debugging statistical computations.
	DbgStats

	// DbgWhitelist for whitelist related debugging.
	DbgWhitelist

	// DbgLDAP is the debugging module for LDAP (Lightweight Directory Access Protocol) related debugging.
	DbgLDAP

	// DbgLDAPPool is the dedicated module for debugging LDAP connection pooling issues.
	DbgLDAPPool

	// DbgCache is suitable for cache mechanism debugging.
	DbgCache

	// DbgBf is used while debugging Bloom filter related operations.
	DbgBf

	// DbgRBL is for real-time blacklist related debugging.
	DbgRBL

	// DbgAction is for debugging related to any actions performed in the system.
	DbgAction

	// DbgFeature is for debugging toggling or usage of features.
	DbgFeature

	// DbgLua is for Lua scripting related debugging.
	DbgLua

	// DbgFilter is used for debugging issues related to filter operations.
	DbgFilter
)

const (
	// DbgNoneName is the debug identifier for 'none'
	DbgNoneName = "none"

	// DbgAllName is the debug identifier for 'all'
	DbgAllName = "all"

	// DbgAuthName is the debug identifier for authentication
	DbgAuthName = "auth"

	// DbgHydraName is the debug identifier for 'hydra'
	DbgHydraName = "hydra"

	// DbgWebAuthnName is the debug identifier for web authentication
	DbgWebAuthnName = "webauthn"

	// DbgStatsName is the debug identifier for statistics
	DbgStatsName = "statistics"

	// DbgWhitelistName is the debug identifier for whitelist
	DbgWhitelistName = "whitelist"

	// DbgLDAPName is the debug identifier for LDAP
	DbgLDAPName = "ldap"

	// DbgLDAPPoolName is the debug identifier for LDAP pool
	DbgLDAPPoolName = "ldappool"

	// DbgCacheName is the debug identifier for cache
	DbgCacheName = "cache"

	// DbgBfName is the debug identifier for brute force
	DbgBfName = "brute_force"

	// DbgRBLName is the debug identifier for RBL
	DbgRBLName = "rbl"

	// DbgActionName is the debug identifier for action
	DbgActionName = "action"

	// DbgFeatureName is the debug identifier for feature
	DbgFeatureName = "feature"

	// DbgLuaName is the debug identifier for Lua
	DbgLuaName = "lua"

	// DbgFilterName is the debug identifier for filter
	DbgFilterName = "filter"
)

const (
	// LuaActionNone indicates a placeholder for when no action is to be taken
	LuaActionNone LuaAction = iota

	// LuaActionBruteForce identifies an action related to the Brute Force attack prevention
	LuaActionBruteForce

	// LuaActionRBL is the action associated with Real-time Blackhole List (RBL) operations
	LuaActionRBL

	// LuaActionTLS is linked with Transport Layer Security (TLS) actions
	LuaActionTLS

	// LuaActionRelayDomains actions are related to domain relays
	LuaActionRelayDomains

	// LuaActionLua denotes actions scripted in Lua
	LuaActionLua

	// LuaActionPost indicates post processing actions
	LuaActionPost
)

const (
	// LuaActionBruteForceName is used to represent a brute force action in Lua
	LuaActionBruteForceName = "brute_force"

	// LuaActionRBLName is used to represent a Real-time Blackhole List action in Lua
	LuaActionRBLName = "rbl"

	// LuaActionTLSName is used to represent a Transport Layer Security encryption action in Lua
	LuaActionTLSName = "tls_encryption"

	// LuaActionRelayDomainsName is used to manage relay domains action in Lua
	LuaActionRelayDomainsName = "relay_domains"

	// LuaActionLuaName is used for executing a generic Lua action
	LuaActionLuaName = "lua"

	// LuaActionPostName is used for a posting an action in Lua
	LuaActionPostName = "post"
)

// SamePasswordsDifferentAccountLimit represents the limit for the number of times a user can repeatedly enter wrong passwords before it is considered an attack.
// When the number of occurrences of a specific password for a specific user reaches the limit from SamePasswordsDifferentAccountLimit configured value, it is logged as a brute force
const SamePasswordsDifferentAccountLimit = 5

// LuaMaxExecutionTime represents the maximum execution time in seconds for Lua scripts.
// It is set to 120 seconds.
// Example usage:
//
//	viper.SetDefault("lua_script_timeout", global.LuaMaxExecutionTime)
const LuaMaxExecutionTime = 120

// LuaBackendResultTypeName represents the constant name used as the Lua type name for the backend_result type.
const LuaBackendResultTypeName = "backend_result"

const (
	// LuaCommandPassDB represents the command for passing database in Lua
	LuaCommandPassDB LuaCommand = iota

	// LuaCommandListAccounts represents the command for listing accounts in Lua
	LuaCommandListAccounts

	// LuaCommandAddMFAValue represents the command for adding a Multi-Factor Authentication value in Lua
	LuaCommandAddMFAValue
)

const (
	// LuaFnCtxSet represents the function name for "context_set" in Lua
	LuaFnCtxSet = "context_set"

	// LuaFnCtxGet represents the function name for "context_get" in Lua
	LuaFnCtxGet = "context_get"

	// LuaFnCtxDelete represents the function name for "context_delete" in Lua
	LuaFnCtxDelete = "context_delete"

	// LuaFnAddCustomLog represents the function name for "custom_log_add" in Lua
	LuaFnAddCustomLog = "custom_log_add"

	// LuaFnBackendVerifyPassword represents the function name for "nauthilus_backend_verify_password" in Lua
	LuaFnBackendVerifyPassword = "nauthilus_backend_verify_password"

	// LuaFnBackendListAccounts represents the function name for "nauthilus_backend_list_accounts" in Lua
	LuaFnBackendListAccounts = "nauthilus_backend_list_accounts"

	// LuaFnBackendAddTOTPSecret represents the function name for "nauthilus_backend_add_totp" in Lua
	LuaFnBackendAddTOTPSecret = "nauthilus_backend_add_totp"

	// LuaModUtil represents the module name for "nauthilus_util" in Lua
	LuaModUtil = "nauthilus_util"

	// LuaFnCallFeature represents the function name for "nauthilus_call_feature" in Lua
	LuaFnCallFeature = "nauthilus_call_feature"

	// LuaFnCallAction represents the function name for "nauthilus_call_action" in Lua
	LuaFnCallAction = "nauthilus_call_action"

	// LuaFnCallFilter represents the function name for "nauthilus_call_filter" in Lua
	LuaFnCallFilter = "nauthilus_call_filter"

	// LuaFnGetNgxBackendServers represents the Lua function name "nauthilus_get_nginx_backend_servers" that retrieves the nginx backend servers.
	LuaFnGetNgxBackendServers = "get_nginx_backend_servers"

	// LuaFnSelectNginxBackend represents the constant used as the key for the Lua function "nauthilus_select_nginx_backend".
	LuaFnSelectNginxBackend = "select_nginx_backend_server"

	LuaFnSetStatusMessage = "status_message_set"
)

const (
	// LuaDefaultTable represents the default table name in Lua
	LuaDefaultTable = "nauthilus"

	// LuaSuccess represents the success status in Lua
	LuaSuccess = "success"

	// LuaFail represents the fail status in Lua
	LuaFail = "fail"

	// LuaFeatureTriggerNo represents the feature trigger no option in Lua
	LuaFeatureTriggerNo = "FEATURE_TRIGGER_NO"

	// LuaFeatureTriggerYes represents the feature trigger yes option in Lua
	LuaFeatureTriggerYes = "FEATURE_TRIGGER_YES"

	// LuaFeatureAbortNo represents the features abort no option in Lua
	LuaFeatureAbortNo = "FEATURES_ABORT_NO"

	// LuaFeatureAbortYes represents the features abort yes option in Lua
	LuaFeatureAbortYes = "FEATURES_ABORT_YES"

	// LuaFeatureResultOk represents the feature result ok status in Lua
	LuaFeatureResultOk = "FEATURE_RESULT_OK"

	// LuaFeatureResultFail represents the feature result fail status in Lua
	LuaFeatureResultFail = "FEATURE_RESULT_FAIL"

	// LuaActionResultOk represents the action result ok status in Lua
	LuaActionResultOk = "ACTION_RESULT_OK"

	// LuaActionResultFail represents the action result fail status in Lua
	LuaActionResultFail = "ACTION_RESULT_FAIL"

	// LuaBackendResultOk represents the backend result ok status in Lua
	LuaBackendResultOk = "BACKEND_RESULT_OK"

	// LuaBackendResultFail represents the backend result fail status in Lua
	LuaBackendResultFail = "BACKEND_RESULT_FAIL"

	// LuaFilterAccept represents the filter accept option in Lua
	LuaFilterAccept = "FILTER_ACCEPT"

	// LuaFilterREJECT represents the filter reject option in Lua
	LuaFilterREJECT = "FILTER_REJECT"

	// LuaFilterResultOk represents the filter result ok status in Lua
	LuaFilterResultOk = "FILTER_RESULT_OK"

	// LuaFilterResultFail represents the filter result fail status in Lua
	LuaFilterResultFail = "FILTER_RESULT_FAIL"
)

const (
	// LuaRequestDebug is for debugging purposes.
	LuaRequestDebug = "debug"

	// LuaRequestNoAuth indicates no authorization required.
	LuaRequestNoAuth = "no_auth"

	// LuaRequestService indicates the type of service.
	LuaRequestService = "service"

	// LuaRequestRepeating signifies that the request is repeating.
	LuaRequestRepeating = "repeating"

	// LuaRequestAuthenticated indicates that the request is authenticated.
	LuaRequestAuthenticated = "authenticated"

	// LuaRequestUserFound is for when a user is found.
	LuaRequestUserFound = "user_found"

	// LuaRequestBruteForceCounter keeps track of the number of attempts.
	LuaRequestBruteForceCounter = "brute_force_counter"

	// LuaRequestBruteForceBucket is for the bucket of brute force attempts.
	LuaRequestBruteForceBucket = "brute_force_bucket"

	// LuaRequestFeature indicates the feature type of the request.
	LuaRequestFeature = "feature"

	// LuaRequestSession indicates the session of the request.
	LuaRequestSession = "session"

	// LuaRequestClientIP signifies the client IP of the request.
	LuaRequestClientIP = "client_ip"

	// LuaRequestClientPort signifies the client port of the request.
	LuaRequestClientPort = "client_port"

	// LuaRequestClientNet indicates the client network.
	LuaRequestClientNet = "client_net"

	// LuaRequestClientHost indicates the client host.
	LuaRequestClientHost = "client_hostname"

	// LuaRequestClientID signifies the client ID of the request.
	LuaRequestClientID = "client_id"

	// LuaRequestLocalIP signifies the local IP of the request.
	LuaRequestLocalIP = "local_ip"

	// LuaRequestLocalPort signifies the local port of the request.
	LuaRequestLocalPort = "local_port"

	// LuaRequestUsername signifies the username of the user making the request.
	LuaRequestUsername = "username"

	// LuaRequestAccount signifies the account of the user making the request.
	LuaRequestAccount = "account"

	// LuaRequestUniqueUserID signifies the unique user ID of the user making the request.
	LuaRequestUniqueUserID = "unique_user_id"

	// LuaRequestDisplayName signifies the display name of the user making the request.
	LuaRequestDisplayName = "display_name"

	// LuaRequestPassword signifies the password of the user making the request.
	LuaRequestPassword = "password"

	// LuaRequestProtocol signifies the protocol of the request.
	LuaRequestProtocol = "protocol"

	// LuaRequestUserAgent signifies the user agent of the request.
	LuaRequestUserAgent = "user_agent"

	// LuaRequestXSSL indicates the SSL of the request.
	LuaRequestXSSL = "ssl"

	// LuaRequestXSSSLSessionID signifies the SSL session ID of the request.
	LuaRequestXSSSLSessionID = "ssl_session_id"

	// LuaRequestXSSLClientVerify checks the SSL client verification.
	LuaRequestXSSLClientVerify = "ssl_client_verify"

	// LuaRequestXSSLClientDN signifies the SSL client distinguished name.
	LuaRequestXSSLClientDN = "ssl_client_dn"

	// LuaRequestXSSLClientCN signifies the SSL client common name.
	LuaRequestXSSLClientCN = "ssl_client_cn"

	// LuaRequestXSSLIssuer signifies the SSL issuer of the client.
	LuaRequestXSSLIssuer = "ssl_issuer"

	// LuaRequestXSSLClientNotBefore indicates the SSL client start date.
	LuaRequestXSSLClientNotBefore = "ssl_client_not_before"

	// LuaRequestXSSLClientNotAfter indicates the SSL client expiry date.
	LuaRequestXSSLClientNotAfter = "ssl_client_not_after"

	// LuaRequestXSSLSubjectDN indicates the SSL subject distinguished name.
	LuaRequestXSSLSubjectDN = "ssl_subject_dn"

	// LuaRequestXSSLIssuerDN indicates the SSL issuer distinguished name.
	LuaRequestXSSLIssuerDN = "ssl_issuer_dn"

	// LuaRequestXSSLClientSubjectDN indicates the SSL client subject distinguished name.
	LuaRequestXSSLClientSubjectDN = "ssl_client_subject_dn"

	// LuaRequestXSSLClientIssuerDN indicates the SSL client issuer distinguished name.
	LuaRequestXSSLClientIssuerDN = "ssl_client_issuer_dn"

	// LuaRequestXSSLProtocol indicates the SSL protocol used.
	LuaRequestXSSLProtocol = "ssl_protocol"

	// LuaRequestXSSLCipher indicates the SSL cipher used.
	LuaRequestXSSLCipher = "ssl_cipher"

	// LuaRequestTOTPSecret signifies the TOTP secret of the user.
	LuaRequestTOTPSecret = "totp_secret"

	LuaRequestStatusMessage = "status_message"
)

// Exit status codes.
const (
	// ResultOk is a constant representing the successful outcome of an operation
	ResultOk = 0

	// ResultFail is a constant representing the unsuccessful outcome of an operation
	ResultFail = 1
)

const (
	// CacheAll refers to the enum value for all cache backends
	CacheAll CacheNameBackend = iota

	// CacheLDAP refers to the enum value for LDAP cache backend
	CacheLDAP

	// CacheLua refers to the enum value for Lua cache backend
	CacheLua
)
