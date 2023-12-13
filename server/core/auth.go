package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/go-webauthn/webauthn/webauthn"
	openapi "github.com/ory/hydra-client-go/v2"
	"gotest.tools/v3/assert"
)

// Authentication is the central object that is filled by a remote application request and is modified from each
// Database that is involved in authentication.
//
// Most fields are related to the Nginx protocol, but can be set in a different way, if using another service type (i.e.
// saslauthd). For further information have a look at the constructor NewAuthentication.
//
//nolint:maligned // Ignore further optimization
type Authentication struct {
	// UsernameReplace is a flag that is set, if a user was found in a Database.
	UsernameReplace bool

	// NoAuth is a flag that is set, if the request mode does not require authentication.
	NoAuth bool

	// ListAccounts is a flag that is set, if Nauthilus is requested to send a full list of available user accounts.
	ListAccounts bool

	// UserFound is a flag that is set, if a password Database found the user.
	UserFound bool

	// PasswordsAccountSeen is a counter that is increased whenever a new failed password was detected for the current account.
	PasswordsAccountSeen uint

	// PasswordsTotalSeen is a counter that is increased whenever a new failed password was detected.
	PasswordsTotalSeen uint

	// LoginAttempts is a counter that is incremented for each failed login request
	LoginAttempts uint

	// StatusCodeOk is the HTTP status code that is set by SetStatusCode.
	StatusCodeOK int

	// StatusCodeInternalError is the HTTP status code that is set by SetStatusCode.
	StatusCodeInternalError int

	// StatusCodeFail is the HTTP status code that is set by SetStatusCode.
	StatusCodeFail int

	// GUID is a global unique identifier that is inherited in all functions and methods that deal with the
	// authentication process. It is needed to track log lines belonging to one request.
	GUID *string

	// Method is set by the "Auth-Method" HTTP request header (Nginx protocol). It is typically something like "plain"
	// or "login".
	Method *string

	// AccountField is the name of either a SQL field name or an LDAP attribute that was used to retrieve a user account.
	AccountField *string

	// Username is the value that was taken from the HTTP header "Auth-User" (Nginx protocol).
	Username string

	// UsernameOrig is a copy from the username that was set by the HTTP request header "Auth-User" (Nginx protocol).
	UsernameOrig string

	// Password is the value that was taken from the HTTP header "Auth-Pass" (Nginx protocol).
	Password string

	// ClientIP is the IP of a client that is to be authenticated. The value is set by the HTTP request header
	// "Client-IP" (Nginx protocol).
	ClientIP string

	// XClientPort adds the remote client TCP port, which is set by the HTTP request header "X-Client-Port".
	XClientPort string

	// ClientHost is the DNS A name of the remote client. It is set with the HTTP request header "Client-Host" (Nginx
	// protocol).
	ClientHost string

	// HAProxy specific headers
	XSSL                string // %[ssl_fc]
	XSSLSessionID       string // %[ssl_fc_session_id,hex]
	XSSLClientVerify    string // %[ssl_c_verify]
	XSSLClientDN        string // %{+Q}[ssl_c_s_dn]
	XSSLClientCN        string // %{+Q}[ssl_c_s_dn(cn)]
	XSSLIssuer          string // %{+Q}[ssl_c_i_dn]
	XSSLClientNotBefore string // %{+Q}[ssl_c_notbefore]
	XSSLClientNotAfter  string // %{+Q}[ssl_c_notafter]
	XSSLSubjectDN       string // %{+Q}[ssl_c_s_dn]
	XSSLIssuerDN        string // %{+Q}[ssl_c_i_dn]
	XSSLClientSubjectDN string // %{+Q}[ssl_c_s_dn]
	XSSLClientIssuerDN  string // %{+Q}[ssl_c_i_dn]
	XSSLProtocol        string // %[ssl_fc_protocol]
	XSSLCipher          string // %[ssl_fc_cipher]

	// XClientID is delivered by some mail user agents when using IMAP. This value is set by the HTTP request header
	// "X-Client-Id".
	XClientID string

	// XLocalIP is the TCP/IP address of the server that asks for authentication. Its value is set by the HTTP request
	// header "X-Local-IP".
	XLocalIP string

	// XPort is the TCP port of the server that asks for authentication. Its value is set by the HTTP request
	// header "X-Local-Port".
	XPort string

	// UserAgent may have been seent by a mail user agent and is set by the HTTP request header "User-Agent".
	UserAgent *string

	// StatusMessage is the HTTP response payload that is sent to the remote server that asked for authentication.
	StatusMessage string

	// Service is set by Nauthilus depending on the router endpoint. Look at httpQueryHandler for the structure of available
	// endpoints.
	Service string

	// BruteForceName is the canonical name of a brute force bucket that was triggered by a rule.
	BruteForceName string

	// FeatureName is the name of a feature that has triggered a reject.
	FeatureName string

	// TOTPSecret is used to store a TOTP secret in a SQL Database.
	TOTPSecret *string

	// TOTPSecretField is the SQL field or LDAP attribute that resolves the TOTP secret for two-factor authentication.
	TOTPSecretField *string

	// TOTPRecoveryField NYI
	TOTPRecoveryField *string

	// UniqueUserIDField is a string representing a unique user identifier.
	UniqueUserIDField *string

	// DisplayNameField is the display name of a user
	DisplayNameField *string

	// AdditionalLogging is a slice of strings that can be filled from Lua features and a Lua backend. Its result will be
	// added to the regular log lines.
	AdditionalLogs []any

	// BruteForceCounter is a map that increments failed login requests. The key is a rule name defined in the
	// configuration file.
	BruteForceCounter map[string]uint

	// SourcePassDBBackend is a marker for the Database that is responsible for a specific user. It is set by the
	// password Database and stored in Redis to track the authentication flow accross databases (including proxy).
	SourcePassDBBackend decl.Backend

	// UsedPassDBBackend is set by the password Database that answered the current authentication request.
	UsedPassDBBackend decl.Backend

	// Attributes is a result container for SQL and LDAP queries. Databases store their result by using a field or
	// attribute name as key and the corresponding result as value.
	Attributes backend.DatabaseResult

	// Protocol is set by the HTTP request header "Auth-Protocol" (Nginx protocol).
	Protocol *config.Protocol

	// HTTPClientContext tracks the context for an HTTP client connection.
	HTTPClientContext context.Context

	*GeoIPCity
	*backend.PasswordHistory
	*lualib.Context
}

// PassDBResult is used in all password databases to store final results of an authentication process.
type PassDBResult struct {
	// Authenticated is a flag that is set if a user was not only found, but also succeeded authentication.
	Authenticated bool

	// UserFound is a flag that is set if the user was found in a password Database.
	UserFound bool

	// AccountField is the SQL field or LDAP attribute that was used for the user account.
	AccountField *string

	// TOTPSecretField is set by the Database which has found the user.
	TOTPSecretField *string

	// TOTPRecoveryField NYI
	TOTPRecoveryField *string

	// UniqueUserIDField is a string representing a unique user identifier.
	UniqueUserIDField *string

	// DisplayNameField is the display name of a user
	DisplayNameField *string

	// Backend is set by the Database backend which has found the user.
	Backend decl.Backend

	// Attributes is the result catalog returned by the underlying password Database.
	Attributes backend.DatabaseResult
}

type (
	// PassDBOption
	// This type specifies the signature of a password database.
	PassDBOption func(auth *Authentication) (*PassDBResult, error)

	// PassDBMap is a struct type that represents a mapping between a backend type and a PassDBOption function.
	// It is used in the VerifyPassword method of the Authentication struct to perform password verification against multiple databases.
	// The backend field represents the type of database backend (decl.Backend) and the fn field represents the PassDBOption function.
	// The PassDBOption function takes an Authentication pointer as input and returns a PassDBResult pointer and an error.
	// The PassDBResult pointer contains the result of the password verification process.
	// This struct is used to store the database mappings in an array and loop through them in the VerifyPassword method.
	PassDBMap struct {
		backend decl.Backend
		fn      PassDBOption
	}
)

type (
	// AccountList is a slice of strings containing the list of all user accounts.
	AccountList []string

	// AccountListOption is the function signature for an account Database.
	AccountListOption func(a *Authentication) (AccountList, error)

	// AccountListMap is a struct type that represents a mapping between a backend and an account list option function for authentication.
	AccountListMap struct {
		backend decl.Backend
		fn      AccountListOption
	}
)

// WebAuthnCredentialDBFunc defines a signature for WebAuthn credential object lookups
type WebAuthnCredentialDBFunc func(uniqueUserID string) ([]webauthn.Credential, error)

// AddTOTPSecretFunc is a function signature that takes a *Authentication and *TOTPSecret as arguments and returns an error.
type AddTOTPSecretFunc func(auth *Authentication, totp *TOTPSecret) (err error)

// String returns an Authentication object as string excluding the user password.
func (a *Authentication) String() string {
	var result string

	value := reflect.ValueOf(a)
	typeOfValue := value.Type()

	for index := 0; index < value.NumField(); index++ {
		switch typeOfValue.Field(index).Name {
		case "GUID":
			continue
		case "Password":
			if config.EnvConfig.DevMode {
				result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
			} else {
				result += fmt.Sprintf(" %s='<hidden>'", typeOfValue.Field(index).Name)
			}
		default:
			result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
		}
	}

	return result[1:]
}

// logLineGeoIP returns an array of key-value pairs representing the geoIP information of the Authentication object.
// It includes the GUID, GeoIP ISO code, GeoIP country name, GeoIP city name, whether the GeoIP is in the European Union,
// GeoIP accuracy radius, latitude, longitude, metro code, and time zone.
// If any value is not available, it is replaced with the "N/A" constant
func (a *Authentication) logLineGeoIP() []any {
	var (
		geoIPCityCountryName string
		geoIPCityCityName    string
	)

	if val, okay := a.GeoIPCity.City.Names["en"]; okay {
		if val != "" {
			geoIPCityCityName = val
		} else {
			geoIPCityCityName = decl.NotAvailable
		}
	} else {
		geoIPCityCityName = decl.NotAvailable
	}

	if val, okay := a.GeoIPCity.Country.Names["en"]; okay {
		if val != "" {
			geoIPCityCountryName = val
		} else {
			geoIPCityCountryName = decl.NotAvailable
		}
	} else {
		geoIPCityCountryName = decl.NotAvailable
	}

	if a.GeoIPCity.Location.TimeZone == "" {
		a.GeoIPCity.Location.TimeZone = decl.NotAvailable
	}

	return []any{
		decl.LogKeyGUID, util.WithNotAvailable(*a.GUID),
		decl.LogKeyGeoIPISOCode, util.WithNotAvailable(a.GeoIPCity.Country.IsoCode),
		decl.LogKeyGeoIPCountryName, geoIPCityCountryName,
		decl.LogKeyGeoIPCityName, geoIPCityCityName,
		decl.LogKeyGeoIPIsInEuropeanUnion, fmt.Sprintf("%v", a.GeoIPCity.Country.IsInEuropeanUnion),
		decl.LogKeyGeoIPAccuracyRadius, fmt.Sprintf("%d", a.GeoIPCity.Location.AccuracyRadius),
		decl.LogKeyGeoIPLatitude, fmt.Sprintf("%f", a.GeoIPCity.Location.Latitude),
		decl.LogKeyGeoIPLongitude, fmt.Sprintf("%f", a.GeoIPCity.Location.Longitude),
		decl.LogKeyGeoIPMetroCode, fmt.Sprintf("%d", a.GeoIPCity.Location.MetroCode),
		decl.LogKeyGeoIPTimeZone, a.GeoIPCity.Location.TimeZone,
	}
}

// LogLineMail returns an array of key-value pairs used for logging mail information.
// The array includes the following information:
// - session: the session GUID
// - protocol: the protocol used
// - local_ip: the local IP address
// - port: the port number
// - client_ip: the client IP address
// - client_port: the client port number
// - client_host: the client host
// - tls_protocol: the TLS protocol used
// - tls_cipher: the TLS cipher used
// - auth_method: the authentication method
// - username: the username
// - orig_username: the original username
// - passdb_backend: the used password database backend
// - current_password_retries: the number of current password retries
// - account_passwords_seen: the number of account passwords seen
// - total_passwords_seen: the total number of passwords seen
// - user_agent: the user agent
// - client_id: the client ID
// - brute_force_bucket: the brute force bucket name
// - feature: the feature name
// - status_message: the status message
// - uri_path: the URI path
// - authenticated: the authentication status
func (a *Authentication) LogLineMail(status string, endpoint string) []any {
	var keyvals []any

	keyvals = []any{
		decl.LogKeyGUID, util.WithNotAvailable(*a.GUID),
		decl.LogKeyProtocol, util.WithNotAvailable(a.Protocol.String()),
		decl.LogKeyLocalIP, util.WithNotAvailable(a.XLocalIP),
		decl.LogKeyPort, util.WithNotAvailable(a.XPort),
		decl.LogKeyClientIP, util.WithNotAvailable(a.ClientIP),
		decl.LogKeyClientPort, util.WithNotAvailable(a.XClientPort),
		decl.LogKeyClientHost, util.WithNotAvailable(a.ClientHost),
		decl.LogKeyTLSSecure, util.WithNotAvailable(a.XSSLProtocol),
		decl.LogKeyTLSCipher, util.WithNotAvailable(a.XSSLCipher),
		decl.LogKeyAuthMethod, util.WithNotAvailable(a.Method),
		decl.LogKeyUsername, util.WithNotAvailable(a.Username),
		decl.LogKeyOrigUsername, util.WithNotAvailable(a.UsernameOrig),
		decl.LogKeyUsedPassdbBackend, util.WithNotAvailable(a.UsedPassDBBackend.String()),
		decl.LogKeyLoginAttempts, a.LoginAttempts,
		decl.LogKeyPasswordsAccountSeen, a.PasswordsAccountSeen,
		decl.LogKeyPasswordsTotalSeen, a.PasswordsTotalSeen,
		decl.LogKeyUserAgent, util.WithNotAvailable(a.UserAgent),
		decl.LogKeyClientID, util.WithNotAvailable(a.XClientID),
		decl.LogKeyBruteForceName, util.WithNotAvailable(a.BruteForceName),
		decl.LogKeyFeatureName, util.WithNotAvailable(a.FeatureName),
		decl.LogKeyStatusMessage, util.WithNotAvailable(a.StatusMessage),
		decl.LogKeyUriPath, endpoint,
		decl.LogKeyStatus, util.WithNotAvailable(status),
	}

	if len(a.AdditionalLogs) > 0 {
		if len(a.AdditionalLogs)%2 == 0 {
			for index := range a.AdditionalLogs {
				keyvals = append(keyvals, a.AdditionalLogs[index])
			}
		}
	}

	return keyvals
}

// GetAccount returns the account value from the Authentication object. If the account field is not set or the account
// value is not found in the attributes, an empty string is returned
func (a *Authentication) GetAccount() string {
	if a.AccountField == nil {
		return ""
	}

	if account, okay := a.Attributes[*a.AccountField]; okay {
		if value, assertOk := account[decl.LDAPSingleValue].(string); assertOk {
			return value
		}
	}

	return ""
}

// GetAccountOk returns the account name of a user. If there is no account, it returns the empty string "". A boolean
// is set to return a "found" flag.
func (a *Authentication) GetAccountOk() (string, bool) {
	account := a.GetAccount()

	return account, account != ""
}

// GetTOTPSecret returns the TOTP secret for a user. If there is no secret, it returns the empty string "".
func (a *Authentication) GetTOTPSecret() string {
	if a.TOTPSecretField == nil {
		return ""
	}

	if totpSecret, okay := a.Attributes[*a.TOTPSecretField]; okay {
		if value, assertOk := totpSecret[decl.LDAPSingleValue].(string); assertOk {
			return value
		}
	}

	return ""
}

// GetTOTPSecretOk returns the TOTP secret for a user. If there is no secret, it returns the empty string "". A boolean
// is set to return a "found" flag.
func (a *Authentication) GetTOTPSecretOk() (string, bool) {
	totpSecret := a.GetTOTPSecret()

	return totpSecret, totpSecret != ""
}

// GetUniqueUserID returns the unique WebAuthn user identifier for a user. If there is no id, it returns the empty string "".
func (a *Authentication) GetUniqueUserID() string {
	if a.UniqueUserIDField == nil {
		return ""
	}

	if webAuthnUserID, okay := a.Attributes[*a.UniqueUserIDField]; okay {
		if value, assertOk := webAuthnUserID[decl.LDAPSingleValue].(string); assertOk {
			return value
		}
	}

	return ""
}

// GetUniqueUserIDOk returns the unique identifier for a user. If there is no id, it returns the empty string "". A boolean
// is set to return a "found" flag.
func (a *Authentication) GetUniqueUserIDOk() (string, bool) {
	uniqueUserID := a.GetUniqueUserID()

	return uniqueUserID, uniqueUserID != ""
}

// GetDisplayName returns the display name for a user. If there is no account, it returns the empty string "".
func (a *Authentication) GetDisplayName() string {
	if a.DisplayNameField == nil {
		return ""
	}

	if account, okay := a.Attributes[*a.DisplayNameField]; okay {
		if value, assertOk := account[decl.SliceWithOneElement].(string); assertOk {
			return value
		}
	}

	return ""
}

// GetDisplayNameOk returns the display name of a user. If there is no account, it returns the empty string "". A boolean
// is set to return a "found" flag.
func (a *Authentication) GetDisplayNameOk() (string, bool) {
	displayName := a.GetDisplayName()

	return displayName, displayName != ""
}

// AuthOK is the general method to indicate authentication success.
func (a *Authentication) AuthOK(ctx *gin.Context) {
	ctx.Header("Auth-Status", "OK")
	ctx.Header("X-Authserv-Session", *a.GUID)

	if a.Service != decl.ServBasicAuth {
		if a.UsernameReplace {
			if account, found := a.GetAccountOk(); found {
				ctx.Header("Auth-User", account)
			}
		}
	}

	if a.Service == decl.ServNginx {
		switch a.Protocol.Get() {
		case decl.ProtoSMTP:
			ctx.Header("Auth-Server", config.EnvConfig.SMTPBackendAddress)
			ctx.Header("Auth-Port", fmt.Sprintf("%d", config.EnvConfig.SMTPBackendPort))
		default:
			ctx.Header("Auth-Server", config.EnvConfig.IMAPBackendAddress)
			ctx.Header("Auth-Port", fmt.Sprintf("%d", config.EnvConfig.IMAPBackendPort))
		}
	}

	if a.Service == decl.ServDovecot {
		if a.Attributes != nil && len(a.Attributes) > 0 {
			for name, value := range a.Attributes {
				var headerValue string

				if len(value) == 0 {
					continue
				}

				if len(value) == 1 {
					headerValue = fmt.Sprintf("%v", value[decl.LDAPSingleValue])
				}

				if len(value) > 1 {
					var stringValues []string

					for index := range value {
						stringValues = append(stringValues, fmt.Sprintf("%v", value[index]))
					}

					separator := ","
					if name == decl.DistinguishedName {
						separator = ";"
					}

					headerValue = strings.Join(stringValues, separator)
				}

				ctx.Header("X-Nauthilus-"+name, fmt.Sprintf("%v", headerValue))
			}
		}
	}

	a.StatusMessage = "OK"

	if a.Service == decl.ServUserInfo {
		ctx.Header("Content-Type", "application/json; charset=UTF-8")
		ctx.Header("X-User-Found", fmt.Sprintf("%v", a.UserFound))
		ctx.JSON(a.StatusCodeOK, &backend.PositivePasswordCache{
			AccountField:    a.AccountField,
			TOTPSecretField: a.TOTPSecretField,
			Backend:         a.SourcePassDBBackend,
			Attributes:      a.Attributes,
		})
	} else {
		ctx.String(a.StatusCodeOK, a.StatusMessage)
	}

	if config.EnvConfig.Verbosity.Level() > decl.LogLevelWarn {
		level.Info(logging.DefaultLogger).Log(a.LogLineMail(func() string {
			if !a.NoAuth {
				return "ok"
			}

			return ""
		}(), ctx.Request.URL.Path)...)
	}

	LoginsCounter.WithLabelValues(decl.LabelSuccess).Inc()
}

// AuthFail is the general method to indicate authentication failures.
func (a *Authentication) AuthFail(ctx *gin.Context) {
	ctx.Header("Auth-Status", decl.PasswordFail)
	ctx.Header("X-Authserv-Session", *a.GUID)

	if a.LoginAttempts > math.MaxUint8 {
		a.LoginAttempts = math.MaxUint8
	}

	if a.Service == decl.ServNginx {
		if a.LoginAttempts < uint(config.EnvConfig.MaxLoginAttempts) {
			ctx.Header("Auth-Wait", fmt.Sprintf("%d", uint(config.EnvConfig.WaitDelay)+a.LoginAttempts))
		}
	}

	a.StatusMessage = decl.PasswordFail

	if a.Service == decl.ServUserInfo {
		ctx.Header("Content-Type", "application/json; charset=UTF-8")
		ctx.Header("X-User-Found", fmt.Sprintf("%v", a.UserFound))
		if a.PasswordHistory != nil {
			ctx.JSON(a.StatusCodeFail, *a.PasswordHistory)
		} else {
			ctx.JSON(a.StatusCodeFail, struct{}{})
		}
	} else {
		ctx.String(a.StatusCodeFail, a.StatusMessage)
	}

	if config.EnvConfig.Verbosity.Level() > decl.LogLevelWarn {
		level.Info(logging.DefaultLogger).Log(a.LogLineMail("fail", ctx.Request.URL.Path)...)
	}

	LoginsCounter.WithLabelValues(decl.LabelFailure).Inc()
}

// AuthTempFail is the general method to indicate internal server errors.
func (a *Authentication) AuthTempFail(ctx *gin.Context, reason string) {
	ctx.Header("Auth-Status", reason)
	ctx.Header("X-Authserv-Session", *a.GUID)

	if a.Service == decl.ServNginx {
		if a.Protocol.Get() == decl.ProtoSMTP {
			ctx.Header("Auth-Error-Code", decl.TempFailCode)
		}
	}

	a.StatusMessage = reason

	if a.Service == decl.ServUserInfo {
		type errType struct {
			Error string `json:"error"`
		}

		message := &errType{reason}

		ctx.Header("Content-Type", "application/json; charset=UTF-8")
		ctx.Header("X-User-Found", fmt.Sprintf("%v", a.UserFound))
		ctx.JSON(a.StatusCodeInternalError, message)
	} else {
		ctx.String(a.StatusCodeInternalError, a.StatusMessage)
	}

	level.Info(logging.DefaultLogger).Log(a.LogLineMail("tempfail", ctx.Request.URL.Path)...)
}

// IsInNetwork checks an IP address against a network and returns true if it matches.
func (a *Authentication) IsInNetwork(networkList []string) (matchIP bool) {
	ipAddress := net.ParseIP(a.ClientIP)

	for _, ipOrNet := range networkList {
		if net.ParseIP(ipOrNet) == nil {
			_, network, err := net.ParseCIDR(ipOrNet)
			if err != nil {
				level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyMsg, "%s is not a network", ipOrNet, decl.LogKeyError, err)

				continue
			}

			util.DebugModule(
				decl.DbgWhitelist,
				decl.LogKeyGUID, a.GUID, decl.LogKeyMsg, fmt.Sprintf("Checking: %s -> %s", a.ClientIP, network.String()),
			)

			if network.Contains(ipAddress) {
				util.DebugModule(decl.DbgWhitelist, decl.LogKeyGUID, a.GUID, decl.LogKeyMsg, "IP matched")

				matchIP = true

				break
			}
		} else {
			util.DebugModule(decl.DbgWhitelist, decl.LogKeyGUID, a.GUID, decl.LogKeyMsg, fmt.Sprintf("Checking: %s -> %s", a.ClientIP, ipOrNet))
			if a.ClientIP == ipOrNet {
				util.DebugModule(decl.DbgWhitelist, decl.LogKeyGUID, a.GUID, decl.LogKeyMsg, "IP matched")

				matchIP = true

				break
			}
		}
	}

	return
}

// VerifyPassword iterates through all known databases and does the main authentication process.
func (a *Authentication) VerifyPassword(passDBs []*PassDBMap) (*PassDBResult, error) {
	var (
		passDBResult *PassDBResult
		err          error
	)

	t := &testing.T{}
	if !assert.Check(t, len(passDBs) > 0) {
		return passDBResult, errors2.ErrNoPassDBs
	}

	configErrors := make(map[decl.Backend]error, len(passDBs))

	for passDBIndex, passDB := range passDBs {
		passDBResult, err = passDB.fn(a)

		util.DebugModule(decl.DbgAuth, decl.LogKeyGUID, a.GUID, "passDB", passDB.backend.String(), "result", fmt.Sprintf("%v", passDBResult))

		if err != nil {
			// Check, if we have some configuration issues in one of the backends.
			if errors.Is(err, errors2.ErrSQLConfig) || errors.Is(err, errors2.ErrLDAPConfig) || errors.Is(err, errors2.ErrLuaConfig) {
				configErrors[passDB.backend] = err

				// After all password databases were running,  check if SQL, LDAP and Lua  backends have configuration errors.
				if passDBIndex == len(passDBs)-1 {
					var allConfigErrors = true

					for _, err = range configErrors {
						if err != nil {
							continue
						}

						// At least _one_ backend worked without errors
						allConfigErrors = false

						break
					}

					// If all (real) Database backends failed, we must return with a temporary failure
					if allConfigErrors {
						err = errors2.ErrAllBackendConfigError

						level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, "passdb", "all", decl.LogKeyError, err)

						break
					}
				} else {
					// There are still backends to query, keep going with the next backend
					continue
				}
			} else {
				// Some critical error occured in one of the backends
				level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, "passdb", passDB.backend.String(), decl.LogKeyError, err)

				break
			}
		}

		if passDBResult == nil {
			err = errors2.ErrNoPassDBResult

			break
		}

		util.DebugModule(
			decl.DbgAuth,
			decl.LogKeyGUID, a.GUID,
			"passdb", passDB.backend.String(),
			decl.LogKeyUsername, a.Username,
			decl.LogKeyOrigUsername, a.UsernameOrig,
			"passdb_result", fmt.Sprintf("%+v", *passDBResult),
		)

		if passDBResult.AccountField != nil {
			a.AccountField = passDBResult.AccountField
		}

		if passDBResult.TOTPSecretField != nil {
			a.TOTPSecretField = passDBResult.TOTPSecretField
		}

		if passDBResult.UniqueUserIDField != nil {
			a.UniqueUserIDField = passDBResult.UniqueUserIDField
		}

		if passDBResult.DisplayNameField != nil {
			a.DisplayNameField = passDBResult.DisplayNameField
		}

		if passDBResult.Attributes != nil && len(passDBResult.Attributes) > 0 {
			a.Attributes = passDBResult.Attributes
		}

		if passDBResult.UserFound {
			a.SourcePassDBBackend = passDBResult.Backend
			a.UsedPassDBBackend = passDB.backend
			a.UserFound = true

			break
		}
	}

	// Enforce authentication
	if a.NoAuth {
		passDBResult.Authenticated = true
	}

	return passDBResult, err
}

// SetStatusCode sets different status codes for various services.
func (a *Authentication) SetStatusCode(service string) error {
	switch service {
	case decl.ServNginx, decl.ServDovecot:
		a.StatusCodeOK = http.StatusOK
		a.StatusCodeInternalError = http.StatusOK
		a.StatusCodeFail = http.StatusOK
	case decl.ServSaslauthd, decl.ServBasicAuth, decl.ServOryHydra, decl.ServUserInfo:
		a.StatusCodeOK = http.StatusOK
		a.StatusCodeInternalError = http.StatusInternalServerError
		a.StatusCodeFail = http.StatusForbidden
	default:
		return errors2.ErrUnknownService
	}

	return nil
}

// HandleFeatures iterates through the list of enabled features and returns true, if a feature returned positive.
func (a *Authentication) HandleFeatures(ctx *gin.Context) (authResult decl.AuthResult) {
	// Helper function that sends an action request and waits for it to be finished. Features may change the Lua context.
	// Lua post actions may make use of these changes.
	doAction := func(luaAction decl.LuaAction) {
		finished := make(chan action.Done)

		action.RequestChan <- &action.Action{
			LuaAction:    luaAction,
			Debug:        config.EnvConfig.Verbosity.Level() == decl.LogLevelDebug,
			Repeating:    false,
			Session:      *a.GUID,
			ClientIP:     a.ClientIP,
			ClientPort:   a.XClientPort,
			ClientHost:   a.ClientHost,
			ClientID:     a.XClientID,
			LocalIP:      a.XLocalIP,
			LocalPort:    a.XPort,
			Username:     a.UsernameOrig,
			Password:     a.Password,
			Protocol:     a.Protocol.Get(),
			FeatureName:  a.FeatureName,
			Context:      a.Context,
			FinishedChan: finished,
		}

		<-finished
	}

	/*
	 * Neutral features
	 */

	if config.EnvConfig.HasFeature(decl.FeatureGeoIP) {
		a.FeatureGeoIP()
	}

	/*
	 * Black or whitelist features
	 */

	if config.EnvConfig.HasFeature(decl.FeatureLua) {
		if triggered, abortFeatures, err := a.FeatureLua(ctx); err != nil {
			return decl.AuthResultTempFail
		} else if triggered {
			a.FeatureName = decl.FeatureLua

			a.UpdateBruteForceBucketsCounter()
			doAction(decl.LuaActionLua)

			return decl.AuthResultFeatureLua
		} else if abortFeatures {
			return decl.AuthResultOK
		}
	}

	/*
	 * Blacklist features
	 */

	if config.EnvConfig.HasFeature(decl.FeatureTLSEncryption) {
		if a.FeatureTLSEncryption() {
			a.FeatureName = decl.FeatureTLSEncryption

			doAction(decl.LuaActionTLS)

			return decl.AuthResultFeatureTLS
		}
	}

	if config.EnvConfig.HasFeature(decl.FeatureRelayDomains) {
		if a.FeatureRelayDomains() {
			a.FeatureName = decl.FeatureRelayDomains

			a.UpdateBruteForceBucketsCounter()
			doAction(decl.LuaActionRelayDomains)

			return decl.AuthResultFeatureRelayDomain
		}
	}

	if config.EnvConfig.HasFeature(decl.FeatureRBL) {
		if triggered, err := a.FeatureRBLs(ctx); err != nil {
			return decl.AuthResultTempFail
		} else if triggered {
			a.FeatureName = decl.FeatureRBL

			a.UpdateBruteForceBucketsCounter()
			doAction(decl.LuaActionRBL)

			return decl.AuthResultFeatureRBL
		}
	}

	return decl.AuthResultOK
}

// PostLuaAction sends a Lua action to be executed asynchronously.
func (a *Authentication) PostLuaAction(passDBResult *PassDBResult) {
	go func() {
		finished := make(chan action.Done)

		action.RequestChan <- &action.Action{
			LuaAction:         decl.LuaActionPost,
			Debug:             config.EnvConfig.Verbosity.Level() == decl.LogLevelDebug,
			Repeating:         false,
			UserFound:         passDBResult.UserFound,
			Authenticated:     passDBResult.Authenticated,
			NoAuth:            a.NoAuth,
			BruteForceCounter: 0,
			Session:           *a.GUID,
			ClientIP:          a.ClientIP,
			ClientPort:        a.XClientPort,
			ClientHost:        a.ClientHost,
			ClientID:          a.XClientID,
			LocalIP:           a.XLocalIP,
			LocalPort:         a.XPort,
			Username:          a.Username,
			Account: func() string {
				if passDBResult.UserFound {
					return a.GetAccount()
				}

				return ""
			}(),
			UniqueUserID:   a.GetUniqueUserID(),
			DisplayName:    a.GetDisplayName(),
			Password:       a.Password,
			Protocol:       a.Protocol.Get(),
			BruteForceName: a.BruteForceName,
			FeatureName:    a.FeatureName,
			Context:        a.Context,
			FinishedChan:   finished,
		}

		<-finished
	}()
}

// HandlePassword is the mein password checking routine. It calls VerifyPassword to check the user credentials. After
// the verification process ended, it updates user information on the Redis server, if the cache backend is enabled.
//
//nolint:gocognit // Ignore
func (a *Authentication) HandlePassword(ctx *gin.Context) (authResult decl.AuthResult) {
	if a.Username == "" {
		util.DebugModule(decl.DbgAuth, decl.LogKeyGUID, a.GUID, decl.LogKeyMsg, "Empty username")

		return decl.AuthResultEmptyUsername
	}

	if !a.NoAuth && a.Password == "" {
		util.DebugModule(decl.DbgAuth, decl.LogKeyGUID, a.GUID, decl.LogKeyMsg, "Empty password")

		return decl.AuthResultEmptyPassword
	}

	/*
	 * Verify user password
	 */

	var passDBs []*PassDBMap

	useCache := false
	backendPos := make(map[decl.Backend]int)

	for index, passDB := range config.EnvConfig.PassDBs {
		db := passDB.Get()

		switch db {
		case decl.BackendCache:
			passDBs = append(passDBs, &PassDBMap{
				decl.BackendCache,
				CachePassDB,
			})
			useCache = true
		case decl.BackendLDAP:
			passDBs = append(passDBs, &PassDBMap{
				decl.BackendLDAP,
				LDAPPassDB,
			})
		case decl.BackendMySQL, decl.BackendPostgres, decl.BackendSQL:
			passDBs = append(passDBs, &PassDBMap{
				decl.BackendSQL,
				SQLPassDB,
			})
		case decl.BackendLua:
			passDBs = append(passDBs, &PassDBMap{
				decl.BackendLua,
				LuaPassDB,
			})
		}

		backendPos[db] = index
	}

	// Capture the index to know which passdb answered the query
	passDBResult, err := a.VerifyPassword(passDBs)
	if err != nil {
		var detailedError *errors2.DetailedError

		if errors.As(err, &detailedError) {
			level.Error(logging.DefaultErrLogger).Log(
				decl.LogKeyGUID, a.GUID,
				decl.LogKeyError, detailedError.Error(),
				decl.LogKeyErrorDetails, detailedError.GetDetails())
		} else {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err.Error())
		}

		return decl.AuthResultTempFail
	}

	if useCache && !a.NoAuth {
		// Make sure the cache backend is in front of the used backend.
		if passDBResult.Authenticated {
			if backendPos[decl.BackendCache] < backendPos[a.UsedPassDBBackend] {
				var usedBackend backend.CacheNameBackend

				switch a.UsedPassDBBackend {
				case decl.BackendLDAP:
					usedBackend = backend.CacheLDAP
				case decl.BackendMySQL, decl.BackendPostgres, decl.BackendSQL:
					usedBackend = backend.CacheSQL
				case decl.BackendLua:
					usedBackend = backend.CacheLua
				}

				cacheNames := backend.GetCacheNames(a.Protocol.Get(), usedBackend)

				for _, cacheName := range cacheNames.GetStringSlice() {
					var accountName string

					accountName, err = a.GetUserAccountFromRedis()
					if err != nil {
						level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err.Error())

						return decl.AuthResultTempFail
					}

					if accountName != "" {
						redisUserKey := config.EnvConfig.RedisPrefix + "ucp:" + cacheName + ":" + accountName
						ppc := &backend.PositivePasswordCache{
							AccountField:      a.AccountField,
							TOTPSecretField:   a.TOTPSecretField,
							UniqueUserIDField: a.UniqueUserIDField,
							DisplayNameField:  a.DisplayNameField,
							Password: func() string {
								if a.Password != "" {
									return util.GetHash(util.PreparePassword(a.Password))
								}

								return a.Password
							}(),
							Backend:    a.SourcePassDBBackend,
							Attributes: a.Attributes,
						}

						go backend.SaveUserDataToRedis(*a.GUID, redisUserKey, config.EnvConfig.RedisPosCacheTTL, ppc)
					}
				}
			}
		} else {
			util.DebugModule(
				decl.DbgAuth,
				decl.LogKeyGUID, a.GUID,
				"authenticated", false,
				decl.LogKeyMsg, "Calling saveBruteForcePasswordToRedis()",
			)

			// Increase counters
			a.saveBruteForcePasswordToRedis()
		}

		a.getAllPasswordHistories()
	}

	if !passDBResult.Authenticated {
		a.UpdateBruteForceBucketsCounter()
		a.PostLuaAction(passDBResult)

		return decl.AuthResultFail
	}

	// Set new username
	if passDBResult.UserFound {
		if passDBResult.AccountField != nil {
			a.AccountField = passDBResult.AccountField
			a.UsernameReplace = true
		}
	}

	authResult = a.FilterLua(passDBResult, ctx)

	a.PostLuaAction(passDBResult)

	return authResult
}

// FilterLua calls Lua filters which can change the backend result.
func (a *Authentication) FilterLua(passDBResult *PassDBResult, ctx *gin.Context) decl.AuthResult {
	filterRequest := &filter.Request{
		Debug:         config.EnvConfig.Verbosity.Level() == decl.LogLevelDebug,
		UserFound:     passDBResult.UserFound,
		Authenticated: passDBResult.Authenticated,
		NoAuth:        a.NoAuth,
		Session:       *a.GUID,
		ClientIP:      a.ClientIP,
		ClientPort:    a.XClientPort,
		ClientHost:    a.ClientHost,
		ClientID:      a.XClientID,
		LocalIP:       a.XLocalIP,
		LocalPort:     a.XPort,
		Username:      a.Username,
		Account: func() string {
			if passDBResult.UserFound {
				return a.GetAccount()
			}

			return ""
		}(),
		UniqueUserID: a.GetUniqueUserID(),
		DisplayName:  a.GetDisplayName(),
		Protocol:     a.Protocol.String(),
		Password:     a.Password,
		Context:      a.Context,
	}

	filterResult, err := filterRequest.CallFilterLua(ctx)
	if err != nil {
		if !errors.Is(err, errors2.ErrNoFiltersDefined) {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err.Error())

			return decl.AuthResultTempFail
		}
	} else {
		for index := range *filterRequest.Logs {
			a.AdditionalLogs = append(a.AdditionalLogs, (*filterRequest.Logs)[index])
		}

		if filterResult {
			return decl.AuthResultFail
		}
	}

	if passDBResult.Authenticated {
		return decl.AuthResultOK
	}

	return decl.AuthResultFail
}

// ListUserAccounts returns the list of all known users from the account databases.
func (a *Authentication) ListUserAccounts() (accountList AccountList) {
	var accounts []*AccountListMap

	for _, accountDB := range config.EnvConfig.PassDBs {
		switch accountDB.Get() {
		case decl.BackendLDAP:
			accounts = append(accounts, &AccountListMap{
				decl.BackendLDAP,
				LDAPAccountDB,
			})
		case decl.BackendMySQL, decl.BackendPostgres, decl.BackendSQL:
			accounts = append(accounts, &AccountListMap{
				decl.BackendSQL,
				SQLAccountDB,
			})
		case decl.BackendLua:
			accounts = append(accounts, &AccountListMap{
				decl.BackendLua,
				LuaAccountDB,
			})
		}
	}

	for _, accountDB := range accounts {
		result, err := accountDB.fn(a)

		util.DebugModule(decl.DbgAuth, decl.LogKeyGUID, a.GUID, "accountDB", accountDB.backend.String(), "result", fmt.Sprintf("%v", result))

		if err == nil {
			accountList = append(accountList, result...)
		} else {
			var detailedError *errors2.DetailedError
			if errors.As(err, &detailedError) {
				level.Error(logging.DefaultErrLogger).Log(
					decl.LogKeyGUID, a.GUID,
					decl.LogKeyError, detailedError.Error(),
					decl.LogKeyErrorDetails, detailedError.GetDetails())
			} else {
				level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, err)
			}
		}
	}

	return accountList
}

// String returns the string for a PassDBResult object.
func (p PassDBResult) String() string {
	var result string

	value := reflect.ValueOf(p)
	typeOfValue := value.Type()

	for index := 0; index < value.NumField(); index++ {
		result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
	}

	return result[1:]
}

// GetUserAccountFromRedis returns the user account value from the user Redis hash. If none was found, a new entry in
// the hash table is created.
func (a *Authentication) GetUserAccountFromRedis() (accountName string, err error) {
	var (
		assertOk bool
		accounts []string
		values   []any
	)

	key := config.EnvConfig.RedisPrefix + decl.RedisUserHashKey

	accountName, err = backend.LookupUserAccountFromRedis(a.Username)
	if err != nil {
		return
	}

	if accountName != "" {
		return
	}

	if a.AccountField != nil {
		if values, assertOk = a.Attributes[*a.AccountField]; !assertOk {
			return "", errors2.ErrNoAccount
		}

		for index := range values {
			accounts = append(accounts, values[index].(string))
		}

		sort.Sort(sort.StringSlice(accounts))

		accountName = strings.Join(accounts, ":")
		err = backend.RedisHandle.HSet(backend.RedisHandle.Context(), key, a.Username, accountName).Err()
	}

	return
}

// NewAuthentication is a constructor for services found in the request URI.
func NewAuthentication(ctx *gin.Context) *Authentication {
	auth := &Authentication{
		HTTPClientContext: ctx,
	}

	guidStr := ctx.Value(decl.GUIDKey).(string)

	if err := auth.SetStatusCode(ctx.Param("service")); err != nil {
		level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, guidStr, decl.LogKeyError, err)

		return nil
	}

	auth.Protocol = &config.Protocol{}

	switch ctx.Param("service") {
	case decl.ServNginx, decl.ServDovecot, decl.ServUserInfo:
		// Nginx header, see: https://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html#protocol
		auth.Username = ctx.Request.Header.Get("Auth-User")
		auth.UsernameOrig = auth.Username
		auth.Password = ctx.Request.Header.Get("Auth-Pass")

		auth.Protocol.Set(ctx.Request.Header.Get("Auth-Protocol"))

		auth.LoginAttempts = func() uint {
			loginAttempts, err := strconv.Atoi(ctx.Request.Header.Get("Auth-Login-Attempt"))
			if err != nil {
				return 0
			}

			if loginAttempts < 0 {
				loginAttempts = 0
			}

			return uint(loginAttempts)
		}()

		method := ctx.Request.Header.Get("Auth-Method")

		auth.Method = &method

		switch ctx.Query("mode") {
		case "no-auth":
			util.DebugModule(decl.DbgAuth, decl.LogKeyGUID, guidStr, decl.LogKeyMsg, "mode=no-auth")

			auth.NoAuth = true
		case "list-accounts":
			util.DebugModule(decl.DbgAuth, decl.LogKeyGUID, guidStr, decl.LogKeyMsg, "mode=list-accounts")

			auth.ListAccounts = true
		}

		auth.WithClientInfo(ctx)
		auth.WithLocalInfo(ctx)
		auth.WithUserAgent(ctx)
		auth.WithXSSL(ctx)

	case decl.ServSaslauthd:
		method := ctx.PostForm("method")
		realm := ctx.PostForm("realm")
		userAgent := ctx.PostForm("user_agent")

		if len(realm) > 0 {
			auth.Username += "@" + realm
		}

		auth.Method = &method
		auth.UserAgent = &userAgent
		auth.Username = ctx.PostForm("username")
		auth.UsernameOrig = auth.Username
		auth.Password = ctx.PostForm("password")
		auth.Protocol = &config.Protocol{}
		auth.Protocol.Set(ctx.PostForm("protocol"))
		auth.XLocalIP = decl.Localhost4
		auth.XPort = ctx.PostForm("port")
		auth.XSSL = ctx.PostForm("tls")
		auth.XSSLProtocol = ctx.PostForm("security")

	case decl.ServBasicAuth:
		// NOTE: We must get username and password later!
		auth.WithClientInfo(ctx)
		auth.WithLocalInfo(ctx)
		auth.WithUserAgent(ctx)
		auth.WithXSSL(ctx)
	}

	auth.WithDefaults(ctx)

	return auth
}

// WithDefaults sets default values for the Authentication structure including the GUID session value.
func (a *Authentication) WithDefaults(ctx *gin.Context) *Authentication {
	if a == nil {
		return nil
	}

	guidStr := ctx.Value(decl.GUIDKey).(string)

	a.GUID = &guidStr
	a.GeoIPCity = &GeoIPCity{}
	a.UsedPassDBBackend = decl.BackendUnknown
	a.PasswordsAccountSeen = 0
	a.Service = ctx.Param("service")
	a.Context = ctx.Value(decl.DataExchangeKey).(*lualib.Context)

	if a.Protocol.Get() == "" {
		a.Protocol.Set(decl.ProtoDefault)
	}

	return a
}

// WithLocalInfo adds the local IP and -port headers to the Authentication structure.
func (a *Authentication) WithLocalInfo(ctx *gin.Context) *Authentication {
	if a == nil {
		return nil
	}

	a.XLocalIP = ctx.Request.Header.Get("X-Local-IP")
	a.XPort = ctx.Request.Header.Get("X-Auth-Port")

	return a
}

// WithClientInfo adds the client IP, -port and -ID headers to the Authentication structure.
func (a *Authentication) WithClientInfo(ctx *gin.Context) *Authentication {
	if a == nil {
		return nil
	}

	a.ClientIP = ctx.Request.Header.Get("Client-IP")

	if config.EnvConfig.ResolveIP {
		a.ClientHost = util.ResolveIPAddress(a.ClientIP)
	}

	if a.ClientHost == "" {
		// Fallback to environment variable
		a.ClientHost = ctx.Request.Header.Get("Client-Host")
	}

	a.XClientPort = ctx.Request.Header.Get("X-Client-Port")
	a.XClientID = ctx.Request.Header.Get("X-Client-Id")

	return a
}

// WithUserAgent adds the User-Agent header to the Authentication structure.
func (a *Authentication) WithUserAgent(ctx *gin.Context) *Authentication {
	if a == nil {
		return nil
	}

	userAgent := ctx.Request.UserAgent()

	a.UserAgent = &userAgent

	return a
}

// WithXSSL adds HAProxy header processing to the Authentication structure.
func (a *Authentication) WithXSSL(ctx *gin.Context) *Authentication {
	if a == nil {
		return nil
	}

	a.XSSL = util.CheckStrings(
		ctx.Request.Header.Get("Auth-SSL"), ctx.Request.Header.Get("X-SSL"))
	a.XSSLSessionID = util.CheckStrings(ctx.Request.Header.Get("X-SSL-Session-ID"))
	a.XSSLClientVerify = util.CheckStrings(
		ctx.Request.Header.Get("Auth-SSL-Verify"), ctx.Request.Header.Get("X-SSL-Client-Verify"))
	a.XSSLClientDN = util.CheckStrings(
		ctx.Request.Header.Get("Auth-SSL-Subject"), ctx.Request.Header.Get("X-SSL-Client-DN"))
	a.XSSLClientCN = util.CheckStrings(ctx.Request.Header.Get("X-SSL-Client-CN"))
	a.XSSLIssuer = util.CheckStrings(ctx.Request.Header.Get("X-SSL-Issuer"))
	a.XSSLClientNotBefore = util.CheckStrings(ctx.Request.Header.Get("X-SSL-Client-NotBefore"))
	a.XSSLClientNotAfter = util.CheckStrings(ctx.Request.Header.Get("X-SSL-Client-NotAfter"))
	a.XSSLSubjectDN = util.CheckStrings(ctx.Request.Header.Get("X-SSL-Subject-DN"))
	a.XSSLIssuerDN = util.CheckStrings(
		ctx.Request.Header.Get("Auth-SSL-Issuer"), ctx.Request.Header.Get("X-SSL-Issuer-DN"))
	a.XSSLClientSubjectDN = util.CheckStrings(ctx.Request.Header.Get("X-SSL-Client-Subject-DN"))
	a.XSSLClientIssuerDN = util.CheckStrings(ctx.Request.Header.Get("X-SSL-Client-Issuer-DN"))
	a.XSSLCipher = util.CheckStrings(
		ctx.Request.Header.Get("Auth-SSL-Cipher"), ctx.Request.Header.Get("X-SSL-Cipher"))
	a.XSSLProtocol = util.CheckStrings(
		ctx.Request.Header.Get("Auth-SSL-Protocol"), ctx.Request.Header.Get("X-SSL-Protocol"))

	// TODO: Nginx: Auth-SSL-Serial, Auth-SSL-Fingerprint

	return a
}

func (a *Authentication) GetOauth2SubjectAndClaims(oauth2Client openapi.OAuth2Client) (string, map[string]any) {
	var (
		subject string
		claim   any
		claims  map[string]any
		okay    bool
	)

	if config.LoadableConfig.Oauth2 != nil {
		claims = make(map[string]any)

		clientIDFound := false

		for index := range config.LoadableConfig.Oauth2.Clients {
			if config.LoadableConfig.Oauth2.Clients[index].ClientId != oauth2Client.GetClientId() {
				continue
			}

			clientIDFound = true

			util.DebugModule(
				decl.DbgAuth,
				decl.LogKeyGUID, a.GUID,
				decl.LogKeyMsg, fmt.Sprintf("Found client_id: %+v", config.LoadableConfig.Oauth2.Clients[index]),
			)

			valueApplied := false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.Name != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Name]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimName] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimName),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.GivenName != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.GivenName]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimGivenName] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimGivenName),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.FamilyName != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.FamilyName]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimFamilyName] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimFamilyName),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.MiddleName != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.MiddleName]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimMiddleName] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimMiddleName),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.NickName != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.NickName]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimNickName] = arg
						valueApplied = true
					}

					if !valueApplied {
						if !valueApplied {
							level.Warn(logging.DefaultLogger).Log(
								decl.LogKeyGUID, a.GUID,
								decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimNickName),
							)
						}
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.PreferredUserName != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.PreferredUserName]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimPreferredUserName] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimPreferredUserName),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.Profile != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Profile]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimProfile] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimProfile),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.Website != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Website]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimWebsite] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimWebsite),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.Picture != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Picture]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimPicture] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimPicture),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.Email != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Email]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimEmail] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimEmail),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.EmailVerified != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.EmailVerified]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						if boolean, err := strconv.ParseBool(arg); err == nil {
							claims[decl.ClaimEmailVerified] = boolean
							valueApplied = true
						}
					} else if arg, assertOk := value[decl.SliceWithOneElement].(bool); assertOk {
						claims[decl.ClaimEmailVerified] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimEmailVerified),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.Gender != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Gender]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimGender] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimGender),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.Birthdate != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Birthdate]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimBirtDate] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimBirtDate),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.ZoneInfo != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.ZoneInfo]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimZoneInfo] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimZoneInfo),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.Locale != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Locale]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimLocale] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimLocale),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.PhoneNumber != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.PhoneNumber]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						claims[decl.ClaimPhoneNumber] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimPhoneNumber),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.PhoneNumberVerified != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.PhoneNumberVerified]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						if boolean, err := strconv.ParseBool(arg); err == nil {
							claims[decl.ClaimPhoneNumberVerified] = boolean
							valueApplied = true
						}
					} else if arg, assertOk := value[decl.SliceWithOneElement].(bool); assertOk {
						claims[decl.ClaimPhoneNumberVerified] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimPhoneNumberVerified),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.Address != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Address]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
						var formattedAddress = struct {
							FormattedAddress string `json:"formatted"`
						}{
							FormattedAddress: arg,
						}

						if jsonObj, err := json.Marshal(formattedAddress); err == nil {
							claims[decl.ClaimAddress] = jsonObj
							valueApplied = true
						}
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimAddress),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.UpdatedAt != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.UpdatedAt]; found {
					if arg, assertOk := value[decl.SliceWithOneElement].(float64); assertOk {
						claims[decl.ClaimUpdatedAt] = arg
						valueApplied = true
					}
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimUpdatedAt),
						)
					}
				}
			}

			valueApplied = false

			if config.LoadableConfig.Oauth2.Clients[index].Claims.Groups != "" {
				if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Groups]; found {
					var stringSlice []string

					util.DebugModule(
						decl.DbgAuth,
						decl.LogKeyGUID, a.GUID,
						"groups", fmt.Sprintf("%#v", value),
					)

					for anyIndex := range value {
						if arg, assertOk := value[anyIndex].(string); assertOk {
							stringSlice = append(stringSlice, arg)
						}
					}

					claims[decl.ClaimGroups] = stringSlice
					valueApplied = true
				}

				if !valueApplied {
					if !valueApplied {
						level.Warn(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", decl.ClaimGroups),
						)
					}
				}
			}

			if config.LoadableConfig.Oauth2.Clients[index].Subject != "" {
				var value []any

				if value, okay = a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Subject]; !okay {
					level.Info(logging.DefaultLogger).Log(
						decl.LogKeyGUID, a.GUID,
						decl.LogKeyMsg, fmt.Sprintf(
							"Attributes did not contain requested field '%s'",
							config.LoadableConfig.Oauth2.Clients[index].Subject,
						),
						"attributes", func() string {
							var attributes []string

							for key := range a.Attributes {
								attributes = append(attributes, key)
							}

							return strings.Join(attributes, ", ")
						}(),
					)
				} else if _, okay = value[decl.SliceWithOneElement].(string); okay {
					subject = value[decl.SliceWithOneElement].(string)
				}
			}
		}

		for scopeIndex := range config.LoadableConfig.Oauth2.CustomScopes {
			customScope := config.LoadableConfig.Oauth2.CustomScopes[scopeIndex]

			for claimIndex := range customScope.Claims {
				customClaimName := customScope.Claims[claimIndex].Name
				customClaimType := customScope.Claims[claimIndex].Type
				valueTypeMatch := false

				for clientIndex := range config.LoadableConfig.Oauth2.Clients {
					if config.LoadableConfig.Oauth2.Clients[clientIndex].ClientId != oauth2Client.GetClientId() {
						continue
					}

					assertOk := false
					if claim, assertOk = config.LoadableConfig.Oauth2.Clients[clientIndex].Claims.CustomClaims[customClaimName]; !assertOk {
						break
					}

					if claimValue, assertOk := claim.(string); assertOk {
						if value, found := a.Attributes[claimValue]; found {
							util.DebugModule(
								decl.DbgAuth,
								decl.LogKeyGUID, a.GUID,
								"custom_claim_name", customClaimName,
								"custom_claim_type", customClaimType,
								"value", fmt.Sprintf("%#v", value),
							)

							if customClaimType == decl.ClaimTypeString {
								if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
									claims[customClaimName] = arg
									valueTypeMatch = true
								}
							} else if customClaimType == decl.ClaimTypeFloat {
								if arg, assertOk := value[decl.SliceWithOneElement].(float64); assertOk {
									claims[customClaimName] = arg
									valueTypeMatch = true
								} else if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
									if number, err := strconv.ParseFloat(arg, 64); err == nil {
										claims[customClaimName] = number
										valueTypeMatch = true
									}
								}
							} else if customClaimType == decl.ClaimTypeInteger {
								if arg, assertOk := value[decl.SliceWithOneElement].(int64); assertOk {
									claims[customClaimName] = arg
									valueTypeMatch = true
								} else if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
									if number, err := strconv.ParseInt(arg, 0, 64); err == nil {
										claims[customClaimName] = number
										valueTypeMatch = true
									}
								}
							} else if customClaimType == decl.ClaimTypeBoolean {
								if arg, assertOk := value[decl.SliceWithOneElement].(bool); assertOk {
									claims[customClaimName] = arg
									valueTypeMatch = true
								} else if arg, assertOk := value[decl.SliceWithOneElement].(string); assertOk {
									if boolean, err := strconv.ParseBool(arg); err == nil {
										claims[customClaimName] = boolean
										valueTypeMatch = true
									}
								}
							}
						}
					}

					if !valueTypeMatch {
						level.Error(logging.DefaultErrLogger).Log(
							decl.LogKeyGUID, a.GUID,
							"custom_claim_name", customClaimName,
							decl.LogKeyError, fmt.Sprintf("Unknown type '%s'", customClaimType),
						)

					}

					break
				}
			}
		}

		if !clientIDFound {
			level.Warn(logging.DefaultLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyMsg, "No client_id section found")
		}
	} else {
		// Default result, if no oauth2/clients definition is found
		subject = *a.AccountField
	}

	return subject, claims
}
