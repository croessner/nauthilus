package core

import (
	"context"
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
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
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

type ClaimHandler struct {
	Type      reflect.Kind
	ApplyFunc func(value any, claims map[string]any, claimKey string) bool
}

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
	SourcePassDBBackend global.Backend

	// UsedPassDBBackend is set by the password Database that answered the current authentication request.
	UsedPassDBBackend global.Backend

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
	Backend global.Backend

	// Attributes is the result catalog returned by the underlying password Database.
	Attributes backend.DatabaseResult
}

type (
	// PassDBOption
	// This type specifies the signature of a password database.
	PassDBOption func(auth *Authentication) (*PassDBResult, error)

	// PassDBMap is a struct type that represents a mapping between a backend type and a PassDBOption function.
	// It is used in the VerifyPassword method of the Authentication struct to perform password verification against multiple databases.
	// The backend field represents the type of database backend (global.Backend) and the fn field represents the PassDBOption function.
	// The PassDBOption function takes an Authentication pointer as input and returns a PassDBResult pointer and an error.
	// The PassDBResult pointer contains the result of the password verification process.
	// This struct is used to store the database mappings in an array and loop through them in the VerifyPassword method.
	PassDBMap struct {
		backend global.Backend
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
		backend global.Backend
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
			geoIPCityCityName = global.NotAvailable
		}
	} else {
		geoIPCityCityName = global.NotAvailable
	}

	if val, okay := a.GeoIPCity.Country.Names["en"]; okay {
		if val != "" {
			geoIPCityCountryName = val
		} else {
			geoIPCityCountryName = global.NotAvailable
		}
	} else {
		geoIPCityCountryName = global.NotAvailable
	}

	if a.GeoIPCity.Location.TimeZone == "" {
		a.GeoIPCity.Location.TimeZone = global.NotAvailable
	}

	return []any{
		global.LogKeyGUID, util.WithNotAvailable(*a.GUID),
		global.LogKeyGeoIPISOCode, util.WithNotAvailable(a.GeoIPCity.Country.IsoCode),
		global.LogKeyGeoIPCountryName, geoIPCityCountryName,
		global.LogKeyGeoIPCityName, geoIPCityCityName,
		global.LogKeyGeoIPIsInEuropeanUnion, fmt.Sprintf("%v", a.GeoIPCity.Country.IsInEuropeanUnion),
		global.LogKeyGeoIPAccuracyRadius, fmt.Sprintf("%d", a.GeoIPCity.Location.AccuracyRadius),
		global.LogKeyGeoIPLatitude, fmt.Sprintf("%f", a.GeoIPCity.Location.Latitude),
		global.LogKeyGeoIPLongitude, fmt.Sprintf("%f", a.GeoIPCity.Location.Longitude),
		global.LogKeyGeoIPMetroCode, fmt.Sprintf("%d", a.GeoIPCity.Location.MetroCode),
		global.LogKeyGeoIPTimeZone, a.GeoIPCity.Location.TimeZone,
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
		global.LogKeyGUID, util.WithNotAvailable(*a.GUID),
		global.LogKeyProtocol, util.WithNotAvailable(a.Protocol.String()),
		global.LogKeyLocalIP, util.WithNotAvailable(a.XLocalIP),
		global.LogKeyPort, util.WithNotAvailable(a.XPort),
		global.LogKeyClientIP, util.WithNotAvailable(a.ClientIP),
		global.LogKeyClientPort, util.WithNotAvailable(a.XClientPort),
		global.LogKeyClientHost, util.WithNotAvailable(a.ClientHost),
		global.LogKeyTLSSecure, util.WithNotAvailable(a.XSSLProtocol),
		global.LogKeyTLSCipher, util.WithNotAvailable(a.XSSLCipher),
		global.LogKeyAuthMethod, util.WithNotAvailable(a.Method),
		global.LogKeyUsername, util.WithNotAvailable(a.Username),
		global.LogKeyOrigUsername, util.WithNotAvailable(a.UsernameOrig),
		global.LogKeyUsedPassdbBackend, util.WithNotAvailable(a.UsedPassDBBackend.String()),
		global.LogKeyLoginAttempts, a.LoginAttempts,
		global.LogKeyPasswordsAccountSeen, a.PasswordsAccountSeen,
		global.LogKeyPasswordsTotalSeen, a.PasswordsTotalSeen,
		global.LogKeyUserAgent, util.WithNotAvailable(a.UserAgent),
		global.LogKeyClientID, util.WithNotAvailable(a.XClientID),
		global.LogKeyBruteForceName, util.WithNotAvailable(a.BruteForceName),
		global.LogKeyFeatureName, util.WithNotAvailable(a.FeatureName),
		global.LogKeyStatusMessage, util.WithNotAvailable(a.StatusMessage),
		global.LogKeyUriPath, endpoint,
		global.LogKeyStatus, util.WithNotAvailable(status),
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
		if value, assertOk := account[global.LDAPSingleValue].(string); assertOk {
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
		if value, assertOk := totpSecret[global.LDAPSingleValue].(string); assertOk {
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
		if value, assertOk := webAuthnUserID[global.LDAPSingleValue].(string); assertOk {
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
		if value, assertOk := account[global.SliceWithOneElement].(string); assertOk {
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
	setCommonHeaders(ctx, a)
	switch a.Service {
	case global.ServNginx:
		setNginxHeaders(ctx, a)
	case global.ServDovecot:
		setDovecotHeaders(ctx, a)
	case global.ServUserInfo:
		setUserInfoHeaders(ctx, a)
	}

	handleLogging(ctx, a)

	LoginsCounter.WithLabelValues(global.LabelSuccess).Inc()
}

func setCommonHeaders(ctx *gin.Context, a *Authentication) {
	ctx.Header("Auth-Status", "OK")
	ctx.Header("X-Authserv-Session", *a.GUID)

	if a.Service != global.ServBasicAuth && a.UsernameReplace {
		if account, found := a.GetAccountOk(); found {
			ctx.Header("Auth-User", account)
		}
	}
}

func setNginxHeaders(ctx *gin.Context, a *Authentication) {
	switch a.Protocol.Get() {
	case global.ProtoSMTP:
		ctx.Header("Auth-Server", config.EnvConfig.SMTPBackendAddress)
		ctx.Header("Auth-Port", fmt.Sprintf("%d", config.EnvConfig.SMTPBackendPort))
	default:
		ctx.Header("Auth-Server", config.EnvConfig.IMAPBackendAddress)
		ctx.Header("Auth-Port", fmt.Sprintf("%d", config.EnvConfig.IMAPBackendPort))
	}
}

func setDovecotHeaders(ctx *gin.Context, a *Authentication) {
	if a.Attributes != nil && len(a.Attributes) > 0 {
		for name, value := range a.Attributes {
			handleAttributeValue(ctx, name, value)
		}
	}
}

func handleAttributeValue(ctx *gin.Context, name string, value []any) {
	var headerValue string

	if valueLen := len(value); valueLen > 0 {
		switch {
		case valueLen == 1:
			headerValue = fmt.Sprintf("%v", value[global.LDAPSingleValue])
		case valueLen > 1:
			stringValues := formatValues(value)
			separator := ","
			if name == global.DistinguishedName {
				separator = ";"
			}
			headerValue = strings.Join(stringValues, separator)
		}

		ctx.Header("X-Nauthilus-"+name, fmt.Sprintf("%v", headerValue))
	}
}

// formatValues takes an array of values and formats them into strings.
// It creates an empty slice of strings called stringValues.
// It then iterates over each value in the values array and appends the formatted string representation of that value to stringValues using fmt.Sprintf("%v", values[index]).
// After iterating over all the values, it returns stringValues.
// Example usage:
// values := []any{"one", "two", "three"}
// result := formatValues(values)
// fmt.Println(result) // Output: ["one", "two", "three"]
func formatValues(values []any) []string {
	var stringValues []string

	for index := range values {
		stringValues = append(stringValues, fmt.Sprintf("%v", values[index]))
	}

	return stringValues
}

// setUserInfoHeaders sets the necessary headers for the user info response.
// It includes the Content-Type header with the value "application/json; charset=UTF-8".
// It also includes the X-User-Found header with the string representation of a.UserFound.
// Finally, it uses ctx.JSON to send a JSON response with a status code of a.StatusCodeOK and a body of backend.PositivePasswordCache.
func setUserInfoHeaders(ctx *gin.Context, a *Authentication) {
	ctx.Header("Content-Type", "application/json; charset=UTF-8")
	ctx.Header("X-User-Found", fmt.Sprintf("%v", a.UserFound))
	ctx.JSON(a.StatusCodeOK, &backend.PositivePasswordCache{
		AccountField:    a.AccountField,
		TOTPSecretField: a.TOTPSecretField,
		Backend:         a.SourcePassDBBackend,
		Attributes:      a.Attributes,
	})
}

// handleLogging logs information about the authentication request if the verbosity level is greater than LogLevelWarn.
// It uses the logging.DefaultLogger to log the information.
// The logged information includes the result of the a.LogLineMail() function, which returns either "ok" or an empty string depending on the value of a.NoAuth,
// and the path of the request URL obtained from ctx.Request.URL.Path.
func handleLogging(ctx *gin.Context, a *Authentication) {
	if config.EnvConfig.Verbosity.Level() > global.LogLevelWarn {
		level.Info(logging.DefaultLogger).Log(a.LogLineMail(func() string {
			if !a.NoAuth {
				return "ok"
			}

			return ""
		}(), ctx.Request.URL.Path)...)
	}
}

// IncreaseLoginAttempts increments the number of login attempts for the Authentication object.
// If the number of login attempts exceeds the maximum value allowed (MaxUint8), it sets it to the maximum value.
// If the Authentication service is equal to ServNginx and the number of login attempts is less than the maximum login attempts specified in the environment configuration,
// it increments the number of login attempts by one.
// The usage example of this method can be found in the AuthFail function.
func (a *Authentication) IncreaseLoginAttempts() {
	if a.LoginAttempts > math.MaxUint8 {
		a.LoginAttempts = math.MaxUint8
	}

	if a.Service == global.ServNginx {
		if a.LoginAttempts < uint(config.EnvConfig.MaxLoginAttempts) {
			a.LoginAttempts++
		}
	}
}

// SetFailureHeaders sets the failure headers for the given authentication context.
// It sets the "Auth-Status" header to the value of global.PasswordFail constant.
// It sets the "X-Authserv-Session" header to the value of the authentication's GUID field.
// It updates the StatusMessage of the authentication to global.PasswordFail.
//
// If the Service field of the authentication is equal to global.ServUserInfo, it also sets the following headers:
//   - "Content-Type" header to "application/json; charset=UTF-8"
//   - "X-User-Found" header to the string representation of the UserFound field of the authentication
//   - If the PasswordHistory field is not nil, it responds with a JSON representation of the PasswordHistory.
//     If the PasswordHistory field is nil, it responds with an empty JSON object.
//
// If the Service field is not equal to global.ServUserInfo, it responds with the StatusMessage of the authentication as plain text.
func (a *Authentication) SetFailureHeaders(ctx *gin.Context) {
	ctx.Header("Auth-Status", global.PasswordFail)
	ctx.Header("X-Authserv-Session", *a.GUID)

	a.StatusMessage = global.PasswordFail

	if a.Service == global.ServUserInfo {
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
}

// LoginAttemptProcessing performs processing for a failed login attempt.
// It checks the verbosity level in the environment configuration and logs the failed login attempt if it is greater than LogLevelWarn.
// It then increments the LoginsCounter with the LabelFailure.
//
// Example usage:
//
//	a := &Authentication{}
//	ctx := &gin.Context{}
//	a.LoginAttemptProcessing(ctx)
func (a *Authentication) LoginAttemptProcessing(ctx *gin.Context) {
	if config.EnvConfig.Verbosity.Level() > global.LogLevelWarn {
		level.Info(logging.DefaultLogger).Log(a.LogLineMail("fail", ctx.Request.URL.Path)...)
	}

	LoginsCounter.WithLabelValues(global.LabelFailure).Inc()
}

// AuthFail handles the failure of authentication.
// It increases the login attempts, sets failure headers on the context, and performs login attempt processing.
func (a *Authentication) AuthFail(ctx *gin.Context) {
	a.IncreaseLoginAttempts()
	a.SetFailureHeaders(ctx)
	a.LoginAttemptProcessing(ctx)
}

// setSMPTHeaders sets SMTP headers in the specified `gin.Context` if the `Service` is `ServNginx` and the `Protocol` is `ProtoSMTP`.
// It adds the `Auth-Error-Code` header with the value `TempFailCode` from the declaration package.
//
// Example usage:
//
//	a.setSMPTHeaders(ctx)
func (a *Authentication) setSMPTHeaders(ctx *gin.Context) {
	if a.Service == global.ServNginx && a.Protocol.Get() == global.ProtoSMTP {
		ctx.Header("Auth-Error-Code", global.TempFailCode)
	}
}

// setUserInfoHeaders sets the necessary headers for UserInfo service in a Gin context
// Usage example:
//
//	func (a *Authentication) AuthTempFail(ctx *gin.Context, reason string) {
//	    ...
//	    if a.Service == global.ServUserInfo {
//	        a.setUserInfoHeaders(ctx, reason)
//	        return
//	    }
//	    ...
//	}
//
// params:
// - ctx: Gin context
// - reason: Error reason to include in the response
func (a *Authentication) setUserInfoHeaders(ctx *gin.Context, reason string) {
	type errType struct {
		Error string
	}

	ctx.Header("Content-Type", "application/json; charset=UTF-8")
	ctx.Header("X-User-Found", fmt.Sprintf("%v", a.UserFound))

	ctx.JSON(a.StatusCodeInternalError, &errType{Error: reason})
}

// AuthTempFail sets the necessary headers and status message for temporary authentication failure.
// If the service is "user", it also sets headers specific to user information.
// After setting the headers, it returns the appropriate response based on the service.
// If the service is not "user", it returns an internal server error response with the status message.
// If the service is "user", it calls the setUserInfoHeaders method to set additional headers and returns.
//
// Parameters:
// - ctx: The gin context object.
// - reason: The reason for the authentication failure.
//
// Usage example:
//
//	  func (a *Authentication) Generic(ctx *gin.Context) {
//	    ...
//	    a.AuthTempFail(ctx, global.TempFailDefault)
//	    ...
//	  }
//	  func (a *Authentication) SASLauthd(ctx *gin.Context) {
//		   ...
//	    a.AuthTempFail(ctx, global.TempFailDefault)
//	    ...
//	  }
//
// Declaration and usage of AuthTempFail:
//
//	A: func (a *Authentication) AuthTempFail(ctx *gin.Context, reason string) {
//	  ...
//	}
func (a *Authentication) AuthTempFail(ctx *gin.Context, reason string) {
	ctx.Header("Auth-Status", reason)
	ctx.Header("X-Authserv-Session", *a.GUID)
	a.setSMPTHeaders(ctx)

	a.StatusMessage = reason

	if a.Service == global.ServUserInfo {
		a.setUserInfoHeaders(ctx, reason)
		return
	}

	ctx.String(a.StatusCodeInternalError, a.StatusMessage)
	level.Info(logging.DefaultLogger).Log(a.LogLineMail("tempfail", ctx.Request.URL.Path)...)
}

// IsInNetwork checks an IP address against a network and returns true if it matches.
func (a *Authentication) IsInNetwork(networkList []string) (matchIP bool) {
	ipAddress := net.ParseIP(a.ClientIP)

	for _, ipOrNet := range networkList {
		if net.ParseIP(ipOrNet) == nil {
			_, network, err := net.ParseCIDR(ipOrNet)
			if err != nil {
				a.logNetworkError(ipOrNet, err)

				continue
			}

			a.checkAndLogNetwork(network)

			if network.Contains(ipAddress) {
				matchIP = true

				break
			}
		} else {
			a.checkAndLogIP(ipOrNet)
			if a.ClientIP == ipOrNet {
				matchIP = true

				break
			}
		}
	}

	return
}

func (a *Authentication) logNetworkError(ipOrNet string, err error) {
	level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyMsg, "%s is not a network", ipOrNet, global.LogKeyError, err)
}

func (a *Authentication) checkAndLogNetwork(network *net.IPNet) {
	util.DebugModule(
		global.DbgWhitelist,
		global.LogKeyGUID, a.GUID, global.LogKeyMsg, fmt.Sprintf("Checking: %s -> %s", a.ClientIP, network.String()),
	)
}

func (a *Authentication) checkAndLogIP(ipOrNet string) {
	util.DebugModule(global.DbgWhitelist, global.LogKeyGUID, a.GUID, global.LogKeyMsg, fmt.Sprintf("Checking: %s -> %s", a.ClientIP, ipOrNet))
}

// VerifyPassword takes in an array of PassDBMap and performs the following steps:
// - Check if there are any password databases available
// - Iterate over each password database and call the corresponding function
// - Log debug information for each database and its result
// - Handle any backend errors and store them in a map
// - If there is no error, authenticate the user using the result returned by the database function
// - If authentication is successful or NoAuth flag is set, return the passDBResult and nil error
//
// Parameters:
// - passDBs: an array of PassDBMap which contains the backend type and the corresponding function to be called
//
// Return values:
// - passDBResult: a pointer to a PassDBResult struct which contains the authentication result
// - err: an error that occurred during the verification process
func (a *Authentication) VerifyPassword(passDBs []*PassDBMap) (*PassDBResult, error) {
	var (
		passDBResult *PassDBResult
		err          error
	)

	if !isThereAnyDatabase(passDBs) {
		return passDBResult, errors2.ErrNoPassDBs
	}

	configErrors := make(map[global.Backend]error, len(passDBs))
	for passDBIndex, passDB := range passDBs {
		passDBResult, err = passDB.fn(a)
		logDebugModule(a, passDB, passDBResult)

		if err != nil {
			err = handleBackendErrors(passDBIndex, passDBs, passDB, err, a, configErrors)
			if err != nil {
				break
			}
		} else {
			passDBResult, err = authenticateUser(passDBResult, a, passDB)
			if err != nil || a.UserFound {
				break
			}
		}
	}

	// Enforce authentication
	if a.NoAuth {
		passDBResult.Authenticated = true
	}

	return passDBResult, err
}

// isThereAnyDatabase checks if there are any databases in the passDBs slice.
// It returns true if the length of passDBs is greater than 0, otherwise false.
// This function uses the assert.Check function from the testify/assert package to perform the assertion.
//
// Example Usage:
//
//	func (a *Authentication) VerifyPassword(passDBs []*PassDBMap) (*PassDBResult, error) {
//	    var (
//	        passDBResult *PassDBResult
//	        err          error
//	    )
//
//	    if !isThereAnyDatabase(passDBs) {
//	        return passDBResult, errors2.ErrNoPassDBs
//	    }
//
//	    // rest of the code
//	}
func isThereAnyDatabase(passDBs []*PassDBMap) bool {
	t := &testing.T{}

	return assert.Check(t, len(passDBs) > 0)
}

// logDebugModule logs debug information about the authentication process.
//
// Parameters:
//   - a: The Authentication object associated with the authentication process.
//   - passDB: The PassDBMap object representing the password database.
//   - passDBResult: The PassDBResult object containing the result of the authentication process.
//
// The logDebugModule function calls the util.DebugModule function to log the debug information.
// It passes the module declaration (global.DbgAuth) as the first parameter, followed by key-value pairs of additional information.
// The key-value pairs include "session" as the key and a.GUID as the value, "passdb" as the key and passDB.backend.String() as the value,
// and "result" as the key and fmt.Sprintf("%v", passDBResult) as the value.
//
// Example Usage:
//
//	logDebugModule(a, passDB, passDBResult)
//
// This function uses the util.DebugModule function from the package to log the debug information.
func logDebugModule(a *Authentication, passDB *PassDBMap, passDBResult *PassDBResult) {
	util.DebugModule(
		global.DbgAuth,
		global.LogKeyGUID, a.GUID,
		"passdb", passDB.backend.String(),
		"result", fmt.Sprintf("%v", passDBResult))
}

// handleBackendErrors handles the errors that occur during backend processing.
// It checks if the error is a configuration error for SQL, LDAP, or Lua backends and adds them to the configErrors map.
// If all password databases have been processed and there are configuration errors, it calls the checkAllBackends function.
// If the error is not a configuration error, it logs the error using the DefaultErrLogger.
// It returns the error unchanged.
func handleBackendErrors(passDBIndex int, passDBs []*PassDBMap, passDB *PassDBMap, err error, a *Authentication, configErrors map[global.Backend]error) error {
	if errors.Is(err, errors2.ErrSQLConfig) || errors.Is(err, errors2.ErrLDAPConfig) || errors.Is(err, errors2.ErrLuaConfig) {
		configErrors[passDB.backend] = err

		// After all password databases were running,  check if SQL, LDAP and Lua  backends have configuration errors.
		if passDBIndex == len(passDBs)-1 {
			err = checkAllBackends(configErrors, a)
		}
	} else {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, "passdb", passDB.backend.String(), global.LogKeyError, err)
	}

	return err
}

// After all password databases were running, check if SQL, LDAP and Lua backends have configuration errors.
func checkAllBackends(configErrors map[global.Backend]error, a *Authentication) (err error) {
	var allConfigErrors = true

	for _, err = range configErrors {
		if err == nil {
			allConfigErrors = false

			break
		}
	}

	// If all (real) Database backends failed, we must return with a temporary failure
	if allConfigErrors {
		err = errors2.ErrAllBackendConfigError
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, "passdb", "all", global.LogKeyError, err)
	}

	return err
}

// authenticateUser updates the passDBResult based on the provided passDB
// and the Authentication object a.
// If passDBResult is nil, it returns an error of type errors2.ErrNoPassDBResult.
// It then calls the util.DebugModule function to log debug information.
// Next, it calls the updateAuthentication function to update the fields of a based on the values in passDBResult.
// If the UserFound field of passDBResult is true, it sets the UserFound field of a to true.
// Finally, it returns the updated passDBResult and nil error.
func authenticateUser(passDBResult *PassDBResult, a *Authentication, passDB *PassDBMap) (*PassDBResult, error) {
	if passDBResult == nil {
		return passDBResult, errors2.ErrNoPassDBResult
	}

	util.DebugModule(
		global.DbgAuth,
		global.LogKeyGUID, a.GUID,
		"passdb", passDB.backend.String(),
		global.LogKeyUsername, a.Username,
		global.LogKeyOrigUsername, a.UsernameOrig,
		"passdb_result", fmt.Sprintf("%+v", *passDBResult),
	)

	passDBResult = updateAuthentication(a, passDBResult, passDB)

	if passDBResult.UserFound {
		a.UserFound = true
	}

	return passDBResult, nil
}

// updateAuthentication updates the fields of the Authentication struct with the values from the PassDBResult struct.
// It checks if each field in passDBResult is not nil and if it is not nil, it updates the corresponding field in the Authentication struct.
// It also updates the SourcePassDBBackend and UsedPassDBBackend fields of the Authentication struct with the values from passDBResult.Backend and passDB.backend respectively.
// It returns the updated PassDBResult struct.
func updateAuthentication(a *Authentication, passDBResult *PassDBResult, passDB *PassDBMap) *PassDBResult {
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

	a.SourcePassDBBackend = passDBResult.Backend
	a.UsedPassDBBackend = passDB.backend

	return passDBResult
}

// SetStatusCode sets different status codes for various services.
func (a *Authentication) SetStatusCode(service string) error {
	switch service {
	case global.ServNginx, global.ServDovecot:
		a.StatusCodeOK = http.StatusOK
		a.StatusCodeInternalError = http.StatusOK
		a.StatusCodeFail = http.StatusOK
	case global.ServSaslauthd, global.ServBasicAuth, global.ServOryHydra, global.ServUserInfo:
		a.StatusCodeOK = http.StatusOK
		a.StatusCodeInternalError = http.StatusInternalServerError
		a.StatusCodeFail = http.StatusForbidden
	default:
		return errors2.ErrUnknownService
	}

	return nil
}

// HandleFeatures iterates through the list of enabled features and returns true, if a feature returned positive.
func (a *Authentication) HandleFeatures(ctx *gin.Context) (authResult global.AuthResult) {
	// Helper function that sends an action request and waits for it to be finished. Features may change the Lua context.
	// Lua post actions may make use of these changes.
	doAction := func(luaAction global.LuaAction) {
		finished := make(chan action.Done)

		action.RequestChan <- &action.Action{
			LuaAction:    luaAction,
			Debug:        config.EnvConfig.Verbosity.Level() == global.LogLevelDebug,
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

	if config.EnvConfig.HasFeature(global.FeatureGeoIP) {
		a.FeatureGeoIP()
	}

	/*
	 * Black or whitelist features
	 */

	if config.EnvConfig.HasFeature(global.FeatureLua) {
		if triggered, abortFeatures, err := a.FeatureLua(ctx); err != nil {
			return global.AuthResultTempFail
		} else if triggered {
			a.FeatureName = global.FeatureLua

			a.UpdateBruteForceBucketsCounter()
			doAction(global.LuaActionLua)

			return global.AuthResultFeatureLua
		} else if abortFeatures {
			return global.AuthResultOK
		}
	}

	/*
	 * Blacklist features
	 */

	if config.EnvConfig.HasFeature(global.FeatureTLSEncryption) {
		if a.FeatureTLSEncryption() {
			a.FeatureName = global.FeatureTLSEncryption

			doAction(global.LuaActionTLS)

			return global.AuthResultFeatureTLS
		}
	}

	if config.EnvConfig.HasFeature(global.FeatureRelayDomains) {
		if a.FeatureRelayDomains() {
			a.FeatureName = global.FeatureRelayDomains

			a.UpdateBruteForceBucketsCounter()
			doAction(global.LuaActionRelayDomains)

			return global.AuthResultFeatureRelayDomain
		}
	}

	if config.EnvConfig.HasFeature(global.FeatureRBL) {
		if triggered, err := a.FeatureRBLs(ctx); err != nil {
			return global.AuthResultTempFail
		} else if triggered {
			a.FeatureName = global.FeatureRBL

			a.UpdateBruteForceBucketsCounter()
			doAction(global.LuaActionRBL)

			return global.AuthResultFeatureRBL
		}
	}

	return global.AuthResultOK
}

// PostLuaAction sends a Lua action to be executed asynchronously.
func (a *Authentication) PostLuaAction(passDBResult *PassDBResult) {
	go func() {
		finished := make(chan action.Done)

		action.RequestChan <- &action.Action{
			LuaAction:         global.LuaActionPost,
			Debug:             config.EnvConfig.Verbosity.Level() == global.LogLevelDebug,
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
func (a *Authentication) HandlePassword(ctx *gin.Context) (authResult global.AuthResult) {
	if a.Username == "" {
		util.DebugModule(global.DbgAuth, global.LogKeyGUID, a.GUID, global.LogKeyMsg, "Empty username")

		return global.AuthResultEmptyUsername
	}

	if !a.NoAuth && a.Password == "" {
		util.DebugModule(global.DbgAuth, global.LogKeyGUID, a.GUID, global.LogKeyMsg, "Empty password")

		return global.AuthResultEmptyPassword
	}

	/*
	 * Verify user password
	 */

	var passDBs []*PassDBMap

	useCache := false
	backendPos := make(map[global.Backend]int)

	for index, passDB := range config.EnvConfig.PassDBs {
		db := passDB.Get()

		switch db {
		case global.BackendCache:
			passDBs = append(passDBs, &PassDBMap{
				global.BackendCache,
				CachePassDB,
			})
			useCache = true
		case global.BackendLDAP:
			passDBs = append(passDBs, &PassDBMap{
				global.BackendLDAP,
				LDAPPassDB,
			})
		case global.BackendMySQL, global.BackendPostgres, global.BackendSQL:
			passDBs = append(passDBs, &PassDBMap{
				global.BackendSQL,
				SQLPassDB,
			})
		case global.BackendLua:
			passDBs = append(passDBs, &PassDBMap{
				global.BackendLua,
				LuaPassDB,
			})
		case global.BackendUnknown:
		}

		backendPos[db] = index
	}

	// Capture the index to know which passdb answered the query
	passDBResult, err := a.VerifyPassword(passDBs)
	if err != nil {
		var detailedError *errors2.DetailedError

		if errors.As(err, &detailedError) {
			level.Error(logging.DefaultErrLogger).Log(
				global.LogKeyGUID, a.GUID,
				global.LogKeyError, detailedError.Error(),
				global.LogKeyErrorDetails, detailedError.GetDetails())
		} else {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err.Error())
		}

		return global.AuthResultTempFail
	}

	if useCache && !a.NoAuth {
		// Make sure the cache backend is in front of the used backend.
		if passDBResult.Authenticated {
			if backendPos[global.BackendCache] < backendPos[a.UsedPassDBBackend] {
				var usedBackend global.CacheNameBackend

				switch a.UsedPassDBBackend {
				case global.BackendLDAP:
					usedBackend = global.CacheLDAP
				case global.BackendMySQL, global.BackendPostgres, global.BackendSQL:
					usedBackend = global.CacheSQL
				case global.BackendLua:
					usedBackend = global.CacheLua
				case global.BackendUnknown:
				case global.BackendCache:
				}

				cacheNames := backend.GetCacheNames(a.Protocol.Get(), usedBackend)

				for _, cacheName := range cacheNames.GetStringSlice() {
					var accountName string

					accountName, err = a.GetUserAccountFromRedis()
					if err != nil {
						level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err.Error())

						return global.AuthResultTempFail
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
				global.DbgAuth,
				global.LogKeyGUID, a.GUID,
				"authenticated", false,
				global.LogKeyMsg, "Calling saveBruteForcePasswordToRedis()",
			)

			// Increase counters
			a.saveBruteForcePasswordToRedis()
		}

		a.getAllPasswordHistories()
	}

	if !passDBResult.Authenticated {
		a.UpdateBruteForceBucketsCounter()
		a.PostLuaAction(passDBResult)

		return global.AuthResultFail
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
func (a *Authentication) FilterLua(passDBResult *PassDBResult, ctx *gin.Context) global.AuthResult {
	filterRequest := &filter.Request{
		Debug:         config.EnvConfig.Verbosity.Level() == global.LogLevelDebug,
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
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err.Error())

			return global.AuthResultTempFail
		}
	} else {
		for index := range *filterRequest.Logs {
			a.AdditionalLogs = append(a.AdditionalLogs, (*filterRequest.Logs)[index])
		}

		if filterResult {
			return global.AuthResultFail
		}
	}

	if passDBResult.Authenticated {
		return global.AuthResultOK
	}

	return global.AuthResultFail
}

// ListUserAccounts returns the list of all known users from the account databases.
func (a *Authentication) ListUserAccounts() (accountList AccountList) {
	var accounts []*AccountListMap

	for _, accountDB := range config.EnvConfig.PassDBs {
		switch accountDB.Get() {
		case global.BackendLDAP:
			accounts = append(accounts, &AccountListMap{
				global.BackendLDAP,
				LDAPAccountDB,
			})
		case global.BackendMySQL, global.BackendPostgres, global.BackendSQL:
			accounts = append(accounts, &AccountListMap{
				global.BackendSQL,
				SQLAccountDB,
			})
		case global.BackendLua:
			accounts = append(accounts, &AccountListMap{
				global.BackendLua,
				LuaAccountDB,
			})
		case global.BackendUnknown:
		case global.BackendCache:
		}
	}

	for _, accountDB := range accounts {
		result, err := accountDB.fn(a)

		util.DebugModule(global.DbgAuth, global.LogKeyGUID, a.GUID, "accountDB", accountDB.backend.String(), "result", fmt.Sprintf("%v", result))

		if err == nil {
			accountList = append(accountList, result...)
		} else {
			var detailedError *errors2.DetailedError
			if errors.As(err, &detailedError) {
				level.Error(logging.DefaultErrLogger).Log(
					global.LogKeyGUID, a.GUID,
					global.LogKeyError, detailedError.Error(),
					global.LogKeyErrorDetails, detailedError.GetDetails())
			} else {
				level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, err)
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

	key := config.EnvConfig.RedisPrefix + global.RedisUserHashKey

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

	guidStr := ctx.Value(global.GUIDKey).(string)

	if err := auth.SetStatusCode(ctx.Param("service")); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guidStr, global.LogKeyError, err)

		return nil
	}

	auth.Protocol = &config.Protocol{}

	switch ctx.Param("service") {
	case global.ServNginx, global.ServDovecot, global.ServUserInfo:
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
			util.DebugModule(global.DbgAuth, global.LogKeyGUID, guidStr, global.LogKeyMsg, "mode=no-auth")

			auth.NoAuth = true
		case "list-accounts":
			util.DebugModule(global.DbgAuth, global.LogKeyGUID, guidStr, global.LogKeyMsg, "mode=list-accounts")

			auth.ListAccounts = true
		}

		auth.WithClientInfo(ctx)
		auth.WithLocalInfo(ctx)
		auth.WithUserAgent(ctx)
		auth.WithXSSL(ctx)

	case global.ServSaslauthd:
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
		auth.XLocalIP = global.Localhost4
		auth.XPort = ctx.PostForm("port")
		auth.XSSL = ctx.PostForm("tls")
		auth.XSSLProtocol = ctx.PostForm("security")

	case global.ServBasicAuth:
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

	guidStr := ctx.Value(global.GUIDKey).(string)

	a.GUID = &guidStr
	a.GeoIPCity = &GeoIPCity{}
	a.UsedPassDBBackend = global.BackendUnknown
	a.PasswordsAccountSeen = 0
	a.Service = ctx.Param("service")
	a.Context = ctx.Value(global.DataExchangeKey).(*lualib.Context)

	if a.Protocol.Get() == "" {
		a.Protocol.Set(global.ProtoDefault)
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

// processClaim processes a claim and updates the claims map with the claimName and claimValue.
// If the claimValue is not empty and found in the Attributes map of the Authentication object,
// the claimValue is set in the claims map with the claimName as key.
// Otherwise, a warning is logged.
//
// Parameters:
// - claimName: The name of the claim to process.
// - claimValue: The value of the claim to process.
// - claims: The map to update with the processed claim.
func (a *Authentication) processClaim(claimName string, claimValue string, claims map[string]any) {
	if claimValue != "" {
		if value, found := a.Attributes[claimValue]; found {
			if arg, assertOk := value[global.SliceWithOneElement].(string); assertOk {
				claims[claimName] = arg

				return
			}
		}

		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyGUID, a.GUID,
			global.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from database", claimName),
		)
	}
}

// Custom logic to apply string claims
func applyClaim(claimKey string, attributeKey string, a *Authentication, claims map[string]any, claimHandlers []ClaimHandler) {
	var success bool

	if attributeValue, found := a.Attributes[attributeKey]; found {
		for _, handler := range claimHandlers {
			if t := reflect.TypeOf(attributeValue).Kind(); t == handler.Type {
				success = handler.ApplyFunc(attributeValue, claims, claimKey)
				if success {
					break
				}
			}
		}
	}

	if !success {
		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyGUID, a.GUID,
			global.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", claimKey),
		)
	}
}

// processClientClaims processes the client claims by iterating over a map of claim names and values.
// The claim names and corresponding values to process are defined in the claimChecks map.
// For each claim, it calls the processClaim method to apply any necessary processing logic and update the claims map.
// Finally, it returns the updated claims map.
//
// Parameters:
// - client: a pointer to the config.Oauth2Client structure representing the client configuration
// - claims: a map[string]any representing the client claims
//
// Returns:
// - a map[string]any representing the updated client claims
//
// Example usage:
//
//	clientClaims := make(map[string]any)
//	updatedClaims := a.processClientClaims(&oauth2Client, clientClaims)
//	fmt.Println(updatedClaims)
func (a *Authentication) processClientClaims(client *config.Oauth2Client, claims map[string]any) map[string]any {
	// Claim names to process
	claimChecks := map[string]string{
		global.ClaimName:              client.Claims.Name,
		global.ClaimGivenName:         client.Claims.GivenName,
		global.ClaimFamilyName:        client.Claims.FamilyName,
		global.ClaimMiddleName:        client.Claims.MiddleName,
		global.ClaimNickName:          client.Claims.NickName,
		global.ClaimPreferredUserName: client.Claims.PreferredUserName,
		global.ClaimProfile:           client.Claims.Profile,
		global.ClaimWebsite:           client.Claims.Website,
		global.ClaimPicture:           client.Claims.Picture,
		global.ClaimEmail:             client.Claims.Email,
		global.ClaimGender:            client.Claims.Gender,
		global.ClaimBirtDate:          client.Claims.Birthdate,
		global.ClaimZoneInfo:          client.Claims.ZoneInfo,
		global.ClaimLocale:            client.Claims.Locale,
		global.ClaimPhoneNumber:       client.Claims.PhoneNumber,
	}

	for claimName, claimVal := range claimChecks {
		a.processClaim(claimName, claimVal, claims)
	}

	return claims
}

// applyClientClaimHandlers applies claim handlers to client claims and returns the modified claims.
func (a *Authentication) applyClientClaimHandlers(client *config.Oauth2Client, claims map[string]any) map[string]any {
	claimHandlers := []ClaimHandler{
		{
			Type: reflect.String,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if strValue, ok := value.(string); ok {
					if claimKey == global.ClaimEmailVerified || claimKey == global.ClaimPhoneNumberVerified {
						if boolean, err := strconv.ParseBool(strValue); err == nil {
							claims[claimKey] = boolean

							return true
						}
					} else if claimKey == global.ClaimAddress {
						claims[claimKey] = struct {
							Formatted string `json:"formatted"`
						}{Formatted: strValue}

						return true
					}
				}

				return false
			},
		},
		{
			Type: reflect.Bool,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if boolValue, ok := value.(bool); ok {
					claims[claimKey] = boolValue

					return true
				}

				return false
			},
		},
		{
			Type: reflect.Float64,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if floatValue, ok := value.(float64); ok {
					claims[claimKey] = floatValue

					return true
				}

				return false
			},
		},
	}

	claimKeys := map[string]string{
		global.ClaimEmailVerified:       client.Claims.EmailVerified,
		global.ClaimPhoneNumberVerified: client.Claims.PhoneNumberVerified,
		global.ClaimAddress:             client.Claims.Address,
		global.ClaimUpdatedAt:           client.Claims.UpdatedAt,
	}

	for claimKey, attrKey := range claimKeys {
		if attrKey != "" {
			applyClaim(claimKey, attrKey, a, claims, claimHandlers)
		}
	}

	return claims
}

// processGroupsClaim processes the groups claim for the specified index in the OAuth2 clients configuration.
// It checks if the claim is defined and retrieves the corresponding value from the Authentication object's Attributes.
// If the value is found and is of type string, it adds it to the provided `claims` map with the key `ClaimGroups`.
// It sets the `valueApplied` flag to true if the value is successfully applied to the `claims` map.
// If the value is not found or is not of type string, it logs a warning message.
// The purpose of the method is to populate the groups claim in the `claims` map for the given OAuth2 client.
//
// Parameters:
// - index: The index of the OAuth2 client in the configuration.
// - claims: The `claims` map to populate with the groups claim.
//
// Example usage:
// ```go
// clientIndex := 0
// claims := make(map[string]any)
// authentication.processGroupsClaim(clientIndex, claims)
// ```
//
// Note: This method relies on the following declarations:
// - `config.LoadableConfig.Oauth2.Clients`: The OAuth2 clients configuration.
// - `a.Attributes`: The Authentication object's Attributes map.
// - `util.DebugModule`: A function for logging debug messages.
// - `global.DbgModule`, `global.LogKeyGUID`, `global.ClaimGroups`, `logging.DefaultLogger`, `global.LogKeyWarning`: Various declarations used internally in the method.
func (a *Authentication) processGroupsClaim(index int, claims map[string]any) {
	valueApplied := false

	if config.LoadableConfig.Oauth2.Clients[index].Claims.Groups != "" {
		if value, found := a.Attributes[config.LoadableConfig.Oauth2.Clients[index].Claims.Groups]; found {
			var stringSlice []string

			util.DebugModule(
				global.DbgAuth,
				global.LogKeyGUID, a.GUID,
				"groups", fmt.Sprintf("%#v", value),
			)

			for anyIndex := range value {
				if arg, assertOk := value[anyIndex].(string); assertOk {
					stringSlice = append(stringSlice, arg)
				}
			}

			claims[global.ClaimGroups] = stringSlice
			valueApplied = true
		}

		if !valueApplied {
			if !valueApplied {
				level.Warn(logging.DefaultLogger).Log(
					global.LogKeyGUID, a.GUID,
					global.LogKeyWarning, fmt.Sprintf("Claim '%s' malformed or not returned from Database", global.ClaimGroups),
				)
			}
		}
	}
}

// processCustomClaims processes custom claims for a specific scope and OAuth2 client.
// It retrieves the custom claim names and types from the configuration and checks if
// the client has defined values for those claims. If so, it converts the claim value
// to the corresponding type and adds it to the claims map.
//
// Parameters:
// - scopeIndex: the index of the custom scope to process
// - oauth2Client: the OAuth2 client to process claims for
// - claims: the map to store the processed claims
//
// Example usage:
// ```
// auth := &Authentication{}
// processCustomClaims(0, oauth2Client, auth.Claims)
// ```
func (a *Authentication) processCustomClaims(scopeIndex int, oauth2Client openapi.OAuth2Client, claims map[string]any) {
	var claim any

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
						global.DbgAuth,
						global.LogKeyGUID, a.GUID,
						"custom_claim_name", customClaimName,
						"custom_claim_type", customClaimType,
						"value", fmt.Sprintf("%#v", value),
					)

					if customClaimType == global.ClaimTypeString {
						if arg, assertOk := value[global.SliceWithOneElement].(string); assertOk {
							claims[customClaimName] = arg
							valueTypeMatch = true
						}
					} else if customClaimType == global.ClaimTypeFloat {
						if arg, assertOk := value[global.SliceWithOneElement].(float64); assertOk {
							claims[customClaimName] = arg
							valueTypeMatch = true
						} else if arg, assertOk := value[global.SliceWithOneElement].(string); assertOk {
							if number, err := strconv.ParseFloat(arg, 64); err == nil {
								claims[customClaimName] = number
								valueTypeMatch = true
							}
						}
					} else if customClaimType == global.ClaimTypeInteger {
						if arg, assertOk := value[global.SliceWithOneElement].(int64); assertOk {
							claims[customClaimName] = arg
							valueTypeMatch = true
						} else if arg, assertOk := value[global.SliceWithOneElement].(string); assertOk {
							if number, err := strconv.ParseInt(arg, 0, 64); err == nil {
								claims[customClaimName] = number
								valueTypeMatch = true
							}
						}
					} else if customClaimType == global.ClaimTypeBoolean {
						if arg, assertOk := value[global.SliceWithOneElement].(bool); assertOk {
							claims[customClaimName] = arg
							valueTypeMatch = true
						} else if arg, assertOk := value[global.SliceWithOneElement].(string); assertOk {
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
					global.LogKeyGUID, a.GUID,
					"custom_claim_name", customClaimName,
					global.LogKeyError, fmt.Sprintf("Unknown type '%s'", customClaimType),
				)

			}

			break
		}
	}
}

// GetOauth2SubjectAndClaims retrieves the subject and claims for an OAuth2 client. It takes an OAuth2 client as a
// parameter and returns the subject and claims as a string and a map
func (a *Authentication) GetOauth2SubjectAndClaims(oauth2Client openapi.OAuth2Client) (string, map[string]any) {
	var (
		okay    bool
		index   int
		subject string
		client  config.Oauth2Client
		claims  map[string]any
	)

	if config.LoadableConfig.Oauth2 != nil {
		claims = make(map[string]any)

		clientIDFound := false

		for index, client = range config.LoadableConfig.Oauth2.Clients {
			if client.ClientId == oauth2Client.GetClientId() {
				clientIDFound = true

				util.DebugModule(
					global.DbgAuth,
					global.LogKeyGUID, a.GUID,
					global.LogKeyMsg, fmt.Sprintf("Found client_id: %+v", client),
				)

				claims = a.processClientClaims(&client, claims)
				claims = a.applyClientClaimHandlers(&client, claims)
				a.processGroupsClaim(index, claims)

				break //exit loop once first matching client found
			}
		}

		for scopeIndex := range config.LoadableConfig.Oauth2.CustomScopes {
			a.processCustomClaims(scopeIndex, oauth2Client, claims)
		}

		if client.Subject != "" {
			var value []any

			if value, okay = a.Attributes[client.Subject]; !okay {
				level.Info(logging.DefaultLogger).Log(
					global.LogKeyGUID, a.GUID,
					global.LogKeyMsg, fmt.Sprintf(
						"Attributes did not contain requested field '%s'",
						client.Subject,
					),
					"attributes", func() string {
						var attributes []string

						for key := range a.Attributes {
							attributes = append(attributes, key)
						}

						return strings.Join(attributes, ", ")
					}(),
				)
			} else if _, okay = value[global.SliceWithOneElement].(string); okay {
				subject = value[global.SliceWithOneElement].(string)
			}
		}

		if !clientIDFound {
			level.Warn(logging.DefaultLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyMsg, "No client_id section found")
		}
	} else {
		// Default result, if no oauth2/clients definition is found
		subject = *a.AccountField
	}

	return subject, claims
}
