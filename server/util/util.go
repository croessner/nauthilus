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

package util

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"hash"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/simia-tech/crypt"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Legal characters for IMAP username based on RFC 3501: Any character except "(", ")", "{", SP, CTL, "%", """, "\". The "*" might be used as master separator.
var usernamePattern = regexp.MustCompile(`^[^(){}%"\\]+$`)

// RedisLogger implements the interface redis.Logging
type RedisLogger struct{}

// Printf implements the printf function from Redis.
func (r *RedisLogger) Printf(_ context.Context, format string, values ...any) {
	level.Info(log.Logger).Log("redis", fmt.Sprintf(format, values...))
}

// CryptPassword is a container for an encrypted password typically used in SQL fields.
type CryptPassword struct {
	definitions.Algorithm
	definitions.PasswordOption
	Password string
	Salt     []byte
}

// Generate creates the encrypted form of a plain text password.
func (c *CryptPassword) Generate(plainPassword string, salt []byte, alg definitions.Algorithm, pwOption definitions.PasswordOption) (
	string, error,
) {
	var (
		hashSalt  []byte
		hashValue hash.Hash
	)

	c.Salt = salt
	hashSalt = append([]byte(plainPassword), salt...)

	switch alg {
	case definitions.SSHA512:
		hashValue = sha512.New()
		c.Algorithm = definitions.SSHA512
	case definitions.SSHA256:
		hashValue = sha256.New()
		c.Algorithm = definitions.SSHA256
	default:
		return "", errors.ErrUnsupportedAlgorithm
	}

	hashValue.Write(hashSalt)

	switch pwOption {
	case definitions.B64:
		c.Password = base64.StdEncoding.EncodeToString(append(hashValue.Sum(nil), salt...))
		c.PasswordOption = definitions.B64
	case definitions.HEX:
		c.Password = hex.EncodeToString(append(hashValue.Sum(nil), salt...))
		c.PasswordOption = definitions.HEX
	default:
		return "", errors.ErrUnsupportedPasswordOption
	}

	return c.Password, nil
}

// GetParameters splits an encoded password into its components.
func (c *CryptPassword) GetParameters(cryptedPassword string) (
	salt []byte, alg definitions.Algorithm, pwOption definitions.PasswordOption, err error,
) {
	var decodedPwSasltSalt []byte

	pattern := `SSHA(256|512)(\.HEX|\.B64)?`
	re := regexp.MustCompile(pattern)
	passwordPrefix := re.FindString(cryptedPassword)

	if strings.HasPrefix(passwordPrefix, "SSHA512") {
		alg = definitions.SSHA512
	} else {
		if strings.HasPrefix(passwordPrefix, "SSHA256") {
			alg = definitions.SSHA256
		} else {
			return salt, alg, pwOption, errors.ErrUnsupportedAlgorithm
		}
	}

	c.Algorithm = alg

	if strings.HasSuffix(passwordPrefix, ".B64") {
		pwOption = definitions.B64
	} else {
		if strings.HasSuffix(passwordPrefix, ".HEX") {
			pwOption = definitions.HEX
		}
	}

	// {SSHA256} or {SSHA512} without suffix
	if len(passwordPrefix) == 7 {
		pwOption = definitions.B64
	}

	c.PasswordOption = pwOption

	c.Password = cryptedPassword[strings.Index(cryptedPassword, "}")+1:]

	//goland:noinspection GoDfaConstantCondition
	switch pwOption {
	case definitions.B64:
		decodedPwSasltSalt, err = base64.StdEncoding.DecodeString(c.Password)
	case definitions.HEX:
		decodedPwSasltSalt, err = hex.DecodeString(c.Password)
	}

	if err != nil {
		return salt, alg, pwOption, err
	}

	//goland:noinspection GoDfaConstantCondition
	switch alg {
	case definitions.SSHA512:
		if len(decodedPwSasltSalt) < 65 {
			return salt, alg, pwOption, errors.ErrUnsupportedAlgorithm
		}

		salt = decodedPwSasltSalt[64:]
	case definitions.SSHA256:
		if len(decodedPwSasltSalt) < 33 {
			return salt, alg, pwOption, errors.ErrUnsupportedAlgorithm
		}

		salt = decodedPwSasltSalt[32:]
	}

	c.Salt = salt

	return salt, alg, pwOption, nil
}

func PreparePassword(password string) string {
	return fmt.Sprintf("%s\x00%s", config.GetFile().GetServer().Redis.PasswordNonce, password)
}

// GetHash creates an SHA-256 hash of a plain text password and returns the first 128 bits.
func GetHash(value string) string {
	if config.GetEnvironment().GetDevMode() {
		return value
	}

	hashValue := sha256.New()
	hashValue.Write([]byte(value))

	// 32 bit is good enough
	return hex.EncodeToString(hashValue.Sum(nil))[:8]
}

// ResolveIPAddress returns the hostname for a given IP address.
func ResolveIPAddress(ctx context.Context, address string) (hostname string) {
	ctxTimeout, cancel := context.WithDeadline(ctx, time.Now().Add(config.GetFile().GetServer().GetDNS().GetTimeout()*time.Second))

	defer cancel()

	resolver := NewDNSResolver()

	if hostNames, err := resolver.LookupAddr(ctxTimeout, address); err == nil {
		if len(hostNames) > 0 {
			hostname = hostNames[0]
			hostname = strings.TrimSuffix(hostname, ".")
		}
	}

	return hostname
}

func ProtoErrToFields(err error) (fields []zap.Field) {
	var e *protocol.Error

	if err == nil {
		return nil
	}

	switch {
	case stderrors.As(err, &e):
		return []zap.Field{
			{Key: "err", Type: zapcore.ErrorType, Interface: e},
			{Key: "details", Type: zapcore.StringType, String: e.Details},
			{Key: "info", Type: zapcore.StringType, String: e.DevInfo},
			{Key: "type", Type: zapcore.StringType, String: e.Type},
		}
	default:
		return nil
	}
}

func RemoveCRLFFromQueryOrFilter(value string, sep string) string {
	re := regexp.MustCompile(`\s*[\r\n]+\s*`)

	return re.ReplaceAllString(value, sep)
}

func DebugModule(module definitions.DbgModule, keyvals ...any) {
	var moduleName string

	if config.GetFile().GetServer().GetLog().GetLogLevel() < definitions.LogLevelDebug {
		return
	}

	switch module {
	case definitions.DbgAll:
		moduleName = definitions.DbgAllName
	case definitions.DbgAuth:
		moduleName = definitions.DbgAuthName
	case definitions.DbgHydra:
		moduleName = definitions.DbgHydraName
	case definitions.DbgWebAuthn:
		moduleName = definitions.DbgWebAuthnName
	case definitions.DbgStats:
		moduleName = definitions.DbgStatsName
	case definitions.DbgWhitelist:
		moduleName = definitions.DbgWhitelistName
	case definitions.DbgLDAP:
		moduleName = definitions.DbgLDAPName
	case definitions.DbgLDAPPool:
		moduleName = definitions.DbgLDAPPoolName
	case definitions.DbgCache:
		moduleName = definitions.DbgCacheName
	case definitions.DbgBf:
		moduleName = definitions.DbgBfName
	case definitions.DbgRBL:
		moduleName = definitions.DbgRBLName
	case definitions.DbgAction:
		moduleName = definitions.DbgActionName
	case definitions.DbgFeature:
		moduleName = definitions.DbgFeatureName
	case definitions.DbgLua:
		moduleName = definitions.DbgLuaName
	case definitions.DbgFilter:
		moduleName = definitions.DbgFilterName
	case definitions.DbgTolerate:
		moduleName = definitions.DbgTolerateName
	case definitions.DbgNeural:
		moduleName = definitions.DbgNeuralName
	case definitions.DbgJWT:
		moduleName = definitions.DbgJWTName
	case definitions.DbgHTTP:
		moduleName = definitions.DbgHTTPName
	default:
		return
	}

	for index := range config.GetFile().GetServer().GetLog().GetDebugModules() {
		if !(config.GetFile().GetServer().GetLog().GetDebugModules()[index].GetModule() == definitions.DbgAll ||
			config.GetFile().GetServer().GetLog().GetDebugModules()[index].GetModule() == module) {
			continue
		}

		keyvals = append(keyvals, "debug_module")
		keyvals = append(keyvals, moduleName)

		if counter, _, _, ok := runtime.Caller(1); ok {
			keyvals = append(keyvals, "function")
			keyvals = append(keyvals, runtime.FuncForPC(counter).Name())

			level.Debug(log.Logger).Log(keyvals...)
		}

		break
	}
}

// WithNotAvailable returns a default "not available" string if the given value is an empty string.
func WithNotAvailable(value string) string {
	if value == "" {
		return definitions.NotAvailable
	}

	return value
}

// logNetworkError logs a network error message.
// a.logNetworkError(ipOrNet, err)
func logNetworkError(guid, ipOrNet string, err error) {
	level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "%s is not a network", ipOrNet, definitions.LogKeyMsg, err)
}

// logNetworkChecking logs the information about checking a network for the given authentication object.
func logNetworkChecking(guid, clientIP string, network *net.IPNet) {
	DebugModule(
		definitions.DbgWhitelist,
		definitions.LogKeyGUID, guid, definitions.LogKeyMsg, fmt.Sprintf("Checking: %s -> %s", clientIP, network.String()),
	)
}

// logIPChecking logs the IP address of the client along with the IP address or network being checked.
func logIPChecking(guid, ipOrNet, clientIP string) {
	DebugModule(definitions.DbgWhitelist, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, fmt.Sprintf("Checking: %s -> %s", clientIP, ipOrNet))
}

// IsInNetwork checks if an IP address is part of a list of networks.
// It iterates through the networkList and checks each network if it contains the given IP address.
// The function returns true if there is a match.
// The function logs any network errors encountered during the process.
// The function logs the information about checking a network for the given authentication object.
// The function logs the IP address of the client along with the IP address or network being checked.
func IsInNetwork(networkList []string, guid, clientIP string) (matchIP bool) {
	ipAddress := net.ParseIP(clientIP)

	for _, ipOrNet := range networkList {
		if net.ParseIP(ipOrNet) == nil {
			_, network, err := net.ParseCIDR(ipOrNet)
			if err != nil {
				logNetworkError(guid, ipOrNet, err)

				continue
			}

			logNetworkChecking(guid, clientIP, network)

			if network.Contains(ipAddress) {
				matchIP = true

				break
			}
		} else {
			logIPChecking(guid, ipOrNet, clientIP)
			if clientIP == ipOrNet {
				matchIP = true

				break
			}
		}
	}

	return
}

// IsSoftWhitelisted checks whether a given clientIP is in the soft whitelist associated with a username.
// Returns true if the clientIP matches any networks in the soft whitelist, otherwise false.
func IsSoftWhitelisted(username, clientIP, guid string, softWhitelist config.SoftWhitelist) bool {
	networks := softWhitelist.Get(username)
	if networks == nil {
		return false
	}

	return IsInNetwork(networks, guid, clientIP)
}

// logForwarderFound logs the finding of the header "X-Forwarded-For" in the debug module.
func logForwarderFound(guid string) {
	DebugModule(
		definitions.DbgAuth,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, "Found header X-Forwarded-For",
	)
}

// logNoTrustedProxies logs a warning message indicating that the client IP
// does not match the trusted proxies. The function uses the level.Warn
// function from the log package to log the warning message. The message
// includes the client IP and the list of trusted proxies. The log entry is
// created with the LogKeyGUID key set to the value of the guid parameter,
// and the LogKeyWarning key set to the formatted warning message.
func logNoTrustedProxies(guid, clientIP string) {
	level.Warn(
		log.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Client IP '%s' not matching %v", clientIP, viper.GetStringSlice("trusted_proxies")),
	)
}

// logTrustedProxy logs the client IP matching with the forwarded address.
func logTrustedProxy(guid string, fwdAddress, clientIP string) {
	DebugModule(
		definitions.DbgAuth,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf(
			"Client IP '%s' matching, forwarded for '%s'", clientIP, fwdAddress),
	)
}

// ProcessXForwardedFor processes the X-Forwarded-For header in the given Gin context,
// extracting the forwarded address and updating the client IP and port accordingly.
// If the forwarded address is not empty, the function checks if the client IP is in the list
// of trusted proxies. If it is not, a warning message is logged and the function returns.
// If the client IP is in the list of trusted proxies, the function logs the matching of
// the client IP with the forwarded address and updates the client IP to the forwarded address.
// If the forwarded address contains multiple IP addresses separated by a comma, the first
// IP address is used as the client IP. The client port is set to "N/A".
func ProcessXForwardedFor(ctx *gin.Context, clientIP, clientPort *string, xssl *string) {
	fwdAddress := ctx.GetHeader("X-Forwarded-For")
	guid := ctx.GetString(definitions.CtxGUIDKey)

	if fwdAddress != "" {
		logForwarderFound(guid)

		if !IsInNetwork(viper.GetStringSlice("trusted_proxies"), guid, *clientIP) {
			logNoTrustedProxies(guid, *clientIP)

			return
		}

		logTrustedProxy(guid, fwdAddress, *clientIP)

		*clientIP = fwdAddress

		multipleIPs := strings.Split(fwdAddress, ",")
		if len(multipleIPs) > 1 {
			*clientIP = strings.TrimSpace(multipleIPs[0])
		}

		*clientPort = definitions.NotAvailable

		if *xssl == "" {
			proto := ctx.GetHeader("X-Forwarded-Proto")
			if proto == "https" {
				*xssl = "on"
			}
		}
	}
}

// ComparePasswords takes a plain password and creates a hash. Then it compares the hashed passwords and returns true, if
// bothe passwords are equal. If an error occurs, the result is false for the compare operation and the error is returned.
func ComparePasswords(hashPassword string, plainPassword string) (bool, error) {
	if strings.HasPrefix(hashPassword, "{SSHA") {
		password := &CryptPassword{}

		salt, alg, pwOption, err := password.GetParameters(hashPassword)
		if err != nil {
			return false, err
		}

		newPassword := &CryptPassword{}
		newPassword.Generate(plainPassword, salt, alg, pwOption)

		if password.Password == newPassword.Password {
			return true, nil
		}
	} else {
		// Supported passwords: MD5, SSHA256, SSHA512, bcrypt, Argon2i, Argon2id
		_, _, _, pwhash, err := crypt.DecodeSettings(hashPassword)
		if err != nil {
			return false, err
		}

		settings, _, _ := strings.Cut(hashPassword, pwhash)

		encoded, err := crypt.Crypt(plainPassword, settings)
		if err != nil {
			return false, err
		}

		if encoded == hashPassword {
			return true, nil
		}
	}

	return false, nil
}

// ByteSize formats a given number of bytes into a human-readable string representation.
// If the number is less than 1024, it will be displayed in bytes (e.g., "256B").
// Otherwise, the number will be converted into a larger unit (e.g., 1.5KB, 20MB, etc.).
func ByteSize(bytes uint64) string {
	const unit = 1024

	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}

	div, exp := uint64(unit), 0

	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// ValidateUsername validates the given username against the usernamePattern regular expression.
// It takes a string username as input and returns a boolean value representing whether the username is valid or not.
// The usernamePattern regular expression allows any character except "(", ")", "{", SP, CTL, "%", "*", "\", except empty string.
// The function returns true if the username matches the pattern, and false otherwise.
func ValidateUsername(username string) bool {
	return usernamePattern.MatchString(username)
}

// NewDNSResolver creates a new DNS resolver based on the configured settings.
func NewDNSResolver() (resolver *net.Resolver) {
	if config.GetFile().GetServer().GetDNS().GetResolver() == "" {
		resolver = &net.Resolver{PreferGo: false}
	} else {
		resolver = &net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{
					Timeout: time.Duration(10) * time.Second,
				}

				return dialer.DialContext(ctx, network, config.GetFile().GetServer().GetDNS().GetResolver())
			},
		}
	}

	return
}

// NewHTTPClient creates and returns a new http.Client with a timeout of 60 seconds and custom TLS configurations.
func NewHTTPClient() *http.Client {
	var proxyFunc func(*http.Request) (*url.URL, error)

	if config.GetFile().GetServer().GetHTTPClient().GetProxy() != "" {
		proxyURL, err := url.Parse(config.GetFile().GetServer().GetHTTPClient().GetProxy())
		if err != nil {
			proxyFunc = http.ProxyFromEnvironment
		} else {
			proxyFunc = http.ProxyURL(proxyURL)
		}
	} else {
		proxyFunc = http.ProxyFromEnvironment
	}

	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Proxy:               proxyFunc,
			MaxConnsPerHost:     config.GetFile().GetServer().GetHTTPClient().GetMaxConnsPerHost(),
			MaxIdleConns:        config.GetFile().GetServer().GetHTTPClient().GetMaxIdleConns(),
			MaxIdleConnsPerHost: config.GetFile().GetServer().GetHTTPClient().GetMaxIdleConnsPerHost(),
			IdleConnTimeout:     config.GetFile().GetServer().GetHTTPClient().GetIdleConnTimeout(),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.GetFile().GetServer().GetTLS().GetHTTPClientSkipVerify(),
			},
		},
	}

	return httpClient
}
