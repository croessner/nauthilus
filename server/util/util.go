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
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"hash"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/svcctx"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/simia-tech/crypt"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// Legal characters for IMAP username based on RFC 9051: Any character except "(", ")", "{", SP, CTL, "%", "\"", "\"". The "*" might be used as master separator.
var usernamePattern = regexp.MustCompile(`^[^\x00-\x1F\x7F(){}%"\\ ]+$`)

// RedisLogger implements the interface redis.Logging
type RedisLogger struct{}

// Printf implements the printf function from Redis.
func (r *RedisLogger) Printf(_ context.Context, format string, values ...any) {
	// Downgrade all go-redis internal logs to DEBUG and avoid formatting cost
	// when DEBUG is disabled.
	if log.Logger == nil || !log.Logger.Enabled(context.Background(), slog.LevelDebug) {
		return
	}

	msg := fmt.Sprintf(format, values...)
	level.Debug(log.Logger).Log(definitions.LogKeyMsg, msg, "source", "go-redis")
}

// FormatDurationMs formats a time.Duration as milliseconds with a fixed precision.
// The output is always in milliseconds using three fractional digits, e.g., "12.345ms".
// This ensures consistent latency units across logs regardless of the duration magnitude.
func FormatDurationMs(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)

	return fmt.Sprintf("%.3fms", ms)
}

// CryptPassword is a container for an encrypted password typically used in SQL fields.
type CryptPassword struct {
	definitions.Algorithm
	definitions.PasswordOption
	Password string
	Salt     []byte
}

// Generate creates the encrypted form of a plain text password.
// It sets the Algorithm, PasswordOption, Salt, and Password fields of the CryptPassword struct
// and returns the generated password string.
func (c *CryptPassword) Generate(plainPassword string, salt []byte, alg definitions.Algorithm, pwOption definitions.PasswordOption) (
	string, error,
) {
	var hashValue hash.Hash

	// Validate algorithm
	switch alg {
	case definitions.SSHA512:
		hashValue = sha512.New()
	case definitions.SSHA256:
		hashValue = sha256.New()
	default:
		return "", errors.ErrUnsupportedAlgorithm
	}

	// Store algorithm and salt in the struct
	c.Algorithm = alg
	c.Salt = salt

	// Write plainPassword and salt to hash
	hashValue.Write([]byte(plainPassword))
	hashValue.Write(salt)

	// Get hash sum
	hashSum := hashValue.Sum(nil)

	// Prepare buffer for hash+salt
	hashWithSalt := make([]byte, len(hashSum)+len(salt))
	copy(hashWithSalt, hashSum)
	copy(hashWithSalt[len(hashSum):], salt)

	// Encode according to password option
	switch pwOption {
	case definitions.ENCB64:
		c.Password = base64.StdEncoding.EncodeToString(hashWithSalt)
		c.PasswordOption = definitions.ENCB64
	case definitions.ENCHEX:
		c.Password = hex.EncodeToString(hashWithSalt)
		c.PasswordOption = definitions.ENCHEX
	default:
		return "", errors.ErrUnsupportedPasswordOption
	}

	return c.Password, nil
}

// Pre-compiled regex pattern for password prefix matching including curly braces and capturing groups
// Full format: {SSHA256.B64}payload or {SSHA512.HEX}payload; option and dot are optional, default B64
var passwordPrefixPattern = regexp.MustCompile(`^\{SSHA(256|512)(?:\.(HEX|B64))?}(.+)$`)

// GetParameters splits an encoded password into its components.
// It extracts the salt, algorithm, and password option from the crypted password
// and sets the corresponding fields in the CryptPassword struct.
func (c *CryptPassword) GetParameters(cryptedPassword string) (
	salt []byte, alg definitions.Algorithm, pwOption definitions.PasswordOption, err error,
) {
	var decodedPwSalt []byte

	alg = definitions.SSHAUNKNOWN
	pwOption = definitions.ENCUNKNOWN

	// Use regex to capture algorithm (group1), option (group2), and payload (group3)
	subs := passwordPrefixPattern.FindStringSubmatch(cryptedPassword)
	if len(subs) != 4 { // full match + 3 capture groups
		return nil, alg, pwOption, errors.ErrUnsupportedAlgorithm
	}

	// Determine algorithm from group 1
	switch subs[1] {
	case "512":
		alg = definitions.SSHA512
	case "256":
		alg = definitions.SSHA256
	default:
		return nil, alg, pwOption, errors.ErrUnsupportedAlgorithm
	}

	c.Algorithm = alg

	// Determine password option from group 2 (default B64)
	switch subs[2] {
	case "HEX":
		pwOption = definitions.ENCHEX
	case "B64", "":
		pwOption = definitions.ENCB64
	default:
		return nil, alg, pwOption, errors.ErrUnsupportedPasswordOption
	}

	c.PasswordOption = pwOption

	// Group 3 is the encoded password+salt payload
	c.Password = subs[3]

	// Decode the password based on the password option
	if pwOption == definitions.ENCB64 {
		decodedPwSalt, err = base64.StdEncoding.DecodeString(c.Password)
	} else if //goland:noinspection GoDfaConstantCondition
	pwOption == definitions.ENCHEX {
		decodedPwSalt, err = hex.DecodeString(c.Password)
	}

	if err != nil {
		return nil, alg, pwOption, err
	}

	// Extract the salt based on the algorithm
	if alg == definitions.SSHA512 {
		if len(decodedPwSalt) < 65 {
			return nil, alg, pwOption, errors.ErrUnsupportedAlgorithm
		}

		salt = decodedPwSalt[64:]
	} else if //goland:noinspection GoDfaConstantCondition
	alg == definitions.SSHA256 {
		if len(decodedPwSalt) < 33 {
			return nil, alg, pwOption, errors.ErrUnsupportedAlgorithm
		}

		salt = decodedPwSalt[32:]
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

	// Trace reverse DNS (PTR) lookup
	tr := monittrace.New("nauthilus/dns")

	// Resolve target DNS server attributes if a custom resolver is configured
	var srvHost string
	var srvPort int
	if r := config.GetFile().GetServer().GetDNS().GetResolver(); r != "" {
		srvHost, srvPort, _ = netSplitHostPortDefault(r, 53)
	}

	tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup_ptr",
		// semantic hints for Tempo service graph
		attribute.String("rpc.system", "dns"),
		semconv.PeerService("dns"),
		semconv.ServerAddress(srvHost),
		semconv.ServerPort(srvPort),
		attribute.String("dns.question.name", address),
		attribute.String("dns.question.type", "PTR"),
	)

	if hostNames, err := resolver.LookupAddr(tctx, address); err == nil {
		if len(hostNames) > 0 {
			hostname = hostNames[0]
			hostname = strings.TrimSuffix(hostname, ".")
		}

		tsp.SetAttributes(attribute.Int("dns.answer.count", len(hostNames)))
	} else {
		tsp.RecordError(err)
	}

	tsp.End()

	return hostname
}

// netSplitHostPortDefault splits host:port and returns a default port when absent.
// It tolerates inputs without scheme (e.g., "1.2.3.4:5353" or "dns.local").
func netSplitHostPortDefault(addr string, defPort int) (host string, port int, err error) {
	// If a scheme is present, strip it via url.Parse to normalize
	if strings.Contains(addr, "://") {
		if u, perr := url.Parse(addr); perr == nil {
			addr = u.Host
		}
	}

	h, p, e := net.SplitHostPort(addr)
	if e != nil {
		// No port – return default
		return addr, defPort, nil
	}

	// Try to parse port
	var pn int
	if p == "" {
		pn = defPort
	} else {
		// ignore parse error; fall back to default
		if v, convErr := strconv.Atoi(p); convErr == nil {
			pn = v
		} else {
			pn = defPort
		}
	}

	return h, pn, nil
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
	case definitions.DbgAccount:
		moduleName = definitions.DbgAccountName
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
	level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "%s is not a network", ipOrNet, definitions.LogKeyError, err)
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

	// Only trust forwarded headers from trusted proxies
	isTrustedProxy := IsInNetwork(viper.GetStringSlice("trusted_proxies"), guid, *clientIP)

	// Determine local transport security (actual connection using TLS)
	isLocalHTTPS := ctx.Request != nil && ctx.Request.TLS != nil

	// Read proto header once (lowercased/trimmed)
	proto := strings.ToLower(strings.TrimSpace(ctx.GetHeader("X-Forwarded-Proto")))

	// Gate for accepting forwarded headers
	acceptForwarded := isTrustedProxy && proto == "https" && isLocalHTTPS

	if fwdAddress != "" {
		logForwarderFound(guid)

		if !acceptForwarded {
			// Not accepted: either not from trusted proxy or header claims https while local request is not HTTPS
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
	}

	// Evaluate X-Forwarded-Proto if xssl not yet set and only if accepted
	if *xssl == "" && acceptForwarded {
		if proto == "https" {
			*xssl = "on"
		} else if proto != "" {
			// explicitly mark as off if header claims non-https
			*xssl = "off"
		}
	}
}

// ComparePasswords takes a plain password and creates a hash. Then it compares the hashed passwords and returns true, if
// both passwords are equal. If an error occurs, the result is false for the compare operation and the error is returned.
// This function uses constant-time comparison to prevent timing attacks.
func ComparePasswords(hashPassword string, plainPassword string) (bool, error) {
	if strings.HasPrefix(hashPassword, "{SSHA") {
		password := &CryptPassword{}

		salt, alg, pwOption, err := password.GetParameters(hashPassword)
		if err != nil {
			return false, err
		}

		newPassword := &CryptPassword{}
		_, err = newPassword.Generate(plainPassword, salt, alg, pwOption)
		if err != nil {
			return false, err
		}

		// Use subtle.ConstantTimeCompare for secure comparison
		return subtle.ConstantTimeCompare([]byte(password.Password), []byte(newPassword.Password)) == 1, nil
	} else {
		// Supported passwords: MD5, SSHA256, SSHA512, bcrypt, Argon2i, Argon2id
		_, _, _, pwhash, err := crypt.DecodeSettings(hashPassword)
		if err != nil {
			return false, err
		}

		settings, _, found := strings.Cut(hashPassword, pwhash)
		if !found {
			return false, errors.ErrUnsupportedAlgorithm
		}

		encoded, err := crypt.Crypt(plainPassword, settings)
		if err != nil {
			return false, err
		}

		// Use subtle.ConstantTimeCompare for secure comparison
		return subtle.ConstantTimeCompare([]byte(encoded), []byte(hashPassword)) == 1, nil
	}
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
		resolver = &net.Resolver{PreferGo: true}
	} else {
		resolver = &net.Resolver{
			PreferGo: true,
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

	baseTransport := &http.Transport{
		Proxy:               proxyFunc,
		MaxConnsPerHost:     config.GetFile().GetServer().GetHTTPClient().GetMaxConnsPerHost(),
		MaxIdleConns:        config.GetFile().GetServer().GetHTTPClient().GetMaxIdleConns(),
		MaxIdleConnsPerHost: config.GetFile().GetServer().GetHTTPClient().GetMaxIdleConnsPerHost(),
		IdleConnTimeout:     config.GetFile().GetServer().GetHTTPClient().GetIdleConnTimeout(),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.GetFile().GetServer().GetTLS().GetHTTPClientSkipVerify() || config.GetFile().GetServer().GetHTTPClient().GetTLS().GetSkipVerify(),
		},
	}

	var transport http.RoundTripper = baseTransport
	if config.GetFile().GetServer().GetInsights().IsTracingEnabled() {
		// Use otelhttp transport (client-kind spans) and add peer.service="http"
		transport = otelhttp.NewTransport(
			baseTransport,
			otelhttp.WithSpanOptions(trace.WithAttributes(semconv.PeerService("http"))),
		)
	}

	httpClient := &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}

	return httpClient
}

// GetCtxWithDeadlineRedisRead creates a context with a timeout derived from the Redis read timeout configuration.
// If the provided context is nil, it initializes a new context using svcctx.Get().
// When configuration is not loaded (e.g., in unit tests), it falls back to a sane default timeout.
// Returns the derived context and its corresponding cancel function.
func GetCtxWithDeadlineRedisRead(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = svcctx.Get()
	}

	var timeout time.Duration
	if config.IsFileLoaded() {
		timeout = config.GetFile().GetServer().GetTimeouts().GetRedisRead()
	} else {
		// Default for tests or when config is not initialized
		timeout = 5 * time.Second
	}

	return context.WithTimeout(ctx, timeout)
}

// GetCtxWithDeadlineRedisWrite creates a context with a timeout derived from the Redis write timeout configuration.
// If the provided context is nil, it initializes a new context using svcctx.Get().
// When configuration is not loaded (e.g., in unit tests), it falls back to a sane default timeout.
// Returns the derived context and its corresponding cancel function.
func GetCtxWithDeadlineRedisWrite(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = svcctx.Get()
	}

	var timeout time.Duration
	if config.IsFileLoaded() {
		timeout = config.GetFile().GetServer().GetTimeouts().GetRedisWrite()
	} else {
		// Default for tests or when config is not initialized
		timeout = 5 * time.Second
	}

	return context.WithTimeout(ctx, timeout)
}

// GetCtxWithDeadlineLDAPSearch creates a context with a timeout for LDAP account searches.
// Parent context is the service context to avoid coupling to HTTP request lifetimes.
func GetCtxWithDeadlineLDAPSearch() (context.Context, context.CancelFunc) {
	var timeout time.Duration
	if config.IsFileLoaded() {
		timeout = config.GetFile().GetServer().GetTimeouts().GetLDAPSearch()
	} else {
		// Sensible default for tests or during init
		timeout = 5 * time.Second
	}

	return context.WithTimeout(svcctx.Get(), timeout)
}

// GetCtxWithDeadlineLDAPModify creates a context with a timeout for LDAP modify operations.
// Falls back to LDAPSearch timeout when LDAPModify is not configured.
func GetCtxWithDeadlineLDAPModify() (context.Context, context.CancelFunc) {
	var timeout time.Duration
	if config.IsFileLoaded() {
		// Some configurations may not have a dedicated LDAPModify timeout; fall back to search
		timeout = config.GetFile().GetServer().GetTimeouts().GetLDAPModify()
		if timeout == 0 {
			timeout = config.GetFile().GetServer().GetTimeouts().GetLDAPSearch()
		}
	} else {
		timeout = 5 * time.Second
	}

	return context.WithTimeout(svcctx.Get(), timeout)
}

// ApplyStringField updates the string pointer `dest` with the value of `src` if `src` is non-empty.
func ApplyStringField(src string, dest *string) {
	if src != "" && dest != nil {
		*dest = src
	}
}
