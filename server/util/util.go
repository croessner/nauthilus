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
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/svcctx"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/simia-tech/crypt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Legal characters for IMAP username based on RFC 9051: Any character except "(", ")", "{", SP, CTL, "%", "\"", "\"". The "*" might be used as master separator.
var usernamePattern = regexp.MustCompile(`^[^\x00-\x1F\x7F(){}%"\\ ]+$`)

// RedisLogger implements the interface redis.Logging
type RedisLogger struct {
	logger *slog.Logger
}

// NewRedisLogger initializes and returns a new instance of RedisLogger with the provided logger.
func NewRedisLogger(logger *slog.Logger) *RedisLogger {
	return &RedisLogger{logger: logger}
}

// Printf implements the printf function from Redis.
func (r *RedisLogger) Printf(ctx context.Context, format string, values ...any) {
	// Downgrade all go-redis internal logs to DEBUG and avoid formatting cost
	// when DEBUG is disabled.
	if r.logger == nil || !r.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}

	msg := fmt.Sprintf(format, values...)
	level.Debug(r.logger).Log(definitions.LogKeyMsg, msg, "source", "go-redis")
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
	return fmt.Sprintf("%s\x00%s", getDefaultConfigFile().GetServer().Redis.PasswordNonce, password)
}

// GetHash creates an SHA-256 hash of a plain text password and returns the first 128 bits.
func GetHash(value string) string {
	if getDefaultEnvironment().GetDevMode() {
		return value
	}

	hashValue := sha256.New()
	hashValue.Write([]byte(value))

	// 32 bit is good enough
	return hex.EncodeToString(hashValue.Sum(nil))[:8]
}

// ResolveIPAddress returns the hostname for a given IP address.
func ResolveIPAddress(ctx context.Context, cfg config.File, address string) (hostname string) {
	ctxTimeout, cancel := context.WithDeadline(ctx, time.Now().Add(cfg.GetServer().GetDNS().GetTimeout()*time.Second))

	defer cancel()

	resolver := NewDNSResolverWithCfg(cfg)

	// Trace reverse DNS (PTR) lookup
	tr := monittrace.New("nauthilus/dns")

	attrs := []attribute.KeyValue{
		// semantic hints for Tempo service graph
		attribute.String("rpc.system", "dns"),
		attribute.String("peer.service", "dns"),
		attribute.String("dns.question.name", address),
		attribute.String("dns.question.type", "PTR"),
	}

	if srvHost, srvPort, ok := DNSResolverPeer(cfg); ok {
		attrs = append(attrs,
			attribute.String("server.address", srvHost),
			attribute.Int("server.port", srvPort),
		)
	}

	tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup_ptr", attrs...)

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

type cfgHolder struct {
	cfg config.File
}

type loggerHolder struct {
	logger *slog.Logger
}

var (
	defaultCfg atomic.Value
	defaultLog atomic.Value
)

var (
	warnMissingCfgOnce sync.Once
	warnMissingLogOnce sync.Once
)

func init() {
	defaultCfg.Store(cfgHolder{cfg: nil})
	defaultLog.Store(loggerHolder{logger: nil})
}

func SetDefaultConfigFile(cfg config.File) {
	defaultCfg.Store(cfgHolder{cfg: cfg})
}

func SetDefaultLogger(logger *slog.Logger) {
	defaultLog.Store(loggerHolder{logger: logger})
}

func getDefaultConfigFile() config.File {
	if v := defaultCfg.Load(); v != nil {
		if h, ok := v.(cfgHolder); ok {
			if h.cfg != nil {
				return h.cfg
			}
		}
	}

	warnMissingCfgOnce.Do(func() {
		stdlog.Printf("ERROR: util default config snapshot is not configured. Ensure the boundary calls util.SetDefaultConfigFile(...)\n")
	})

	panic("util: default config snapshot not configured")
}

func getDefaultLogger() *slog.Logger {
	if v := defaultLog.Load(); v != nil {
		if h, ok := v.(loggerHolder); ok {
			if h.logger != nil {
				return h.logger
			}
		}
	}

	warnMissingLogOnce.Do(func() {
		stdlog.Printf("ERROR: util default logger is not configured. Ensure the boundary calls util.SetDefaultLogger(...)\n")
	})

	panic("util: default logger not configured")
}

func DebugModule(ctx context.Context, cfg config.File, logger *slog.Logger, module definitions.DbgModule, keyvals ...any) {
	DebugModuleWithCfg(ctx, cfg, logger, module, keyvals...)
}

// DebugModuleWithCfg logs debug information for a specific module if it is enabled in the configuration and logger is specified.
func DebugModuleWithCfg(ctx context.Context, cfg config.File, logger *slog.Logger, module definitions.DbgModule, keyvals ...any) {
	if cfg == nil || logger == nil {
		return
	}

	logCfg := cfg.GetServer().GetLog()
	if logCfg.GetLogLevel() < definitions.LogLevelDebug {
		return
	}

	mapping := definitions.GetDbgModuleMapping()
	if mapping == nil {
		return
	}

	moduleName, ok := mapping.ModToStr[module]
	if !ok {
		return
	}

	tracer := monittrace.New("nauthilus/util")

	var dbgCtx context.Context
	var sp trace.Span

	if gCtx, ok := ctx.(*gin.Context); ok {
		dbgCtx, sp = tracer.Start(gCtx.Request.Context(), "util.debugmodule",
			attribute.String("debug_module", moduleName),
		)

		gCtx.Request = gCtx.Request.WithContext(dbgCtx)
	} else {
		dbgCtx, sp = tracer.Start(ctx, "util.debugmodule",
			attribute.String("debug_module", moduleName),
		)
	}

	defer sp.End()

	enabled := false
	for _, dbgModule := range logCfg.GetDebugModules() {
		mod := dbgModule.GetModule()
		if mod == definitions.DbgAll || mod == module {
			enabled = true

			break
		}
	}

	if !enabled {
		return
	}

	attrs := make([]any, 0, len(keyvals)+4)
	attrs = append(attrs, keyvals...)
	attrs = append(attrs, "debug_module", moduleName)

	if pc, _, _, ok := runtime.Caller(1); ok {
		if fn := runtime.FuncForPC(pc); fn != nil {
			sp.SetAttributes(attribute.String("function", fn.Name()))

			attrs = append(attrs, "function", fn.Name())
		} else {
			attrs = append(attrs, "function", "unknown")
		}
	}

	level.Debug(logger).WithContext(dbgCtx).Log(attrs...)
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
func logNetworkError(logger *slog.Logger, guid, ipOrNet string, err error) {
	level.Error(logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "%s is not a network", ipOrNet, definitions.LogKeyError, err)
}

// logNetworkChecking logs the information about checking a network for the given authentication object.
func logNetworkChecking(ctx context.Context, cfg config.File, logger *slog.Logger, guid, clientIP string, network *net.IPNet) {
	DebugModuleWithCfg(
		ctx,
		cfg,
		logger,
		definitions.DbgWhitelist,
		definitions.LogKeyGUID, guid, definitions.LogKeyMsg, fmt.Sprintf("Checking: %s -> %s", clientIP, network.String()),
	)
}

// logIPChecking logs the IP address of the client along with the IP address or network being checked.
func logIPChecking(ctx context.Context, cfg config.File, logger *slog.Logger, guid, ipOrNet, clientIP string) {
	DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgWhitelist, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, fmt.Sprintf("Checking: %s -> %s", clientIP, ipOrNet))
}

// IsInNetwork checks if an IP address is part of a list of networks.
// It iterates through the networkList and checks each network if it contains the given IP address.
// The function returns true if there is a match.
// The function logs any network errors encountered during the process.
// The function logs the information about checking a network for the given authentication object.
// The function logs the IP address of the client along with the IP address or network being checked.
func IsInNetwork(ctx context.Context, cfg config.File, logger *slog.Logger, networkList []string, guid, clientIP string) (matchIP bool) {
	return IsInNetworkWithCfg(ctx, cfg, logger, networkList, guid, clientIP)
}

func IsInNetworkWithCfg(ctx context.Context, cfg config.File, logger *slog.Logger, networkList []string, guid, clientIP string) (matchIP bool) {
	ipAddress := net.ParseIP(clientIP)

	for _, ipOrNet := range networkList {
		if net.ParseIP(ipOrNet) == nil {
			_, network, err := net.ParseCIDR(ipOrNet)
			if err != nil {
				logNetworkError(logger, guid, ipOrNet, err)

				continue
			}

			logNetworkChecking(ctx, cfg, logger, guid, clientIP, network)

			if network.Contains(ipAddress) {
				matchIP = true

				break
			}
		} else {
			logIPChecking(ctx, cfg, logger, guid, ipOrNet, clientIP)
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
func IsSoftWhitelisted(ctx context.Context, cfg config.File, logger *slog.Logger, username, clientIP, guid string, softWhitelist config.SoftWhitelist) bool {
	networks := softWhitelist.Get(username)
	if networks == nil {
		return false
	}

	return IsInNetwork(ctx, cfg, logger, networks, guid, clientIP)
}

// logForwarderFound logs the finding of the header "X-Forwarded-For" in the debug module.
func logForwarderFound(ctx context.Context, cfg config.File, logger *slog.Logger, guid string) {
	DebugModuleWithCfg(
		ctx,
		cfg,
		logger,
		definitions.DbgAuth,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, "Found header X-Forwarded-For",
	)
}

// logNoTrustedProxies logs a warning message indicating that the client IP
// does not match the trusted proxies.
func logNoTrustedProxies(cfg config.File, logger *slog.Logger, guid, clientIP string) {
	level.Warn(logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Client IP '%s' not matching %v", clientIP, cfg.GetServer().GetTrustedProxies()),
	)
}

// logTrustedProxy logs the client IP matching with the forwarded address.
func logTrustedProxy(ctx context.Context, cfg config.File, logger *slog.Logger, guid, fwdAddress, clientIP string) {
	DebugModuleWithCfg(
		ctx,
		cfg,
		logger,
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
func ProcessXForwardedFor(ctx *gin.Context, cfg config.File, logger *slog.Logger, clientIP, clientPort *string, xssl *string) {
	fwdAddress := ctx.GetHeader("X-Forwarded-For")
	guid := ctx.GetString(definitions.CtxGUIDKey)

	// Only trust forwarded headers from trusted proxies
	isTrustedProxy := IsInNetworkWithCfg(ctx.Request.Context(), cfg, logger, cfg.GetServer().GetTrustedProxies(), guid, *clientIP)

	// Determine local transport security (actual connection using TLS)
	isLocalHTTPS := ctx.Request != nil && ctx.Request.TLS != nil

	// Read proto header once (lowercased/trimmed)
	proto := strings.ToLower(strings.TrimSpace(ctx.GetHeader("X-Forwarded-Proto")))

	// Gate for accepting forwarded headers
	acceptForwarded := isTrustedProxy && proto == "https" && isLocalHTTPS

	if fwdAddress != "" {
		logForwarderFound(ctx.Request.Context(), cfg, logger, guid)

		if !acceptForwarded {
			// Not accepted: either not from trusted proxy or header claims https while local request is not HTTPS
			logNoTrustedProxies(cfg, logger, guid, *clientIP)

			return
		}

		logTrustedProxy(ctx.Request.Context(), cfg, logger, guid, fwdAddress, *clientIP)

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
	return NewDNSResolverWithCfg(getDefaultConfigFile())
}

func NewDNSResolverWithCfg(cfg config.File) (resolver *net.Resolver) {
	if cfg == nil || cfg.GetServer().GetDNS().GetResolver() == "" {
		resolver = &net.Resolver{PreferGo: true}
	} else {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{
					Timeout: cfg.GetServer().GetDNS().GetTimeout() * time.Second,
				}

				return dialer.DialContext(ctx, network, cfg.GetServer().GetDNS().GetResolver())
			},
		}
	}

	return
}

func NewHTTPClientWithCfg(cfg config.File) *http.Client {
	var proxyFunc func(*http.Request) (*url.URL, error)

	if cfg.GetServer().GetHTTPClient().GetProxy() != "" {
		proxyURL, err := url.Parse(cfg.GetServer().GetHTTPClient().GetProxy())
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
		MaxConnsPerHost:     cfg.GetServer().GetHTTPClient().GetMaxConnsPerHost(),
		MaxIdleConns:        cfg.GetServer().GetHTTPClient().GetMaxIdleConns(),
		MaxIdleConnsPerHost: cfg.GetServer().GetHTTPClient().GetMaxIdleConnsPerHost(),
		IdleConnTimeout:     cfg.GetServer().GetHTTPClient().GetIdleConnTimeout(),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.GetServer().GetTLS().GetHTTPClientSkipVerify() || cfg.GetServer().GetHTTPClient().GetTLS().GetSkipVerify(),
		},
	}

	var transport http.RoundTripper = baseTransport
	if cfg.GetServer().GetInsights().IsTracingEnabled() {
		// Use otelhttp transport (client-kind spans) and add peer.service="http"
		transport = otelhttp.NewTransport(
			baseTransport,
			otelhttp.WithSpanOptions(trace.WithAttributes(attribute.String("peer.service", "http"))),
		)
	}

	httpClient := &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}

	return httpClient
}

// NewHTTPClient creates and returns a new http.Client with a timeout of 60 seconds and custom TLS configurations.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
	}
}

// GetCtxWithDeadlineRedisRead creates a context with a timeout derived from the Redis read timeout configuration.
// If the provided context is nil, it initializes a new context using svcctx.Get().
// When configuration is not loaded (e.g., in unit tests), it falls back to a sane default timeout.
// Returns the derived context and its corresponding cancel function.
func GetCtxWithDeadlineRedisRead(ctx context.Context, cfg config.File) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = svcctx.Get()
	}

	var timeout time.Duration
	if cfg != nil {
		timeout = cfg.GetServer().GetTimeouts().GetRedisRead()
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
func GetCtxWithDeadlineRedisWrite(ctx context.Context, cfg config.File) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = svcctx.Get()
	}

	var timeout time.Duration
	if cfg != nil {
		timeout = cfg.GetServer().GetTimeouts().GetRedisWrite()
	} else {
		// Default for tests or when config is not initialized
		timeout = 5 * time.Second
	}

	return context.WithTimeout(ctx, timeout)
}

// GetCtxWithDeadlineLDAPSearch creates a context with a timeout for LDAP account searches.
// Parent context is the service context to avoid coupling to HTTP request lifetimes.
func GetCtxWithDeadlineLDAPSearch(cfg config.File) (context.Context, context.CancelFunc) {
	var timeout time.Duration
	if cfg != nil {
		timeout = cfg.GetServer().GetTimeouts().GetLDAPSearch()
	} else {
		// Sensible default for tests or during init
		timeout = 5 * time.Second
	}

	return context.WithTimeout(svcctx.Get(), timeout)
}

// GetCtxWithDeadlineLDAPModify creates a context with a timeout for LDAP modify operations.
// Falls back to LDAPSearch timeout when LDAPModify is not configured.
func GetCtxWithDeadlineLDAPModify(cfg config.File) (context.Context, context.CancelFunc) {
	var timeout time.Duration
	if cfg != nil {
		// Some configurations may not have a dedicated LDAPModify timeout; fall back to search
		timeout = cfg.GetServer().GetTimeouts().GetLDAPModify()
		if timeout == 0 {
			timeout = cfg.GetServer().GetTimeouts().GetLDAPSearch()
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
