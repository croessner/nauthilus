package util

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/simia-tech/crypt"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// RedisLogger implements the interface redis.Logging
type RedisLogger struct{}

// Printf implements the printf function from Redis.
func (r *RedisLogger) Printf(_ context.Context, format string, values ...any) {
	level.Info(logging.DefaultLogger).Log("redis", fmt.Sprintf(format, values...))
}

// CryptPassword is a container for an encrypted password typically used in SQL fields.
type CryptPassword struct {
	decl.Algorithm
	decl.PasswordOption
	Password string
	Salt     []byte
}

// Generate creates the encrypted form of a plain text password.
func (c *CryptPassword) Generate(plainPassword string, salt []byte, alg decl.Algorithm, pwOption decl.PasswordOption) (
	string, error,
) {
	var (
		hashSalt  []byte
		hashValue hash.Hash
	)

	c.Salt = salt
	hashSalt = append([]byte(plainPassword), salt...)

	switch alg {
	case decl.SSHA512:
		hashValue = sha512.New()
		c.Algorithm = decl.SSHA512
	case decl.SSHA256:
		hashValue = sha256.New()
		c.Algorithm = decl.SSHA256
	default:
		return "", errors2.ErrUnsupportedAlgorithm
	}

	hashValue.Write(hashSalt)

	switch pwOption {
	case decl.B64:
		c.Password = base64.StdEncoding.EncodeToString(append(hashValue.Sum(nil), salt...))
		c.PasswordOption = decl.B64
	case decl.HEX:
		c.Password = hex.EncodeToString(append(hashValue.Sum(nil), salt...))
		c.PasswordOption = decl.HEX
	default:
		return "", errors2.ErrUnsupportedPasswordOption
	}

	return c.Password, nil
}

// GetParameters splits an encoded password into its components.
func (c *CryptPassword) GetParameters(cryptedPassword string) (
	salt []byte, alg decl.Algorithm, pwOption decl.PasswordOption, err error,
) {
	var decodedPwSasltSalt []byte

	pattern := `SSHA(256|512)(\.HEX|\.B64)?`
	re := regexp.MustCompile(pattern)
	passwordPrefix := re.FindString(cryptedPassword)

	if strings.HasPrefix(passwordPrefix, "SSHA512") {
		alg = decl.SSHA512
	} else {
		if strings.HasPrefix(passwordPrefix, "SSHA256") {
			alg = decl.SSHA256
		} else {
			return salt, alg, pwOption, errors2.ErrUnsupportedAlgorithm
		}
	}

	c.Algorithm = alg

	if strings.HasSuffix(passwordPrefix, ".B64") {
		pwOption = decl.B64
	} else {
		if strings.HasSuffix(passwordPrefix, ".HEX") {
			pwOption = decl.HEX
		} else {
			return salt, alg, pwOption, errors2.ErrUnsupportedPasswordOption
		}
	}

	c.PasswordOption = pwOption

	// {SSHA256} or {SSHA512}
	if len(passwordPrefix) == 7 { //nolint:gomnd // Ignore
		pwOption = decl.B64
	}

	c.Password = cryptedPassword[strings.Index(cryptedPassword, "}")+1:]

	switch pwOption {
	case decl.B64:
		decodedPwSasltSalt, err = base64.StdEncoding.DecodeString(c.Password)
	case decl.HEX:
		decodedPwSasltSalt, err = hex.DecodeString(c.Password)
	}

	if err != nil {
		return salt, alg, pwOption, err
	}

	switch alg {
	case decl.SSHA512:
		salt = decodedPwSasltSalt[64:]
	case decl.SSHA256:
		salt = decodedPwSasltSalt[32:]
	}

	c.Salt = salt

	return salt, alg, pwOption, nil
}

func PreparePassword(password string) string {
	return fmt.Sprintf("%s\x00%s", config.LoadableConfig.PasswordNonce, password)
}

// GetHash creates an SHA-256 hash of a plain text password and returns the first 128 bits.
func GetHash(value string) string {
	if config.EnvConfig.DevMode {
		return value
	}

	hashValue := sha256.New()
	hashValue.Write([]byte(value))

	// 32 bit is good enough
	return hex.EncodeToString(hashValue.Sum(nil))[:8]
}

// MapBytesToString is a helper for MySQL databases that converts the values from a slice of bytes to strings.
func MapBytesToString(data map[string]any) {
	for key, value := range data {
		if bytes, okay := value.([]byte); okay {
			data[key] = string(bytes)
		}
	}
}

func newRedisFailoverClient(slavesOnly bool) (redisHandle *redis.Client) {
	redisHandle = redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:       config.EnvConfig.RedisSentinelMasterName,
		SentinelAddrs:    config.EnvConfig.RedisSentinels,
		SlaveOnly:        slavesOnly,
		DB:               config.EnvConfig.RedisDB,
		SentinelUsername: config.EnvConfig.RedisSentinelUsername,
		SentinelPassword: config.EnvConfig.RedisSentinelPassword,
		Username:         config.EnvConfig.RedisUsername,
		Password:         config.EnvConfig.RedisPassword,
	})

	return
}

func newRedisClient(address string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     address,
		Username: config.EnvConfig.RedisUsername,
		Password: config.EnvConfig.RedisPassword,
		DB:       config.EnvConfig.RedisDB,
	})
}

// NewRedisClient constructs a new Redis fail over client or a regular client depending on the configuration done in
// Config.
func NewRedisClient() (redisHandle redis.UniversalClient) {
	// If two or more sentinels are defined and a master name is set, switch to a FailoverClient.
	if len(config.EnvConfig.RedisSentinels) > 1 && config.EnvConfig.RedisSentinelMasterName != "" {
		redisHandle = newRedisFailoverClient(false)
	} else {
		redisHandle = newRedisClient(fmt.Sprintf("%s:%d", config.EnvConfig.RedisAddress, config.EnvConfig.RedisPort))
	}

	return
}

// NewRedisReplicaClient constructs a new Redis slave server if Nauthilus is not configured to use Redis sentinels and if
// the configuration settings for RedisRO are different from the default Redis settings.
func NewRedisReplicaClient() redis.UniversalClient {
	if len(config.EnvConfig.RedisSentinels) > 1 && config.EnvConfig.RedisSentinelMasterName != "" {
		return newRedisFailoverClient(true)
	}

	if config.EnvConfig.RedisAddressRO != config.EnvConfig.RedisAddress || config.EnvConfig.RedisPortRO != config.EnvConfig.RedisPort {
		return newRedisClient(fmt.Sprintf("%s:%d", config.EnvConfig.RedisAddressRO, config.EnvConfig.RedisPortRO))
	}

	return nil
}

func NewDNSResolver() (resolver *net.Resolver) {
	if config.EnvConfig.DNSResolver == "" {
		level.Debug(logging.DefaultLogger).Log(decl.LogKeyMsg, "Using default DNS resolver")

		resolver = &net.Resolver{
			PreferGo: true,
		}
	} else {
		level.Debug(logging.DefaultLogger).Log(decl.LogKeyMsg, fmt.Sprintf("Using DNS resolver %s", config.EnvConfig.DNSResolver))

		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{
					//nolint:gomnd // Ignore
					Timeout: time.Millisecond * time.Duration(10000),
				}

				return dialer.DialContext(ctx, network, fmt.Sprintf("%s:53", config.EnvConfig.DNSResolver))
			},
		}
	}

	return
}

// ResolveIPAddress returns the hostname for a given IP address.
func ResolveIPAddress(address string) (hostname string) {
	ctx, cancel := context.WithDeadline(context.TODO(), time.Now().Add(time.Duration(config.EnvConfig.DNSTimeout)*time.Second))
	defer cancel()

	resolver := NewDNSResolver()

	if hostNames, err := resolver.LookupAddr(ctx, address); err == nil {
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
	case errors.As(err, &e):
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

func DebugModule(module decl.DbgModule, keyvals ...any) {
	var moduleName string

	if config.EnvConfig.Verbosity.Level() < decl.LogLevelDebug {
		return
	}

	switch module {
	case decl.DbgAll:
		moduleName = decl.DbgAllName
	case decl.DbgAuth:
		moduleName = decl.DbgAuthName
	case decl.DbgHydra:
		moduleName = decl.DbgHydraName
	case decl.DbgWebAuthn:
		moduleName = decl.DbgWebAuthnName
	case decl.DbgStats:
		moduleName = decl.DbgStatsName
	case decl.DbgWhitelist:
		moduleName = decl.DbgWhitelistName
	case decl.DbgLDAP:
		moduleName = decl.DbgLDAPName
	case decl.DbgLDAPPool:
		moduleName = decl.DbgLDAPPoolName
	case decl.DbgSQL:
		moduleName = decl.DbgSQLName
	case decl.DbgCache:
		moduleName = decl.DbgCacheName
	case decl.DbgBf:
		moduleName = decl.DbgBfName
	case decl.DbgRBL:
		moduleName = decl.DbgRBLName
	case decl.DbgAction:
		moduleName = decl.DbgActionName
	case decl.DbgFeature:
		moduleName = decl.DbgFeatureName
	case decl.DbgLua:
		moduleName = decl.DbgLuaName
	case decl.DbgFilter:
		moduleName = decl.DbgFilterName
	default:
		moduleName = decl.DbgNoneName
	}

	for index := range config.EnvConfig.DbgModule {
		if !(config.EnvConfig.DbgModule[index].GetModule() == decl.DbgAll || config.EnvConfig.DbgModule[index].GetModule() == module) {
			continue
		}

		keyvals = append(keyvals, "debug_module")
		keyvals = append(keyvals, moduleName)

		if counter, _, _, ok := runtime.Caller(1); ok {
			keyvals = append(keyvals, "function")
			keyvals = append(keyvals, runtime.FuncForPC(counter).Name())

			_ = level.Debug(logging.DefaultLogger).Log(keyvals...)
		}
		break
	}
}

// WithNotAvailable checks a list of string. If none of the strings does have a content, we return the decl.NotAvailable string.
func WithNotAvailable(elements ...any) string {
	var value string

	value = CheckStrings(elements...)

	if value == "" {
		return decl.NotAvailable
	}

	return value
}

// CheckStrings checks a list of strings and returns the first that is non-empty.
func CheckStrings(elements ...any) string {
	var value string

	if elements == nil {
		return ""
	}

	for index := range elements {
		switch element := elements[index].(type) {
		case string:
			if element != "" {
				return element
			}
		case *string:
			if element == nil {
				return ""
			}

			if *element != "" {
				return *element
			}
		}
	}

	return value
}

func GetProxyAddress(request *http.Request, clientIP string, clientPort string) (string, string) {
	fwdAddress := request.Header.Get("X-Forwarded-For")

	if fwdAddress != "" {
		DebugModule(
			decl.DbgAuth,
			decl.LogKeyMsg, "Found header X-Forwarded-For",
		)

		for _, trustedProxy := range viper.GetStringSlice("trusted_proxies") {
			if clientIP != trustedProxy {
				DebugModule(
					decl.DbgAuth,
					decl.LogKeyMsg, fmt.Sprintf("Client IP '%s' not matching '%s'", clientIP, trustedProxy),
				)

				continue
			}

			DebugModule(
				decl.DbgAuth,
				decl.LogKeyMsg, fmt.Sprintf(
					"Client IP '%s' matching, forwarded for '%s'", clientIP, fwdAddress),
			)

			clientIP = fwdAddress

			multipleIPs := strings.Split(fwdAddress, ", ")
			if len(multipleIPs) > 1 {
				clientIP = multipleIPs[0]
			}

			clientPort = decl.NotAvailable

			break
		}
	}

	return clientIP, clientPort
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
