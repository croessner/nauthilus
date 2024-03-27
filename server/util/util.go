package util

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
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
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/go-kit/log/level"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/redis/go-redis/v9"
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
	global.Algorithm
	global.PasswordOption
	Password string
	Salt     []byte
}

// Generate creates the encrypted form of a plain text password.
func (c *CryptPassword) Generate(plainPassword string, salt []byte, alg global.Algorithm, pwOption global.PasswordOption) (
	string, error,
) {
	var (
		hashSalt  []byte
		hashValue hash.Hash
	)

	c.Salt = salt
	hashSalt = append([]byte(plainPassword), salt...)

	switch alg {
	case global.SSHA512:
		hashValue = sha512.New()
		c.Algorithm = global.SSHA512
	case global.SSHA256:
		hashValue = sha256.New()
		c.Algorithm = global.SSHA256
	default:
		return "", errors2.ErrUnsupportedAlgorithm
	}

	hashValue.Write(hashSalt)

	switch pwOption {
	case global.B64:
		c.Password = base64.StdEncoding.EncodeToString(append(hashValue.Sum(nil), salt...))
		c.PasswordOption = global.B64
	case global.HEX:
		c.Password = hex.EncodeToString(append(hashValue.Sum(nil), salt...))
		c.PasswordOption = global.HEX
	default:
		return "", errors2.ErrUnsupportedPasswordOption
	}

	return c.Password, nil
}

// GetParameters splits an encoded password into its components.
func (c *CryptPassword) GetParameters(cryptedPassword string) (
	salt []byte, alg global.Algorithm, pwOption global.PasswordOption, err error,
) {
	var decodedPwSasltSalt []byte

	pattern := `SSHA(256|512)(\.HEX|\.B64)?`
	re := regexp.MustCompile(pattern)
	passwordPrefix := re.FindString(cryptedPassword)

	if strings.HasPrefix(passwordPrefix, "SSHA512") {
		alg = global.SSHA512
	} else {
		if strings.HasPrefix(passwordPrefix, "SSHA256") {
			alg = global.SSHA256
		} else {
			return salt, alg, pwOption, errors2.ErrUnsupportedAlgorithm
		}
	}

	c.Algorithm = alg

	if strings.HasSuffix(passwordPrefix, ".B64") {
		pwOption = global.B64
	} else {
		if strings.HasSuffix(passwordPrefix, ".HEX") {
			pwOption = global.HEX
		} else {
			return salt, alg, pwOption, errors2.ErrUnsupportedPasswordOption
		}
	}

	c.PasswordOption = pwOption

	// {SSHA256} or {SSHA512}
	if len(passwordPrefix) == 7 { //nolint:gomnd // Ignore
		pwOption = global.B64
	}

	c.Password = cryptedPassword[strings.Index(cryptedPassword, "}")+1:]

	switch pwOption {
	case global.B64:
		decodedPwSasltSalt, err = base64.StdEncoding.DecodeString(c.Password)
	case global.HEX:
		decodedPwSasltSalt, err = hex.DecodeString(c.Password)
	}

	if err != nil {
		return salt, alg, pwOption, err
	}

	switch alg {
	case global.SSHA512:
		salt = decodedPwSasltSalt[64:]
	case global.SSHA256:
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

// redisTLSOptions checks if Redis TLS is enabled in the configuration.
// If TLS is enabled, it loads the X509 key pair and creates a tls.Config object.
// The loaded certificate is added to the tls.Config object.
// If an error occurs while loading the key pair, it logs the error and returns nil.
// If Redis TLS is disabled, it returns nil.
func redisTLSOptions(tlsCfg *config.TLS) *tls.Config {
	if config.LoadableConfig.Server.Redis.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(tlsCfg.Cert, tlsCfg.Key)
		if err != nil {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyInstance, config.LoadableConfig.Server.InstanceName, global.LogKeyError, err)

			return nil
		}

		// Create a tls.Config object to use
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		return tlsConfig
	}

	return nil
}

// newRedisFailoverClient creates a new failover client for Redis.
// The client connects to Redis through sentinels. The option slavesOnly determines
// whether the client reads from slaves only. If it is set to true, all reads will be
// done from the slave. If it is set to false, read operations can be done from both
// the master and slave. The configuration for the client (such as MasterName,
// SentinelAddrs, DB, SentinelUsername, SentinelPassword, Username, Password,
// PoolSize, MinIdleConns) are loaded from the config.
//
// It returns a redisHandle which is a pointer to a redis.Client object.
//
// usage:
//
//	client := newRedisFailoverClient(true)
func newRedisFailoverClient(redisCfg *config.Redis, slavesOnly bool) (redisHandle *redis.Client) {
	redisHandle = redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:       redisCfg.Sentinels.Master,
		SentinelAddrs:    redisCfg.Sentinels.Addresses,
		ReplicaOnly:      slavesOnly,
		DB:               redisCfg.DatabaseNmuber,
		SentinelUsername: redisCfg.Sentinels.Username,
		SentinelPassword: redisCfg.Sentinels.Password,
		Username:         redisCfg.Master.Username,
		Password:         redisCfg.Master.Password,
		PoolSize:         redisCfg.PoolSize,
		MinIdleConns:     redisCfg.IdlePoolSize,
		TLSConfig:        redisTLSOptions(&redisCfg.TLS),
	})

	return
}

// newRedisClient returns a new Redis client that is configured with the provided address and authentication credentials.
// The client is created using the redis.NewClient function from the "github.com/go-redis/redis" package.
// The address is used to specify the network address of the Redis server.
// The remaining configuration properties such as username, password, database number, pool size, and TLS options are obtained from the "config.LoadableConfig.Server.Redis.Master" and
func newRedisClient(redisCfg *config.Redis, address string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:         address,
		Username:     redisCfg.Master.Username,
		Password:     redisCfg.Master.Password,
		DB:           redisCfg.DatabaseNmuber,
		PoolSize:     redisCfg.PoolSize,
		MinIdleConns: redisCfg.IdlePoolSize,
		TLSConfig:    redisTLSOptions(&redisCfg.TLS),
	})
}

// newRedisClusterClient creates a new Redis cluster client using the specified cluster options.
// The cluster options include the addresses of the Redis cluster nodes, username, password, pool size, and minimum idle connections.
// It also includes the TLS configuration obtained from the redisTLSOptions function.
// The newRedisClusterClient function returns a pointer to the redis.ClusterClient object.
func newRedisClusterClient(redisCfg *config.Redis) *redis.ClusterClient {
	return redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:        redisCfg.Cluster.Addresses,
		Username:     redisCfg.Cluster.Username,
		Password:     redisCfg.Cluster.Password,
		PoolSize:     redisCfg.PoolSize,
		MinIdleConns: redisCfg.IdlePoolSize,
		TLSConfig:    redisTLSOptions(&redisCfg.TLS),
	})
}

// NewRedisClient creates a new Redis client based on the configuration settings.
// It checks whether a Redis cluster is specified in the configuration and creates a cluster client if so.
// If a Redis sentinel setup is specified in the configuration, it creates a failover client.
// For a standalone Redis setup, it creates a regular Redis client.
// The created Redis client is then returned as a universal client.
func NewRedisClient() (redisHandle redis.UniversalClient) {
	redisCfg := &config.LoadableConfig.Server.Redis

	if len(redisCfg.Cluster.Addresses) > 0 {
		redisHandle = newRedisClusterClient(redisCfg)
	} else if len(redisCfg.Sentinels.Addresses) > 0 && redisCfg.Sentinels.Master != "" {
		redisHandle = newRedisFailoverClient(redisCfg, false)
	} else {
		redisHandle = newRedisClient(redisCfg, redisCfg.Master.Address)
	}

	return
}

// NewRedisReplicaClient is a function that returns a Redis replica client based on the configuration settings.
// If there are cluster addresses configured, it returns nil.
// If there are multiple sentinel addresses and a master address is configured, it returns a failover client.
// If the replica address is different from the master address, it returns a regular client using the replica address.
// Otherwise, it returns nil.
func NewRedisReplicaClient() redis.UniversalClient {
	redisCfg := &config.LoadableConfig.Server.Redis

	if len(redisCfg.Cluster.Addresses) > 0 {
		return nil
	}

	if len(redisCfg.Sentinels.Addresses) > 1 && redisCfg.Sentinels.Master != "" {
		return newRedisFailoverClient(redisCfg, true)
	}

	if redisCfg.Master.Address != redisCfg.Replica.Address {
		return newRedisClient(redisCfg, redisCfg.Replica.Address)
	}

	return nil
}

// NewDNSResolver creates a new DNS resolver based on the configured settings.
func NewDNSResolver() (resolver *net.Resolver) {
	if config.LoadableConfig.Server.DNS.Resolver == "" {
		level.Debug(logging.DefaultLogger).Log(global.LogKeyMsg, "Using default DNS resolver")

		resolver = &net.Resolver{
			PreferGo: true,
		}
	} else {
		level.Debug(logging.DefaultLogger).Log(global.LogKeyMsg, fmt.Sprintf("Using DNS resolver %s", config.LoadableConfig.Server.DNS.Resolver))

		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}

				return dialer.DialContext(ctx, network, fmt.Sprintf("%s:53", config.LoadableConfig.Server.DNS.Resolver))
			},
		}
	}

	return
}

// ResolveIPAddress returns the hostname for a given IP address.
func ResolveIPAddress(ctx context.Context, address string) (hostname string) {
	ctxTimeout, cancel := context.WithDeadline(ctx, time.Now().Add(config.LoadableConfig.Server.DNS.Timeout*time.Second))

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

func DebugModule(module global.DbgModule, keyvals ...any) {
	var moduleName string

	if config.LoadableConfig.Server.Log.Level.Level() < global.LogLevelDebug {
		return
	}

	switch module {
	case global.DbgAll:
		moduleName = global.DbgAllName
	case global.DbgAuth:
		moduleName = global.DbgAuthName
	case global.DbgHydra:
		moduleName = global.DbgHydraName
	case global.DbgWebAuthn:
		moduleName = global.DbgWebAuthnName
	case global.DbgStats:
		moduleName = global.DbgStatsName
	case global.DbgWhitelist:
		moduleName = global.DbgWhitelistName
	case global.DbgLDAP:
		moduleName = global.DbgLDAPName
	case global.DbgLDAPPool:
		moduleName = global.DbgLDAPPoolName
	case global.DbgCache:
		moduleName = global.DbgCacheName
	case global.DbgBf:
		moduleName = global.DbgBfName
	case global.DbgRBL:
		moduleName = global.DbgRBLName
	case global.DbgAction:
		moduleName = global.DbgActionName
	case global.DbgFeature:
		moduleName = global.DbgFeatureName
	case global.DbgLua:
		moduleName = global.DbgLuaName
	case global.DbgFilter:
		moduleName = global.DbgFilterName
	default:
		return
	}

	for index := range config.LoadableConfig.Server.Log.DbgModules {
		if !(config.LoadableConfig.Server.Log.DbgModules[index].GetModule() == global.DbgAll || config.LoadableConfig.Server.Log.DbgModules[index].GetModule() == module) {
			continue
		}

		keyvals = append(keyvals, "debug_module")
		keyvals = append(keyvals, moduleName)

		if counter, _, _, ok := runtime.Caller(1); ok {
			keyvals = append(keyvals, "function")
			keyvals = append(keyvals, runtime.FuncForPC(counter).Name())

			level.Debug(logging.DefaultLogger).Log(keyvals...)
		}

		break
	}
}

// WithNotAvailable checks a list of string. If none of the strings does have a content, we return the global.NotAvailable string.
func WithNotAvailable(elements ...any) string {
	var value string

	value = CheckStrings(elements...)

	if value == "" {
		return global.NotAvailable
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
			global.DbgAuth,
			global.LogKeyMsg, "Found header X-Forwarded-For",
		)

		for _, trustedProxy := range viper.GetStringSlice("trusted_proxies") {
			if clientIP != trustedProxy {
				DebugModule(
					global.DbgAuth,
					global.LogKeyMsg, fmt.Sprintf("Client IP '%s' not matching '%s'", clientIP, trustedProxy),
				)

				continue
			}

			DebugModule(
				global.DbgAuth,
				global.LogKeyMsg, fmt.Sprintf(
					"Client IP '%s' matching, forwarded for '%s'", clientIP, fwdAddress),
			)

			clientIP = fwdAddress

			multipleIPs := strings.Split(fwdAddress, ", ")
			if len(multipleIPs) > 1 {
				clientIP = multipleIPs[0]
			}

			clientPort = global.NotAvailable

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
