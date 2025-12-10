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

package rediscli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"

	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
	maintnotifications "github.com/redis/go-redis/v9/maintnotifications"
)

// RedisTLSOptions checks if Redis TLS is enabled in the configuration.
// If TLS is enabled, it loads the X509 key pair and creates a tls.Config object.
// The loaded certificate is added to the tls.Config object.
// If an error occurs while loading the key pair, it logs the error and returns nil.
// If Redis TLS is disabled, it returns nil.
func RedisTLSOptions(tlsCfg *config.TLS) *tls.Config {
	if tlsCfg != nil && tlsCfg.IsEnabled() {
		var certs []tls.Certificate
		var caCertPool *x509.CertPool

		if tlsCfg.GetCAFile() != "" {
			caCert, err := os.ReadFile(tlsCfg.GetCAFile())
			if err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, "Failed to read CA certificate",
					definitions.LogKeyError, err,
				)
			}

			caCertPool = x509.NewCertPool()
			if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, "Failed to append CA certificate",
					definitions.LogKeyError, "Failed to append CA certificate",
				)

				return nil
			}
		}

		if tlsCfg.GetCert() != "" && tlsCfg.GetKey() != "" {
			cert, err := tls.LoadX509KeyPair(tlsCfg.GetCert(), tlsCfg.GetKey())
			if err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, "Failed to load X509 key pair",
					definitions.LogKeyError, err,
				)

				return nil
			}

			certs = append(certs, cert)
		}

		// Create a tls.Config object to use
		tlsConfig := &tls.Config{
			Certificates:       certs,
			RootCAs:            caCertPool,
			InsecureSkipVerify: tlsCfg.GetSkipVerify(),
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
	fo := &redis.FailoverOptions{
		MasterName:       redisCfg.GetSentinel().GetMasterName(),
		SentinelAddrs:    redisCfg.GetSentinel().GetAddresses(),
		ReplicaOnly:      slavesOnly,
		DB:               redisCfg.GetDatabaseNumber(),
		SentinelUsername: redisCfg.GetSentinel().GetUsername(),
		SentinelPassword: redisCfg.GetSentinel().GetPassword(),
		Username:         redisCfg.GetStandaloneMaster().GetUsername(),
		Password:         redisCfg.GetStandaloneMaster().GetPassword(),
		PoolSize:         redisCfg.GetPoolSize(),
		MinIdleConns:     redisCfg.GetIdlePoolSize(),
		TLSConfig:        RedisTLSOptions(redisCfg.GetTLS()),

		ContextTimeoutEnabled: true,
		PoolTimeout:           redisCfg.GetPoolTimeout(),
		DialTimeout:           redisCfg.GetDialTimeout(),
		ReadTimeout:           redisCfg.GetReadTimeout(),
		WriteTimeout:          redisCfg.GetWriteTimeout(),
		PoolFIFO:              redisCfg.GetPoolFIFO(),
		ConnMaxIdleTime:       redisCfg.GetConnMaxIdleTime(),
		MaxRetries:            redisCfg.GetMaxRetries(),
		// CLIENT SETINFO toggle from configuration (default disabled for compatibility).
		DisableIdentity: !redisCfg.IsIdentityEnabled(),
		// Explicitly prefer RESP3 to ensure push notifications for tracking
		Protocol: 3,
	}

	// Enable CLIENT TRACKING if configured
	if ct := redisCfg.GetClientTracking(); ct.IsEnabled() {
		fo.OnConnect = func(ctx context.Context, cn *redis.Conn) error {
			return enableClientTracking(ctx, cn, ct)
		}
	}

	redisHandle = redis.NewFailoverClient(fo)

	// Attach OpenTelemetry Redis tracing if enabled
	instrumentRedisIfEnabled(redisHandle)

	// Attach client-side batching hook if enabled
	attachBatchingHookIfEnabled(redisHandle)

	return
}

// newRedisClient returns a new Redis client that is configured with the provided address and authentication credentials.
// The client is created using the redis.NewClient function from the "github.com/go-redis/redis" package.
// The address is used to specify the network address of the Redis server.
// The remaining configuration properties such as username, password, database number, pool size, and TLS options are obtained from the "config.GetFile().GetServer().Redis.Master" and
func newRedisClient(redisCfg *config.Redis, address string) *redis.Client {
	opts := &redis.Options{
		Addr:         address,
		Username:     redisCfg.GetStandaloneMaster().GetUsername(),
		Password:     redisCfg.GetStandaloneMaster().GetPassword(),
		DB:           redisCfg.GetDatabaseNumber(),
		PoolSize:     redisCfg.GetPoolSize(),
		MinIdleConns: redisCfg.GetIdlePoolSize(),
		TLSConfig:    RedisTLSOptions(redisCfg.GetTLS()),

		ContextTimeoutEnabled: true,
		PoolTimeout:           redisCfg.GetPoolTimeout(),
		DialTimeout:           redisCfg.GetDialTimeout(),
		ReadTimeout:           redisCfg.GetReadTimeout(),
		WriteTimeout:          redisCfg.GetWriteTimeout(),
		PoolFIFO:              redisCfg.GetPoolFIFO(),
		ConnMaxIdleTime:       redisCfg.GetConnMaxIdleTime(),
		MaxRetries:            redisCfg.GetMaxRetries(),
		// CLIENT SETINFO toggle from configuration (default disabled for compatibility).
		DisableIdentity: !redisCfg.IsIdentityEnabled(),
		// Ensure RESP3 to support push notifications
		Protocol: 3,
	}

	// Maintenance Notifications: only enable if configured. Standalone supports MaintNotificationsConfig.
	if redisCfg.IsMaintNotificationsEnabled() {
		opts.MaintNotificationsConfig = &maintnotifications.Config{Mode: maintnotifications.ModeAuto}
	} else {
		opts.MaintNotificationsConfig = &maintnotifications.Config{Mode: maintnotifications.ModeDisabled}
	}

	if ct := redisCfg.GetClientTracking(); ct.IsEnabled() {
		opts.OnConnect = func(ctx context.Context, cn *redis.Conn) error {
			return enableClientTracking(ctx, cn, ct)
		}
	}

	c := redis.NewClient(opts)

	// Attach OpenTelemetry Redis tracing if enabled
	instrumentRedisIfEnabled(c)

	// Attach client-side batching hook if enabled
	attachBatchingHookIfEnabled(c)

	return c
}

// newRedisClusterClient creates a new Redis cluster client using the specified cluster options.
// The cluster options include the addresses of the Redis cluster nodes, username, password, pool size, and minimum idle connections.
// It also includes topology awareness features like RouteByLatency, RouteRandomly, and RouteReadsToReplicas.
// Additional options include MaxRedirects, ReadTimeout, and WriteTimeout for fine-tuning the cluster behavior.
// The function includes the TLS configuration obtained from the RedisTLSOptions function.
// The newRedisClusterClient function returns a pointer to the redis.ClusterClient object.
func newRedisClusterClient(redisCfg *config.Redis) *redis.ClusterClient {
	clusterCfg := redisCfg.GetCluster()

	options := &redis.ClusterOptions{
		Addrs:        clusterCfg.GetAddresses(),
		Username:     clusterCfg.GetUsername(),
		Password:     clusterCfg.GetPassword(),
		PoolSize:     redisCfg.GetPoolSize(),
		MinIdleConns: redisCfg.GetIdlePoolSize(),
		TLSConfig:    RedisTLSOptions(redisCfg.GetTLS()),

		ContextTimeoutEnabled: true,
		PoolTimeout:           redisCfg.GetPoolTimeout(),
		DialTimeout:           redisCfg.GetDialTimeout(),
		ReadTimeout:           redisCfg.GetReadTimeout(),
		WriteTimeout:          redisCfg.GetWriteTimeout(),
		PoolFIFO:              redisCfg.GetPoolFIFO(),
		ConnMaxIdleTime:       redisCfg.GetConnMaxIdleTime(),
		MaxRetries:            redisCfg.GetMaxRetries(),

		// Topology awareness options
		RouteByLatency: clusterCfg.GetRouteByLatency(),
		RouteRandomly:  clusterCfg.GetRouteRandomly(),
		ReadOnly:       clusterCfg.GetRouteReadsToReplicas(),
		// CLIENT SETINFO toggle from configuration (default disabled for compatibility).
		DisableIdentity: !redisCfg.IsIdentityEnabled(),
		// Ensure RESP3 to support push notifications for tracking
		Protocol: 3,
	}

	// Maintenance Notifications for cluster: configurable. Apply to options to propagate to nodes.
	if redisCfg.IsMaintNotificationsEnabled() {
		options.MaintNotificationsConfig = &maintnotifications.Config{Mode: maintnotifications.ModeAuto}
	} else {
		options.MaintNotificationsConfig = &maintnotifications.Config{Mode: maintnotifications.ModeDisabled}
	}

	// Set optional parameters only if they have non-zero values
	if maxRedirects := clusterCfg.GetMaxRedirects(); maxRedirects > 0 {
		options.MaxRedirects = maxRedirects
	}

	if readTimeout := clusterCfg.GetReadTimeout(); readTimeout > 0 {
		options.ReadTimeout = readTimeout
	}

	if writeTimeout := clusterCfg.GetWriteTimeout(); writeTimeout > 0 {
		options.WriteTimeout = writeTimeout
	}

	if ct := redisCfg.GetClientTracking(); ct.IsEnabled() {
		options.OnConnect = func(ctx context.Context, cn *redis.Conn) error {
			return enableClientTracking(ctx, cn, ct)
		}
	}

	c := redis.NewClusterClient(options)

	// Attach OpenTelemetry Redis tracing if enabled
	instrumentRedisIfEnabled(c)

	// Attach client-side batching hook if enabled
	attachBatchingHookIfEnabled(c)

	return c
}

// instrumentRedisIfEnabled enables OpenTelemetry tracing for Redis clients when configured.
func instrumentRedisIfEnabled(c redis.UniversalClient) {
	tr := config.GetFile().GetServer().GetInsights().GetTracing()
	if tr.IsEnabled() && tr.IsRedisEnabled() {
		// Ignore error to avoid impacting runtime if instrumentation fails
		_ = redisotel.InstrumentTracing(c)
	}
}

// newRedisClusterClientReadOnly creates a new Redis cluster client optimized for read operations.
// It's similar to newRedisClusterClient but forces the ReadOnly flag to true, which directs
// read commands to replica nodes in the cluster rather than masters.
// This function is used to create a separate client for read operations to improve performance
// and reduce load on master nodes.
func newRedisClusterClientReadOnly(redisCfg *config.Redis) *redis.ClusterClient {
	clusterCfg := redisCfg.GetCluster()

	options := &redis.ClusterOptions{
		Addrs:        clusterCfg.GetAddresses(),
		Username:     clusterCfg.GetUsername(),
		Password:     clusterCfg.GetPassword(),
		PoolSize:     redisCfg.GetPoolSize(),
		MinIdleConns: redisCfg.GetIdlePoolSize(),
		TLSConfig:    RedisTLSOptions(redisCfg.GetTLS()),

		ContextTimeoutEnabled: true,
		PoolTimeout:           redisCfg.GetPoolTimeout(),
		DialTimeout:           redisCfg.GetDialTimeout(),
		ReadTimeout:           redisCfg.GetReadTimeout(),
		WriteTimeout:          redisCfg.GetWriteTimeout(),
		PoolFIFO:              redisCfg.GetPoolFIFO(),
		ConnMaxIdleTime:       redisCfg.GetConnMaxIdleTime(),
		MaxRetries:            redisCfg.GetMaxRetries(),

		// Topology awareness options - force ReadOnly to true
		RouteByLatency: clusterCfg.GetRouteByLatency(),
		RouteRandomly:  clusterCfg.GetRouteRandomly(),
		ReadOnly:       true, // Always use replicas for read operations
		// CLIENT SETINFO toggle from configuration (default disabled for compatibility).
		DisableIdentity: !redisCfg.IsIdentityEnabled(),
		// Ensure RESP3 to support push notifications for tracking
		Protocol: 3,
	}

	// Maintenance Notifications for cluster read-only client: mirror primary setting.
	if redisCfg.IsMaintNotificationsEnabled() {
		options.MaintNotificationsConfig = &maintnotifications.Config{Mode: maintnotifications.ModeAuto}
	} else {
		options.MaintNotificationsConfig = &maintnotifications.Config{Mode: maintnotifications.ModeDisabled}
	}

	// Set optional parameters only if they have non-zero values
	if maxRedirects := clusterCfg.GetMaxRedirects(); maxRedirects > 0 {
		options.MaxRedirects = maxRedirects
	}

	if readTimeout := clusterCfg.GetReadTimeout(); readTimeout > 0 {
		options.ReadTimeout = readTimeout
	}

	if writeTimeout := clusterCfg.GetWriteTimeout(); writeTimeout > 0 {
		options.WriteTimeout = writeTimeout
	}

	// Enable CLIENT TRACKING on connection if configured
	if ct := redisCfg.GetClientTracking(); ct.IsEnabled() {
		options.OnConnect = func(ctx context.Context, cn *redis.Conn) error {
			return enableClientTracking(ctx, cn, ct)
		}
	}

	c := redis.NewClusterClient(options)

	// Attach client-side batching hook if enabled
	attachBatchingHookIfEnabled(c)

	return c
}

// enableClientTracking sends a CLIENT TRACKING ON command with configured flags.
// It requires a RESP3 connection; go-redis negotiates RESP3 by default when Protocol is 3.
func enableClientTracking(ctx context.Context, cn *redis.Conn, ct *config.RedisClientTracking) error {
	args := buildClientTrackingArgs(ct)

	// Use the low-level Do to send the command
	if err := cn.Do(ctx, args...).Err(); err != nil {
		// Log error but don't fail the connection establishment
		level.Warn(log.Logger).Log(
			definitions.LogKeyMsg, "CLIENT TRACKING failed; continuing without tracking",
			definitions.LogKeyError, err,
		)

		return nil
	}

	return nil
}

// buildClientTrackingArgs builds arguments slice for CLIENT TRACKING ON
func buildClientTrackingArgs(ct *config.RedisClientTracking) []interface{} {
	args := []any{"client", "tracking", "on"}

	if ct == nil {
		return args
	}

	if ct.IsBCast() {
		args = append(args, "bcast")
	}

	if ct.IsNoLoop() {
		args = append(args, "noloop")
	}

	if ct.IsOptIn() {
		args = append(args, "optin")
	}

	if ct.IsOptOut() {
		args = append(args, "optout")
	}

	prefixes := ct.GetPrefixes()
	for _, p := range prefixes {
		if p == "" {
			continue
		}

		args = append(args, "prefix", p)
	}

	return args
}
