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
	"log/slog"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/log/level"

	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

// redisTLSOptions builds production Redis TLS from the candidate-bound artifact snapshot.
func redisTLSOptions(cfg config.File, tlsCfg *config.TLS) (*tls.Config, error) {
	return config.BuildClientTLSConfig(cfg, tlsCfg)
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
func newRedisFailoverClient(cfg config.File, logger *slog.Logger, redisCfg *config.Redis, slavesOnly bool, tlsConfig *tls.Config) (redisHandle *redis.Client) {
	sentinelPassword := ""

	redisCfg.GetSentinel().GetPassword().WithString(func(value string) {
		sentinelPassword = value
	})

	masterPassword := ""

	redisCfg.GetStandaloneMaster().GetPassword().WithString(func(value string) {
		masterPassword = value
	})

	fo := &redis.FailoverOptions{
		MasterName:       redisCfg.GetSentinel().GetMasterName(),
		SentinelAddrs:    redisCfg.GetSentinel().GetAddresses(),
		ReplicaOnly:      slavesOnly,
		DB:               redisCfg.GetDatabaseNumber(),
		SentinelUsername: redisCfg.GetSentinel().GetUsername(),
		SentinelPassword: sentinelPassword,
		Username:         redisCfg.GetStandaloneMaster().GetUsername(),
		Password:         masterPassword,
		PoolSize:         redisCfg.GetPoolSize(),
		MinIdleConns:     redisCfg.GetIdlePoolSize(),
		TLSConfig:        tlsConfig,

		ContextTimeoutEnabled: false,
		PoolTimeout:           redisCfg.GetPoolTimeout(),
		DialTimeout:           redisCfg.GetDialTimeout(),
		ReadTimeout:           redisCfg.GetReadTimeout(),
		WriteTimeout:          redisCfg.GetWriteTimeout(),
		PoolFIFO:              redisCfg.GetPoolFIFO(),
		ConnMaxIdleTime:       redisCfg.GetConnMaxIdleTime(),
		MaxRetries:            redisCfg.GetMaxRetries(),
		// CLIENT SETINFO toggle from configuration (default disabled for compatibility).
		DisableIdentity: !redisCfg.IsIdentityEnabled(),
		// Prefer RESP3 only if requested or RESP3-only capabilities are enabled.
		// Otherwise, default to RESP2 to avoid parsing issues with asynchronous push messages.
		Protocol: getProtocol(redisCfg),
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
	attachBatchingHookIfEnabled(cfg, logger, redisHandle)

	return
}

// newRedisClient returns a new Redis client that is configured with the provided address and authentication credentials.
// The client is created using the redis.NewClient function from the "github.com/go-redis/redis" package.
// The address is used to specify the network address of the Redis server.
// The remaining configuration properties such as username, password, database number, pool size, and TLS options are obtained from the "config.GetFile().GetServer().Redis.Master" and
func newRedisClient(cfg config.File, logger *slog.Logger, redisCfg *config.Redis, address string, tlsConfig *tls.Config) *redis.Client {
	masterPassword := ""

	redisCfg.GetStandaloneMaster().GetPassword().WithString(func(value string) {
		masterPassword = value
	})

	opts := &redis.Options{
		Addr:         address,
		Username:     redisCfg.GetStandaloneMaster().GetUsername(),
		Password:     masterPassword,
		DB:           redisCfg.GetDatabaseNumber(),
		PoolSize:     redisCfg.GetPoolSize(),
		MinIdleConns: redisCfg.GetIdlePoolSize(),
		TLSConfig:    tlsConfig,

		ContextTimeoutEnabled: false,
		PoolTimeout:           redisCfg.GetPoolTimeout(),
		DialTimeout:           redisCfg.GetDialTimeout(),
		ReadTimeout:           redisCfg.GetReadTimeout(),
		WriteTimeout:          redisCfg.GetWriteTimeout(),
		PoolFIFO:              redisCfg.GetPoolFIFO(),
		ConnMaxIdleTime:       redisCfg.GetConnMaxIdleTime(),
		MaxRetries:            redisCfg.GetMaxRetries(),
		// CLIENT SETINFO toggle from configuration (default disabled for compatibility).
		DisableIdentity: !redisCfg.IsIdentityEnabled(),
		// Ensure RESP version based on configuration and Redis capabilities.
		Protocol: getProtocol(redisCfg),
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
	attachBatchingHookIfEnabled(cfg, logger, c)

	return c
}

// newRedisClusterClient creates a new Redis cluster client using the specified cluster options.
// The cluster options include the addresses of the Redis cluster nodes, username, password, pool size, and minimum idle connections.
// It also includes topology awareness capabilities like RouteByLatency, RouteRandomly, and RouteReadsToReplicas.
// Additional options include MaxRedirects, ReadTimeout, and WriteTimeout for fine-tuning the cluster behavior.
// The function receives TLS parsed from the candidate-bound artifact snapshot.
// The newRedisClusterClient function returns a pointer to the redis.ClusterClient object.
func newRedisClusterClient(cfg config.File, logger *slog.Logger, redisCfg *config.Redis, tlsConfig *tls.Config) *redis.ClusterClient {
	clusterCfg := redisCfg.GetCluster()
	options := newRedisClusterOptions(redisCfg, clusterCfg, tlsConfig)

	setRedisClusterMaintenanceNotifications(options, redisCfg)
	setRedisClusterOptionalTimeouts(options, clusterCfg)
	setRedisClusterClientTracking(options, redisCfg)

	c := redis.NewClusterClient(options)

	// Attach OpenTelemetry Redis tracing if enabled
	instrumentRedisIfEnabled(c)

	// Attach client-side batching hook if enabled
	attachBatchingHookIfEnabled(cfg, logger, c)

	return c
}

// newRedisClusterOptions builds the base Redis Cluster option set.
func newRedisClusterOptions(redisCfg *config.Redis, clusterCfg *config.Cluster, tlsConfig *tls.Config) *redis.ClusterOptions {
	return &redis.ClusterOptions{
		Addrs:                 clusterCfg.GetAddresses(),
		Username:              clusterCfg.GetUsername(),
		Password:              redisClusterPassword(clusterCfg),
		PoolSize:              redisCfg.GetPoolSize(),
		MinIdleConns:          redisCfg.GetIdlePoolSize(),
		TLSConfig:             tlsConfig,
		ContextTimeoutEnabled: false,
		PoolTimeout:           redisCfg.GetPoolTimeout(),
		DialTimeout:           redisCfg.GetDialTimeout(),
		ReadTimeout:           redisCfg.GetReadTimeout(),
		WriteTimeout:          redisCfg.GetWriteTimeout(),
		PoolFIFO:              redisCfg.GetPoolFIFO(),
		ConnMaxIdleTime:       redisCfg.GetConnMaxIdleTime(),
		MaxRetries:            redisCfg.GetMaxRetries(),
		RouteByLatency:        clusterCfg.GetRouteByLatency(),
		RouteRandomly:         clusterCfg.GetRouteRandomly(),
		ReadOnly:              clusterCfg.GetRouteReadsToReplicas(),
		DisableIdentity:       !redisCfg.IsIdentityEnabled(),
		Protocol:              getProtocol(redisCfg),
	}
}

// redisClusterPassword extracts the optional cluster password value.
func redisClusterPassword(clusterCfg *config.Cluster) string {
	clusterPassword := ""

	clusterCfg.GetPassword().WithString(func(value string) {
		clusterPassword = value
	})

	return clusterPassword
}

// setRedisClusterMaintenanceNotifications applies the configured Redis maintenance mode.
func setRedisClusterMaintenanceNotifications(options *redis.ClusterOptions, redisCfg *config.Redis) {
	if redisCfg.IsMaintNotificationsEnabled() {
		options.MaintNotificationsConfig = &maintnotifications.Config{Mode: maintnotifications.ModeAuto}

		return
	}

	options.MaintNotificationsConfig = &maintnotifications.Config{Mode: maintnotifications.ModeDisabled}
}

// setRedisClusterOptionalTimeouts applies optional cluster-specific timeout overrides.
func setRedisClusterOptionalTimeouts(options *redis.ClusterOptions, clusterCfg *config.Cluster) {
	if maxRedirects := clusterCfg.GetMaxRedirects(); maxRedirects > 0 {
		options.MaxRedirects = maxRedirects
	}

	if readTimeout := clusterCfg.GetReadTimeout(); readTimeout > 0 {
		options.ReadTimeout = readTimeout
	}

	if writeTimeout := clusterCfg.GetWriteTimeout(); writeTimeout > 0 {
		options.WriteTimeout = writeTimeout
	}
}

// setRedisClusterClientTracking wires Redis client tracking when enabled.
func setRedisClusterClientTracking(options *redis.ClusterOptions, redisCfg *config.Redis) {
	if ct := redisCfg.GetClientTracking(); ct.IsEnabled() {
		options.OnConnect = func(ctx context.Context, cn *redis.Conn) error {
			return enableClientTracking(ctx, cn, ct)
		}
	}
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
func newRedisClusterClientReadOnly(cfg config.File, logger *slog.Logger, redisCfg *config.Redis, tlsConfig *tls.Config) *redis.ClusterClient {
	clusterCfg := redisCfg.GetCluster()
	options := newRedisClusterOptions(redisCfg, clusterCfg, tlsConfig)
	options.ReadOnly = true

	setRedisClusterMaintenanceNotifications(options, redisCfg)
	setRedisClusterOptionalTimeouts(options, clusterCfg)
	setRedisClusterClientTracking(options, redisCfg)

	c := redis.NewClusterClient(options)

	// Attach OpenTelemetry Redis tracing if enabled
	instrumentRedisIfEnabled(c)

	// Attach client-side batching hook if enabled
	attachBatchingHookIfEnabled(cfg, logger, c)

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
func buildClientTrackingArgs(ct *config.RedisClientTracking) []any {
	args := []any{redisCommandClient, "tracking", "on"}

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

// getProtocol determines the Redis protocol version (2 or 3) to use.
func getProtocol(redisCfg *config.Redis) int {
	if redisCfg == nil {
		return 2
	}

	// If a protocol is explicitly configured, use it.
	if p := redisCfg.GetProtocol(); p > 0 {
		return p
	}

	// Default to RESP3 only if RESP3-only capabilities are enabled.
	if redisCfg.GetClientTracking().IsEnabled() || redisCfg.IsMaintNotificationsEnabled() {
		return 3
	}

	// Default to RESP2 for stability with pipelines.
	return 2
}
