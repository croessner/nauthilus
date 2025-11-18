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
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"

	"github.com/redis/go-redis/v9"
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
	redisHandle = redis.NewFailoverClient(&redis.FailoverOptions{
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
	})

	return
}

// newRedisClient returns a new Redis client that is configured with the provided address and authentication credentials.
// The client is created using the redis.NewClient function from the "github.com/go-redis/redis" package.
// The address is used to specify the network address of the Redis server.
// The remaining configuration properties such as username, password, database number, pool size, and TLS options are obtained from the "config.GetFile().GetServer().Redis.Master" and
func newRedisClient(redisCfg *config.Redis, address string) *redis.Client {
	return redis.NewClient(&redis.Options{
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
	})
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

	return redis.NewClusterClient(options)
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

	return redis.NewClusterClient(options)
}
