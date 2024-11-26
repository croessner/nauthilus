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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
)

// RedisTLSOptions checks if Redis TLS is enabled in the configuration.
// If TLS is enabled, it loads the X509 key pair and creates a tls.Config object.
// The loaded certificate is added to the tls.Config object.
// If an error occurs while loading the key pair, it logs the error and returns nil.
// If Redis TLS is disabled, it returns nil.
func RedisTLSOptions(tlsCfg *config.TLS) *tls.Config {
	if tlsCfg != nil && tlsCfg.Enabled {
		var certs []tls.Certificate

		if tlsCfg.Cert != "" && tlsCfg.Key != "" {
			cert, err := tls.LoadX509KeyPair(tlsCfg.Cert, tlsCfg.Key)
			if err != nil {
				level.Error(log.Logger).Log(definitions.LogKeyInstance, config.LoadableConfig.Server.InstanceName, definitions.LogKeyMsg, err)

				return nil
			}

			certs = append(certs, cert)
		}

		// Create a tls.Config object to use
		tlsConfig := &tls.Config{
			Certificates: certs,
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
		TLSConfig:        RedisTLSOptions(&redisCfg.TLS),
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
		TLSConfig:    RedisTLSOptions(&redisCfg.TLS),
	})
}

// newRedisClusterClient creates a new Redis cluster client using the specified cluster options.
// The cluster options include the addresses of the Redis cluster nodes, username, password, pool size, and minimum idle connections.
// It also includes the TLS configuration obtained from the RedisTLSOptions function.
// The newRedisClusterClient function returns a pointer to the redis.ClusterClient object.
func newRedisClusterClient(redisCfg *config.Redis) *redis.ClusterClient {
	return redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:        redisCfg.Cluster.Addresses,
		Username:     redisCfg.Cluster.Username,
		Password:     redisCfg.Cluster.Password,
		PoolSize:     redisCfg.PoolSize,
		MinIdleConns: redisCfg.IdlePoolSize,
		TLSConfig:    RedisTLSOptions(&redisCfg.TLS),
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

	if redisCfg.Replica.Address != "" {
		if redisCfg.Master.Address != redisCfg.Replica.Address {
			return newRedisClient(redisCfg, redisCfg.Replica.Address)
		}
	}

	return nil
}
