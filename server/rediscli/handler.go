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
	"math/rand"

	"github.com/croessner/nauthilus/server/config"
	"github.com/redis/go-redis/v9"
)

// RedisClients provides an interface to interact with Redis, supporting methods for initialization and handle management.
var client Client

func GetClient() Client {
	if client == nil {
		client = NewClient()
	}

	return client
}

// Client defines an interface for interacting with a Redis client with methods for initialization and handle retrieval.
type Client interface {
	// GetWriteHandle retrieves the Redis client's write handle for operations requiring write access.
	GetWriteHandle() redis.UniversalClient

	// GetReadHandle retrieves a Redis client's read handle, supporting multiple read handles for load balancing.
	GetReadHandle() redis.UniversalClient

	// Close releases all resources associated with the client, including write and read handles, and closes any open connections.
	Close()
}

// redisClient represents a Redis client with separate handles for write and read operations.
// It implements methods to initialize and retrieve these handles.
type redisClient struct {
	// writeHandle represents the primary Redis client used for write operations within the redisClient structure.
	writeHandle redis.UniversalClient

	// readHandle is a map that associates Redis server addresses with their corresponding read-only Redis client instances.
	readHandle map[string]redis.UniversalClient
}

var _ Client = (*redisClient)(nil)

// NewClient creates and returns a new instance of a Redis client that implements the Client interface.
func NewClient() Client {
	newClient := &redisClient{}

	newClient.newRedisClient()
	newClient.newRedisReplicaClient()

	return newClient
}

// newRedisClient initializes the redisClient by setting its write handle based on the provided Redis configuration.
func (clt *redisClient) newRedisClient() {
	redisCfg := &config.GetFile().GetServer().Redis

	if len(redisCfg.Cluster.Addresses) > 0 {
		clt.SetWriteHandle(newRedisClusterClient(redisCfg))
	} else if len(redisCfg.Sentinels.Addresses) > 0 && redisCfg.Sentinels.Master != "" {
		clt.SetWriteHandle(newRedisFailoverClient(redisCfg, false))
	} else {
		if redisCfg.Master.Address == "" {
			panic("no Redis master address provided")
		}

		clt.SetWriteHandle(newRedisClient(redisCfg, redisCfg.Master.Address))
	}
}

// newRedisReplicaClient initializes read handles for Redis replicas based on the configuration, supporting multiple setups.
func (clt *redisClient) newRedisReplicaClient() {
	redisCfg := &config.GetFile().GetServer().Redis

	if len(redisCfg.Cluster.Addresses) > 0 {
		return
	}

	if len(redisCfg.Sentinels.Addresses) > 1 && redisCfg.Sentinels.Master != "" {
		clt.AddReadHandle(redisCfg.Sentinels.Addresses[0], newRedisFailoverClient(redisCfg, true))
	}

	// Deprecated
	if redisCfg.Replica.Address != "" {
		if redisCfg.Master.Address != redisCfg.Replica.Address {
			clt.AddReadHandle(redisCfg.Replica.Address, newRedisClient(redisCfg, redisCfg.Replica.Address))
		}
	}

	if len(redisCfg.Replica.Addresses) > 0 {
		for _, address := range redisCfg.Replica.Addresses {
			if address != redisCfg.Master.Address {
				clt.AddReadHandle(address, newRedisClient(redisCfg, address))
			}
		}
	}
}

// SetWriteHandle sets the write handle for the redisClient to the provided redis.UniversalClient instance.
func (clt *redisClient) SetWriteHandle(handle redis.UniversalClient) {
	clt.writeHandle = handle
}

// AddReadHandle adds a read handle for the specified address to the redisClient's readHandle map.
func (clt *redisClient) AddReadHandle(address string, handle redis.UniversalClient) {
	if clt.readHandle == nil {
		clt.readHandle = make(map[string]redis.UniversalClient)
	}

	clt.readHandle[address] = handle
}

// GetWriteHandle returns the Redis client's write handle, which is used for operations requiring write access.
func (clt *redisClient) GetWriteHandle() redis.UniversalClient {
	return clt.writeHandle
}

// GetReadHandle returns a read handle from the redisClient, shuffling among available read handles if multiple exist.
func (clt *redisClient) GetReadHandle() redis.UniversalClient {
	var addresses []string

	if clt.readHandle == nil {
		if clt.writeHandle != nil {
			return clt.writeHandle
		}

		return nil
	}

	for address := range clt.readHandle {
		addresses = append(addresses, address)
	}

	if len(addresses) == 1 {
		return clt.readHandle[addresses[0]]
	}

	rand.Shuffle(len(addresses), func(i, j int) {
		addresses[i], addresses[j] = addresses[j], addresses[i]
	})

	return clt.readHandle[addresses[0]]
}

// Close terminates all active connections held by the redisClient, including both write and read handles.
func (clt *redisClient) Close() {
	if clt.writeHandle != nil {
		clt.writeHandle.Close()
	}

	if clt.readHandle != nil {
		for _, handle := range clt.readHandle {
			handle.Close()
		}
	}
}

// testClient is a concrete implementation of the Client interface using a Redis UniversalClient.
type testClient struct {
	client redis.UniversalClient
}

// GetWriteHandle returns the Redis UniversalClient used for write operations.
func (tc *testClient) GetWriteHandle() redis.UniversalClient {
	return tc.client
}

// GetReadHandle retrieves the Redis UniversalClient instance for read operations.
func (tc *testClient) GetReadHandle() redis.UniversalClient {
	return tc.client
}

// Close terminates the connection managed by the testClient's Redis UniversalClient.
func (tc *testClient) Close() {
	tc.client.Close()
}

var _ Client = (*testClient)(nil)

// NewTestClient initializes and returns a new testClient instance, implementing the Client interface using the provided Redis client.
func NewTestClient(db *redis.Client) Client {
	client = &testClient{client: db}

	return client
}
