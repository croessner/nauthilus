# Redis Cluster Support with Topology Awareness

This document describes the implementation of Redis Cluster support with topology awareness in Nauthilus.

## Overview

Redis Cluster is a distributed implementation of Redis that provides:
- Automatic data sharding across multiple Redis nodes
- High availability via replica nodes
- Automatic failover when a master node is down

Topology awareness refers to the ability of the Redis client to understand the cluster's structure and optimize operations based on this knowledge. This includes routing commands to the most appropriate node based on factors like latency or load.

## Implementation Details

The following changes have been made to implement Redis Cluster support with topology awareness:

### 1. Enhanced Configuration Options

The `Cluster` struct in `server/config/server.go` has been extended with the following options:

```
// Code snippet from server/config/server.go
type Cluster struct {
    Addresses      []string      `mapstructure:"addresses" validate:"required,dive,hostname_port"`
    Username       string        `mapstructure:"username" validate:"omitempty,excludesall= "`
    Password       string        `mapstructure:"password" validate:"omitempty,excludesall= "`
    RouteByLatency bool          `mapstructure:"route_by_latency"`
    RouteRandomly  bool          `mapstructure:"route_randomly"`
    ReadOnly       bool          `mapstructure:"read_only"`
    MaxRedirects   int           `mapstructure:"max_redirects" validate:"omitempty,gte=0"`
    ReadTimeout    time.Duration `mapstructure:"read_timeout" validate:"omitempty"`
    WriteTimeout   time.Duration `mapstructure:"write_timeout" validate:"omitempty"`
}
```

These options provide fine-grained control over how the Redis Cluster client behaves:

- **RouteByLatency**: When enabled, commands are routed to the node with the lowest latency
- **RouteRandomly**: When enabled, commands are routed randomly across nodes
- **RouteReadsToReplicas**: When enabled, read commands are directed to replica nodes (Available from v1.7.11)
- **ReadOnly**: Deprecated, use RouteReadsToReplicas instead
- **MaxRedirects**: Maximum number of redirects to follow for a single command
- **ReadTimeout**: Timeout for read operations
- **WriteTimeout**: Timeout for write operations

### 2. Improved Redis Cluster Client

The `newRedisClusterClient` function in `server/rediscli/client.go` has been updated to use these configuration options:

```
// Code snippet from server/rediscli/client.go
func newRedisClusterClient(redisCfg *config.Redis) *redis.ClusterClient {
    clusterCfg := redisCfg.GetCluster()

    options := &redis.ClusterOptions{
        Addrs:        clusterCfg.GetAddresses(),
        Username:     clusterCfg.GetUsername(),
        Password:     clusterCfg.GetPassword(),
        PoolSize:     redisCfg.GetPoolSize(),
        MinIdleConns: redisCfg.GetIdlePoolSize(),
        TLSConfig:    RedisTLSOptions(redisCfg.GetTLS()),

        // Topology awareness options
        RouteByLatency: clusterCfg.GetRouteByLatency(),
        RouteRandomly:  clusterCfg.GetRouteRandomly(),
        ReadOnly:       clusterCfg.GetRouteReadsToReplicas(), // Using new getter for better semantics
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
```

### 3. Read-Only Redis Cluster Client

A new function `newRedisClusterClientReadOnly` has been added to create a Redis Cluster client optimized for read operations:

```
// Code snippet from server/rediscli/client.go
func newRedisClusterClientReadOnly(redisCfg *config.Redis) *redis.ClusterClient {
    // Similar to newRedisClusterClient but forces ReadOnly to true
    // ...
}
```

### 4. Support for Redis Cluster Replicas

The `newRedisReplicaClient` method in `server/rediscli/handler.go` has been updated to create a read-only Redis Cluster client when cluster addresses are configured:

```
// Code snippet from server/rediscli/handler.go
func (clt *redisClient) newRedisReplicaClient() {
    redisCfg := config.GetFile().GetServer().GetRedis()

    if len(redisCfg.GetCluster().GetAddresses()) > 0 {
        // For Redis Cluster, create a read-only client for read operations
        clusterCfg := redisCfg.GetCluster()

        // Only create a separate read client if RouteReadsToReplicas is enabled in the configuration
        if clusterCfg.GetRouteReadsToReplicas() {
            // Create a virtual address to represent the cluster
            clusterAddress := "cluster:" + clusterCfg.GetAddresses()[0]

            // Create a new cluster client with ReadOnly set to true
            readOnlyClient := newRedisClusterClientReadOnly(redisCfg)

            // Add the read-only client as a read handle
            clt.AddReadHandle(clusterAddress, readOnlyClient)
        }

        return
    }

    // Existing code for non-cluster setups...
}
```

## Configuration Example

Here's an example configuration for Redis Cluster with topology awareness:

```yaml
redis:
  cluster:
    addresses:
      - "redis-node1:6379"
      - "redis-node2:6379"
      - "redis-node3:6379"
    username: "redis_user"
    password: "redis_password"
    route_by_latency: true
    route_randomly: false
    route_reads_to_replicas: true
    max_redirects: 3
    read_timeout: 200ms
    write_timeout: 500ms
```

## Benefits

This implementation provides several benefits:

1. **Improved Performance**: By routing read commands to replica nodes, the load on master nodes is reduced, improving overall performance.
2. **Better Scalability**: The system can scale horizontally by adding more Redis nodes to the cluster.
3. **Higher Availability**: With automatic failover, the system can continue to operate even if some nodes are down.
4. **Optimized Command Routing**: Commands are routed to the most appropriate node based on factors like latency or load.
5. **Fine-Grained Control**: The configuration options provide fine-grained control over how the Redis Cluster client behaves.

## Conclusion

The implementation of Redis Cluster support with topology awareness in Nauthilus provides a more robust, scalable, and performant Redis solution. By leveraging the distributed nature of Redis Cluster and optimizing command routing, the system can handle higher loads and provide better availability.
