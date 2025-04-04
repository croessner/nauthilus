package redislib

import (
	"fmt"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// failoverPool represents a Redis connection pool configuration for a failover setup, with an optional read-only flag.
type failoverPool struct {
	// name is a string that uniquely identifies the Redis connection pool.
	name string

	// readOnly indicates whether the Redis connection pool is in read-only mode.
	readOnly bool
}

var (
	// redisPools stores a map of Redis clients indexed by unique connection names for standalone Redis configurations.
	redisPools = make(map[string]*redis.Client)

	// redisClusterPools stores a map of Redis Cluster clients indexed by unique connection names for cluster configurations.
	redisClusterPools = make(map[string]*redis.ClusterClient)

	// redisFailoverPools holds a map of Redis clients configured for sentinel or sentinel_replica failover setups.
	redisFailoverPools = make(map[failoverPool]*redis.Client)
)

// PoolStats represents the statistics of a Redis pool with a unique name identifier.
type PoolStats struct {
	// Name represents the unique identifier for the Redis pool.
	Name string

	// Stats holds the statistical data of the Redis pool.
	Stats *redis.PoolStats
}

// ConfigValues holds the configuration parameters for a Redis client.
type ConfigValues struct {
	// Address refers to the address of the Redis server.
	Address string

	// Addresses holds a list of Redis server addresses, typically used for Sentinel and Cluster configurations.
	Addresses []string

	// MasterName specifies the name of the Redis master for Sentinel-based Redis failover setups.
	MasterName string

	// SentinelUsername specifies the username used to authenticate with Redis Sentinel servers.
	SentinelUsername string

	// SentinelPassword specifies the password used for authenticating with Redis Sentinel servers.
	SentinelPassword string

	// Username specifies the username required for authenticating with the Redis server.
	Username string

	// Password defines the secret key required to authenticate with the Redis server.
	Password string

	// DB specifies the Redis database ID to connect to, typically used for logical separation within a single Redis server.
	DB int

	// PoolSize defines the maximum number of socket connections that can be open simultaneously.
	PoolSize int

	// MinIdleConns specifies the minimum number of idle connections to maintain in the pool.
	MinIdleConns int

	// RedisTLS represents the TLS configuration required to enable and manage TLS connections for Redis.
	RedisTLS *config.TLS
}

// GetStandaloneStats collects and returns statistics for all standalone Redis pools configured in the application.
func GetStandaloneStats() []PoolStats {
	var poolStats []PoolStats

	for name, client := range redisPools {
		poolStats = append(poolStats, PoolStats{name, client.PoolStats()})
	}

	return poolStats
}

// GetSentinelStats returns a slice of PoolStats for all Redis failover pools that match the provided readOnly status.
func GetSentinelStats(readOnly bool) []PoolStats {
	var poolStats []PoolStats

	for foP, client := range redisFailoverPools {
		if foP.readOnly == readOnly {
			poolStats = append(poolStats, PoolStats{foP.name, client.PoolStats()})
		}
	}

	return poolStats
}

// GetClusterStats returns a slice of PoolStats containing statistics for each Redis Cluster pool.
func GetClusterStats() []PoolStats {
	var poolStats []PoolStats

	for name, client := range redisClusterPools {
		poolStats = append(poolStats, PoolStats{name, client.PoolStats()})
	}

	return poolStats
}

// getConfigValues retrieves configuration values from the provided Lua table and returns a ConfigValues struct.
func getConfigValues(conf *lua.LTable) *ConfigValues {
	configValues := &ConfigValues{}

	configValues.Address = getStringValue(conf, "address")
	configValues.MasterName = getStringValue(conf, "master_name")
	configValues.SentinelUsername = getStringValue(conf, "sentinel_username")
	configValues.SentinelPassword = getStringValue(conf, "sentinel_password")
	configValues.Username = getStringValue(conf, "username")
	configValues.Password = getStringValue(conf, "password")

	configValues.DB = getIntValue(conf, "db")
	configValues.PoolSize = getIntValue(conf, "pool_size")
	configValues.MinIdleConns = getIntValue(conf, "min_idle_conns")

	addresses := conf.RawGetString("addresses")
	if addressesTable, ok := addresses.(*lua.LTable); ok {
		configValues.Addresses = getLuaTableAsStringSlice(addressesTable)
	}

	tlsEnabled := conf.RawGetString("tls_enabled")
	if tlsEnabledVal, ok := tlsEnabled.(lua.LBool); ok {
		configValues.RedisTLS = &config.TLS{
			Enabled: bool(tlsEnabledVal),
			Cert:    getStringValue(conf, "tls_cert_file"),
			Key:     getStringValue(conf, "tls_key_file"),
		}
	}

	return configValues
}

// getStringValue retrieves a string value associated with the given key from a Lua table.
// Returns an empty string if the key does not exist or the value is not a string.
func getStringValue(conf *lua.LTable, key string) string {
	value := conf.RawGetString(key)
	if str, ok := value.(lua.LString); ok {
		return str.String()
	}

	return ""
}

// getIntValue retrieves the integer value associated with the given key from a Lua table.
// If the key is not found or the value is not a number, it returns 0.
func getIntValue(conf *lua.LTable, key string) int {
	value := conf.RawGetString(key)
	if num, ok := value.(lua.LNumber); ok {
		return int(num)
	}

	return 0
}

// getLuaTableAsStringSlice extracts string values from a Lua table and returns them as a slice of strings.
func getLuaTableAsStringSlice(luaValue lua.LValue) []string {
	var result []string

	if tbl, okay := luaValue.(*lua.LTable); okay {
		tbl.ForEach(func(_, value lua.LValue) {
			result = append(result, value.String())
		})
	}

	return result
}

// newRedisClient creates a new Redis client based on the provided configuration values.
func newRedisClient(conf *ConfigValues) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:         conf.Address,
		Username:     conf.Username,
		Password:     conf.Password,
		DB:           conf.DB,
		PoolSize:     conf.PoolSize,
		MinIdleConns: conf.MinIdleConns,
		TLSConfig:    rediscli.RedisTLSOptions(conf.RedisTLS),
	})
}

// newRedisFailoverClient creates a new Redis failover client using the provided configuration and read replica flag.
func newRedisFailoverClient(conf *ConfigValues, readReplica bool) *redis.Client {
	return redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:       conf.MasterName,
		SentinelAddrs:    conf.Addresses,
		SentinelUsername: conf.SentinelUsername,
		SentinelPassword: conf.SentinelPassword,
		Username:         conf.Username,
		Password:         conf.Password,
		DB:               conf.DB,
		PoolSize:         conf.PoolSize,
		MinIdleConns:     conf.MinIdleConns,
		TLSConfig:        rediscli.RedisTLSOptions(conf.RedisTLS),
		ReplicaOnly:      readReplica,
	})
}

// newRedisClusterClient creates a new Redis Cluster client using the provided configuration values.
func newRedisClusterClient(conf *ConfigValues) *redis.ClusterClient {
	return redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:        conf.Addresses,
		Username:     conf.Username,
		Password:     conf.Password,
		PoolSize:     conf.PoolSize,
		MinIdleConns: conf.MinIdleConns,
		TLSConfig:    rediscli.RedisTLSOptions(conf.RedisTLS),
	})
}

// RegisterRedisPool registers a Redis connection pool based on the provided mode (`standalone`, `sentinel`, `sentinel_replica`, `cluster`).
func RegisterRedisPool(L *lua.LState) int {
	name := L.CheckString(1)
	mode := L.CheckString(2)
	conf := getConfigValues(L.CheckTable(3))

	errMsg := lua.LString(fmt.Sprintf("A redis connection with name '%s' already exists", name))

	switch mode {
	case "standalone":
		if _, okay := redisPools[name]; okay {
			L.Push(errMsg)
			L.Push(lua.LNil)
		}

		redisPools[name] = newRedisClient(conf)
	case "sentinel", "sentinel_replica":
		if _, okay := redisFailoverPools[failoverPool{name: name}]; okay {
			L.Push(errMsg)
			L.Push(lua.LNil)
		}

		readOnly := false
		if mode == "sentinel_replica" {
			readOnly = true
		}

		redisFailoverPools[failoverPool{name: name, readOnly: readOnly}] = newRedisFailoverClient(conf, readOnly)
	case "cluster":
		if _, okay := redisClusterPools[name]; okay {
			L.Push(errMsg)
			L.Push(lua.LNil)
		}

		redisClusterPools[name] = newRedisClusterClient(conf)
	default:
		L.Push(lua.LString(fmt.Sprintf("Unknown mode: %s", mode)))
		L.Push(lua.LNil)

		return 2
	}

	L.Push(lua.LString("OK"))

	return 1
}

// GetRedisConnection retrieves a Redis connection by name. Searches through standalone, failover, and cluster pools.
// If found, it returns the connection as a Lua userdata object. If not found, it returns nil and an error message.
func GetRedisConnection(L *lua.LState) int {
	var (
		okay   bool
		client redis.UniversalClient
	)

	name := L.CheckString(1)

	if client, okay = redisPools[name]; !okay {
		if client, okay = redisFailoverPools[failoverPool{name: name}]; !okay {
			if client, okay = redisClusterPools[name]; !okay {
				L.Push(lua.LNil)
				L.Push(lua.LString(fmt.Sprintf("No known redis configurtion found with name '%s'", name)))

				return 2
			}
		}
	}

	ud := L.NewUserData()
	ud.Value = client

	L.SetMetatable(ud, L.GetTypeMetatable("redis_client"))
	L.Push(ud)

	return 1
}

// getRedisConnectionWithFallback returns a Redis client from Lua state or a fallback client if the Lua state contains "default".
func getRedisConnectionWithFallback(L *lua.LState, fallbackClient redis.UniversalClient) redis.UniversalClient {
	ud := L.Get(1)
	if ud == lua.LString("default") {
		return fallbackClient
	}

	client, okay := ud.(*lua.LUserData).Value.(redis.UniversalClient)
	if !okay {
		return fallbackClient
	}

	return client
}
