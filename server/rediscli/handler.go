package rediscli

import "github.com/redis/go-redis/v9"

var (
	// WriteHandle is a variable of type `redis.UniversalClient` that represents the system wide redis pool (writes).
	WriteHandle redis.UniversalClient //nolint:gochecknoglobals // System wide redis pool

	// ReadHandle is a variable of type `redis.UniversalClient` that represents the system wide redis pool (reads).
	ReadHandle redis.UniversalClient //nolint:gochecknoglobals // System wide redis pool
)
