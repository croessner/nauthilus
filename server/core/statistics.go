package core

import (
	"context"
	"errors"
	"strings"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/redis/go-redis/v9"
)

// Metric is a prometheus metric with a value and a label.
type Metric struct {
	Value float64 `redis:"value"`
	Label string  `redis:"label"`
}

// getCounterValue returns the value for a prometheus counter.
func getCounterValue(metric *prometheus.CounterVec, lvs ...string) float64 {
	dtoMetric := &dto.Metric{}

	if err := metric.WithLabelValues(lvs...).Write(dtoMetric); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

		return 0
	}

	return dtoMetric.Counter.GetValue()
}

// LoadStatsFromRedis loads the prometheus statistics at startup from a Redis server.
func LoadStatsFromRedis() {
	var (
		redisValue float64
		err        error
	)

	util.DebugModule(global.DbgStats, global.LogKeyMsg, "Load counter statistics from redis")

	stats.LoginsCounter.Reset()

	// Prometheus redis variables
	redisLoginsCounterKey := config.LoadableConfig.Server.Redis.Prefix + global.RedisMetricsCounterHashKey + "_" + strings.ToUpper(config.LoadableConfig.Server.InstanceName)

	for _, counterType := range []string{global.LabelSuccess, global.LabelFailure} {
		if redisValue, err = backend.RedisHandleReplica.HGet(context.Background(), redisLoginsCounterKey, counterType).Float64(); err != nil {
			if errors.Is(err, redis.Nil) {
				level.Info(logging.DefaultLogger).Log(global.LogKeyMsg, "No statistics on Redis server")

				return
			}

			level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

			return
		}

		stats.LoginsCounter.WithLabelValues(counterType).Add(redisValue)
	}
}

// SaveStatsToRedis saves the prometheus statistics to a Redis server.
func SaveStatsToRedis() {
	var err error

	util.DebugModule(global.DbgStats, global.LogKeyMsg, "Save counter statistics to redis")

	metrics := []Metric{
		{Value: getCounterValue(stats.LoginsCounter, global.LabelSuccess), Label: global.LabelSuccess},
		{Value: getCounterValue(stats.LoginsCounter, global.LabelFailure), Label: global.LabelFailure},
	}

	// Prometheus redis variables
	redisLoginsCounterKey := config.LoadableConfig.Server.Redis.Prefix + global.RedisMetricsCounterHashKey + "_" + strings.ToUpper(config.LoadableConfig.Server.InstanceName)

	for index := range metrics {
		if err = backend.RedisHandle.HSet(context.Background(), redisLoginsCounterKey, metrics[index].Label, metrics[index].Value).Err(); err != nil {
			level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

			return
		}

		stats.RedisWriteCounter.Inc()
	}
}
