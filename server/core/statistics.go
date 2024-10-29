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

package core

import (
	"context"
	"errors"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
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
		level.Error(log.Logger).Log(global.LogKeyError, err)

		return 0
	}

	return dtoMetric.Counter.GetValue()
}

// LoadStatsFromRedis loads the prometheus statistics at startup from a Redis server.
func LoadStatsFromRedis(ctx context.Context) {
	var (
		redisValue float64
		err        error
	)

	util.DebugModule(global.DbgStats, global.LogKeyMsg, "Load counter statistics from redis")

	stats.LoginsCounter.Reset()

	// Prometheus redis variables
	redisLoginsCounterKey := config.LoadableConfig.Server.Redis.Prefix + global.RedisMetricsCounterHashKey + "_" + strings.ToUpper(config.LoadableConfig.Server.InstanceName)

	for _, counterType := range []string{global.LabelSuccess, global.LabelFailure} {
		if redisValue, err = rediscli.ReadHandle.HGet(ctx, redisLoginsCounterKey, counterType).Float64(); err != nil {
			if errors.Is(err, redis.Nil) {
				level.Info(log.Logger).Log(global.LogKeyMsg, "No statistics on Redis server")

				return
			}

			level.Error(log.Logger).Log(global.LogKeyError, err)

			return
		}

		stats.LoginsCounter.WithLabelValues(counterType).Add(redisValue)
	}
}

// SaveStatsToRedis saves the prometheus statistics to a Redis server.
func SaveStatsToRedis(ctx context.Context) {
	var err error

	util.DebugModule(global.DbgStats, global.LogKeyMsg, "Save counter statistics to redis")

	metrics := []Metric{
		{Value: getCounterValue(stats.LoginsCounter, global.LabelSuccess), Label: global.LabelSuccess},
		{Value: getCounterValue(stats.LoginsCounter, global.LabelFailure), Label: global.LabelFailure},
	}

	// Prometheus redis variables
	redisLoginsCounterKey := config.LoadableConfig.Server.Redis.Prefix + global.RedisMetricsCounterHashKey + "_" + strings.ToUpper(config.LoadableConfig.Server.InstanceName)

	for index := range metrics {
		if err = rediscli.WriteHandle.HSet(ctx, redisLoginsCounterKey, metrics[index].Label, metrics[index].Value).Err(); err != nil {
			level.Error(log.Logger).Log(global.LogKeyError, err)

			return
		}

		stats.RedisWriteCounter.Inc()
	}
}
