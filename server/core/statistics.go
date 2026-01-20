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
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

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
func getCounterValue(logger *slog.Logger, metric *prometheus.CounterVec, lvs ...string) float64 {
	dtoMetric := &dto.Metric{}

	if err := metric.WithLabelValues(lvs...).Write(dtoMetric); err != nil {
		level.Error(logger).Log(definitions.LogKeyMsg, "Unable to get counter value", definitions.LogKeyError, err)

		return 0
	}

	return dtoMetric.Counter.GetValue()
}

// LoadStatsFromRedis loads the prometheus statistics at startup from a Redis server.
func LoadStatsFromRedis(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client) {
	util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgStats, definitions.LogKeyMsg, "Load counter statistics from redis")

	stats.GetMetrics().GetLoginsCounter().Reset()

	// Prometheus redis variables
	redisLoginsCounterKey := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisMetricsCounterHashKey + "_" + strings.ToUpper(cfg.GetServer().GetInstanceName())

	counterTypes := []string{definitions.LabelSuccess, definitions.LabelFailure}

	// Use pipelining to batch Redis operations and reduce network round trips
	var cmds []redis.Cmder
	var err error

	cmds, err = rediscli.ExecuteReadPipeline(ctx, redisClient, func(pipe redis.Pipeliner) error {
		for _, counterType := range counterTypes {
			pipe.HGet(ctx, redisLoginsCounterKey, counterType)
		}
		return nil
	})

	if err != nil && !errors.Is(err, redis.Nil) {
		level.Error(logger).Log(definitions.LogKeyMsg, "Unable to load status from Redis", definitions.LogKeyError, err)

		return
	}

	if errors.Is(err, redis.Nil) {
		level.Info(logger).Log(definitions.LogKeyMsg, "No statistics on Redis server")
	}

	// Count as multiple Redis operations for metrics
	stats.GetMetrics().GetRedisReadCounter().Add(float64(len(counterTypes)))

	// Process results
	for i, cmd := range cmds {
		hgetCmd, ok := cmd.(*redis.StringCmd)
		if !ok {
			level.Error(logger).Log(
				definitions.LogKeyMsg, "Unexpected command type in pipeline result",
				definitions.LogKeyError, fmt.Errorf("unexpected command type: %T", cmd),
			)

			continue
		}

		val, err := hgetCmd.Float64()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}

			level.Error(logger).Log(definitions.LogKeyMsg, "Unexpected HGET comannd result", definitions.LogKeyError, err)

			continue
		}

		stats.GetMetrics().GetLoginsCounter().WithLabelValues(counterTypes[i]).Add(val)
	}
}

// SaveStatsToRedis saves the prometheus statistics to a Redis server.
func SaveStatsToRedis(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client) {
	if ctx == nil {
		return
	}

	if err := ctx.Err(); err != nil {
		return
	}

	util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgStats, definitions.LogKeyMsg, "Save counter statistics to redis")

	metrics := []Metric{
		{Value: getCounterValue(logger, stats.GetMetrics().GetLoginsCounter(), definitions.LabelSuccess), Label: definitions.LabelSuccess},
		{Value: getCounterValue(logger, stats.GetMetrics().GetLoginsCounter(), definitions.LabelFailure), Label: definitions.LabelFailure},
	}

	// Prometheus redis variables
	redisLoginsCounterKey := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisMetricsCounterHashKey + "_" + strings.ToUpper(cfg.GetServer().GetInstanceName())

	// Use pipelining to batch Redis operations and reduce network round trips
	_, err := rediscli.ExecuteWritePipeline(ctx, redisClient, func(pipe redis.Pipeliner) error {
		for index := range metrics {
			pipe.HSet(ctx, redisLoginsCounterKey, metrics[index].Label, metrics[index].Value)
		}
		return nil
	})

	if err != nil {
		level.Error(logger).Log(definitions.LogKeyMsg, "Execute write pipeline failed", definitions.LogKeyError, err)

		return
	}

	// Count as multiple Redis operations for metrics
	stats.GetMetrics().GetRedisWriteCounter().Add(float64(len(metrics)))
}

// UpdateRedisPoolStats updates and tracks Redis pool statistics such as hits, misses, timeouts, and connection counts.
func UpdateRedisPoolStats(cfg config.File, logger *slog.Logger, redisClient rediscli.Client) {
	previousHits := make(map[string]float64)
	previousMisses := make(map[string]float64)
	previousTimeouts := make(map[string]float64)
	ticker := time.NewTicker(time.Second * 10)

	defer ticker.Stop()

	for range ticker.C {
		redisStatsMap := map[string]*redis.PoolStats{
			"default_rw": redisClient.GetWriteHandle().PoolStats(),
		}

		if redisClient.GetWriteHandle() != redisClient.GetReadHandle() {
			redisStatsMap["default_ro"] = redisClient.GetReadHandle().PoolStats()
		}

		for _, redisStats := range redislib.GetStandaloneStats() {
			redisStatsMap[redisStats.Name+"_rw"] = redisStats.Stats
		}

		for _, redisStats := range redislib.GetSentinelStats(false) {
			redisStatsMap[redisStats.Name+"_rw"] = redisStats.Stats
		}

		for _, redisStats := range redislib.GetSentinelStats(true) {
			redisStatsMap[redisStats.Name+"_ro"] = redisStats.Stats
		}

		for _, redisStats := range redislib.GetClusterStats() {
			redisStatsMap[redisStats.Name+"_rw"] = redisStats.Stats
		}

		for poolName, redisStats := range redisStatsMap {
			currentHits := float64(redisStats.Hits)
			currentMisses := float64(redisStats.Misses)
			currentTimeouts := float64(redisStats.Timeouts)

			if previousHit, ok := previousHits[poolName]; ok {
				hitsDiff := currentHits - previousHit
				if hitsDiff >= 0 {
					stats.GetMetrics().GetRedisHits().With(prometheus.Labels{definitions.ReisPromPoolName: poolName}).Add(hitsDiff)
				}
			}

			if previousMiss, ok := previousMisses[poolName]; ok {
				missesDiff := currentMisses - previousMiss
				if missesDiff >= 0 {
					stats.GetMetrics().GetRedisMisses().With(prometheus.Labels{definitions.ReisPromPoolName: poolName}).Add(missesDiff)
				}
			}

			if previousTimeout, ok := previousTimeouts[poolName]; ok {
				timeoutsDiff := currentTimeouts - previousTimeout
				if timeoutsDiff >= 0 {
					stats.GetMetrics().GetRedisTimeouts().With(prometheus.Labels{definitions.ReisPromPoolName: poolName}).Add(timeoutsDiff)
				}
			}

			previousHits[poolName] = currentHits
			previousMisses[poolName] = currentMisses
			previousTimeouts[poolName] = currentTimeouts

			stats.GetMetrics().GetRedisTotalConns().With(prometheus.Labels{definitions.ReisPromPoolName: poolName}).Set(float64(redisStats.TotalConns))
			stats.GetMetrics().GetRedisIdleConns().With(prometheus.Labels{definitions.ReisPromPoolName: poolName}).Set(float64(redisStats.IdleConns))
			stats.GetMetrics().GetRedisStaleConns().With(prometheus.Labels{definitions.ReisPromPoolName: poolName}).Set(float64(redisStats.StaleConns))
		}
	}
}
