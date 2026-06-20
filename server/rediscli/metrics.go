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
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
)

const redisMetricLabelInstance = "instance"

type redisInfoGaugeMetric struct {
	infoKey string
	gauge   *prometheus.GaugeVec
}

var (
	// Redis server metrics
	redisConnectedClients = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_connected_clients",
			Help: "Number of client connections (excluding connections from replicas)",
		}, []string{redisMetricLabelInstance},
	)

	redisUsedMemory = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_used_memory_bytes",
			Help: "Total number of bytes allocated by Redis using its allocator",
		}, []string{redisMetricLabelInstance},
	)

	redisUsedMemoryRss = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_used_memory_rss_bytes",
			Help: "Number of bytes that Redis allocated as seen by the operating system",
		}, []string{redisMetricLabelInstance},
	)

	redisMemFragmentationRatio = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_mem_fragmentation_ratio",
			Help: "Ratio between used_memory_rss and used_memory",
		}, []string{redisMetricLabelInstance},
	)

	redisCommandsProcessed = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_commands_processed_total",
			Help: "Total number of commands processed by the server",
		}, []string{redisMetricLabelInstance},
	)

	redisKeyspaceHits = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_keyspace_hits_total",
			Help: "Number of successful lookup of keys in the main dictionary",
		}, []string{redisMetricLabelInstance},
	)

	redisKeyspaceMisses = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_keyspace_misses_total",
			Help: "Number of failed lookup of keys in the main dictionary",
		}, []string{redisMetricLabelInstance},
	)

	redisKeyspaceHitRate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_keyspace_hit_rate",
			Help: "Ratio of keyspace hits to total keyspace hits and misses",
		}, []string{redisMetricLabelInstance},
	)

	redisEvictedKeys = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_evicted_keys_total",
			Help: "Number of evicted keys due to maxmemory limit",
		}, []string{redisMetricLabelInstance},
	)

	redisExpiredKeys = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_expired_keys_total",
			Help: "Number of key expiration events",
		}, []string{redisMetricLabelInstance},
	)

	redisRejectedConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_rejected_connections_total",
			Help: "Number of connections rejected because of maxclients limit",
		}, []string{redisMetricLabelInstance},
	)

	redisInstantaneousOpsPerSec = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_instantaneous_ops_per_sec",
			Help: "Number of commands processed per second",
		}, []string{redisMetricLabelInstance},
	)

	redisInstantaneousInputKbps = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_instantaneous_input_kbps",
			Help: "The network's read rate per second in KB/sec",
		}, []string{redisMetricLabelInstance},
	)

	redisInstantaneousOutputKbps = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_instantaneous_output_kbps",
			Help: "The network's write rate per second in KB/sec",
		}, []string{redisMetricLabelInstance},
	)

	redisLatencyMs = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_latency_milliseconds",
			Help: "Redis command latency in milliseconds",
		}, []string{"instance", "command"},
	)
)

var redisInfoGaugeMetrics = []redisInfoGaugeMetric{
	{infoKey: "connected_clients", gauge: redisConnectedClients},
	{infoKey: "used_memory", gauge: redisUsedMemory},
	{infoKey: "used_memory_rss", gauge: redisUsedMemoryRss},
	{infoKey: "mem_fragmentation_ratio", gauge: redisMemFragmentationRatio},
	{infoKey: "total_commands_processed", gauge: redisCommandsProcessed},
	{infoKey: "evicted_keys", gauge: redisEvictedKeys},
	{infoKey: "expired_keys", gauge: redisExpiredKeys},
	{infoKey: "rejected_connections", gauge: redisRejectedConnections},
	{infoKey: "instantaneous_ops_per_sec", gauge: redisInstantaneousOpsPerSec},
	{infoKey: "instantaneous_input_kbps", gauge: redisInstantaneousInputKbps},
	{infoKey: "instantaneous_output_kbps", gauge: redisInstantaneousOutputKbps},
}

// UpdateRedisServerMetrics periodically collects and updates Redis server metrics
func UpdateRedisServerMetrics(ctx context.Context, cfg config.File, logger *slog.Logger) {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collectRedisServerMetrics(ctx, cfg, logger)
		}
	}
}

// collectRedisServerMetrics collects Redis server metrics using the INFO command
func collectRedisServerMetrics(ctx context.Context, cfg config.File, logger *slog.Logger) {
	client := GetClient()
	if client == nil {
		return
	}

	// Collect metrics from write handle
	writeHandle := client.GetWriteHandle()
	if writeHandle != nil {
		collectMetricsFromClient(ctx, logger, writeHandle, "write")
	}

	// Collect metrics from read handle if it's different from write handle
	readHandle := client.GetReadHandle()
	if readHandle != nil && readHandle != writeHandle {
		collectMetricsFromClient(ctx, logger, readHandle, "read")
	}

	// Collect latency metrics
	collectLatencyMetrics(ctx, cfg, logger, writeHandle, "write")
}

// collectMetricsFromClient collects metrics from a Redis client using the INFO command
func collectMetricsFromClient(ctx context.Context, logger *slog.Logger, client redis.UniversalClient, instance string) {
	// Increment Redis read counter for the INFO command
	stats.GetMetrics().GetRedisReadCounter().Inc()

	// Get Redis INFO
	infoStr, err := client.Info(ctx).Result()
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyMsg, "Failed to get Redis INFO",
			definitions.LogKeyError, err,
		)

		return
	}

	// Parse INFO response
	info := parseRedisInfo(infoStr)

	// Update metrics
	updateRedisMetrics(info, instance)
}

// parseRedisInfo parses the Redis INFO command output into a map
func parseRedisInfo(info string) map[string]string {
	result := make(map[string]string)
	lines := strings.SplitSeq(info, "\r\n")

	for line := range lines {
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split line into key and value
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		result[parts[0]] = parts[1]
	}

	return result
}

// updateRedisMetrics updates Prometheus metrics with values from Redis INFO
func updateRedisMetrics(info map[string]string, instance string) {
	updateRedisInfoGaugeMetrics(info, instance)
	updateRedisKeyspaceMetrics(info, instance)
}

// updateRedisInfoGaugeMetrics updates direct Redis INFO gauge mappings.
func updateRedisInfoGaugeMetrics(info map[string]string, instance string) {
	for _, metric := range redisInfoGaugeMetrics {
		if value, ok := info[metric.infoKey]; ok {
			metric.gauge.WithLabelValues(instance).Set(parseRedisInfoFloat(value))
		}
	}
}

// updateRedisKeyspaceMetrics updates hit, miss, and hit-rate gauges.
func updateRedisKeyspaceMetrics(info map[string]string, instance string) {
	value, ok := info["keyspace_hits"]
	if !ok {
		return
	}

	hits := parseRedisInfoFloat(value)
	redisKeyspaceHits.WithLabelValues(instance).Set(hits)

	missValue, ok := info["keyspace_misses"]
	if !ok {
		return
	}

	misses := parseRedisInfoFloat(missValue)
	redisKeyspaceMisses.WithLabelValues(instance).Set(misses)

	if total := hits + misses; total > 0 {
		redisKeyspaceHitRate.WithLabelValues(instance).Set(hits / total)
	}
}

// parseRedisInfoFloat parses Redis INFO numbers and treats malformed values as zero.
func parseRedisInfoFloat(value string) float64 {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}

	return parsed
}

// collectLatencyMetrics collects Redis command latency metrics
func collectLatencyMetrics(ctx context.Context, cfg config.File, logger *slog.Logger, client redis.UniversalClient, instance string) {
	if client == nil {
		return
	}

	// Increment Redis read counter for the LATENCY command
	stats.GetMetrics().GetRedisReadCounter().Inc()

	// Get Redis command latency
	latencyCmd := client.Do(ctx, "LATENCY", "LATEST")
	if latencyCmd.Err() != nil {
		// LATENCY command might not be available in all Redis versions
		util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgStats, definitions.LogKeyMsg, "Failed to get Redis LATENCY: %v", latencyCmd.Err())

		return
	}

	// Parse latency response
	latencyData, err := latencyCmd.Slice()
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyMsg, "Failed to parse Redis LATENCY response",
			definitions.LogKeyError, err,
		)

		return
	}

	// Process each command's latency
	for _, cmdData := range latencyData {
		cmdSlice, ok := cmdData.([]any)
		if !ok || len(cmdSlice) < 4 {
			continue
		}

		// Extract command name and latency
		cmdName, ok := cmdSlice[0].(string)
		if !ok {
			continue
		}

		latency, ok := cmdSlice[2].(int64)
		if !ok {
			continue
		}

		// Update latency metric
		redisLatencyMs.WithLabelValues(instance, cmdName).Set(float64(latency))
	}
}
