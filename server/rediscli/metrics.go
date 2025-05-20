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
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
)

var (
	// Redis server metrics
	redisConnectedClients = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_connected_clients",
			Help: "Number of client connections (excluding connections from replicas)",
		}, []string{"instance"},
	)

	redisUsedMemory = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_used_memory_bytes",
			Help: "Total number of bytes allocated by Redis using its allocator",
		}, []string{"instance"},
	)

	redisUsedMemoryRss = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_used_memory_rss_bytes",
			Help: "Number of bytes that Redis allocated as seen by the operating system",
		}, []string{"instance"},
	)

	redisMemFragmentationRatio = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_mem_fragmentation_ratio",
			Help: "Ratio between used_memory_rss and used_memory",
		}, []string{"instance"},
	)

	redisCommandsProcessed = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_commands_processed_total",
			Help: "Total number of commands processed by the server",
		}, []string{"instance"},
	)

	redisKeyspaceHits = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_keyspace_hits_total",
			Help: "Number of successful lookup of keys in the main dictionary",
		}, []string{"instance"},
	)

	redisKeyspaceMisses = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_keyspace_misses_total",
			Help: "Number of failed lookup of keys in the main dictionary",
		}, []string{"instance"},
	)

	redisKeyspaceHitRate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_keyspace_hit_rate",
			Help: "Ratio of keyspace hits to total keyspace hits and misses",
		}, []string{"instance"},
	)

	redisEvictedKeys = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_evicted_keys_total",
			Help: "Number of evicted keys due to maxmemory limit",
		}, []string{"instance"},
	)

	redisExpiredKeys = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_expired_keys_total",
			Help: "Number of key expiration events",
		}, []string{"instance"},
	)

	redisRejectedConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_rejected_connections_total",
			Help: "Number of connections rejected because of maxclients limit",
		}, []string{"instance"},
	)

	redisInstantaneousOpsPerSec = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_instantaneous_ops_per_sec",
			Help: "Number of commands processed per second",
		}, []string{"instance"},
	)

	redisInstantaneousInputKbps = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_instantaneous_input_kbps",
			Help: "The network's read rate per second in KB/sec",
		}, []string{"instance"},
	)

	redisInstantaneousOutputKbps = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_instantaneous_output_kbps",
			Help: "The network's write rate per second in KB/sec",
		}, []string{"instance"},
	)

	redisLatencyMs = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_latency_milliseconds",
			Help: "Redis command latency in milliseconds",
		}, []string{"instance", "command"},
	)
)

// UpdateRedisServerMetrics periodically collects and updates Redis server metrics
func UpdateRedisServerMetrics(ctx context.Context) {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collectRedisServerMetrics(ctx)
		}
	}
}

// collectRedisServerMetrics collects Redis server metrics using the INFO command
func collectRedisServerMetrics(ctx context.Context) {
	client := GetClient()
	if client == nil {
		return
	}

	// Collect metrics from write handle
	writeHandle := client.GetWriteHandle()
	if writeHandle != nil {
		collectMetricsFromClient(ctx, writeHandle, "write")
	}

	// Collect metrics from read handle if it's different from write handle
	readHandle := client.GetReadHandle()
	if readHandle != nil && readHandle != writeHandle {
		collectMetricsFromClient(ctx, readHandle, "read")
	}

	// Collect latency metrics
	collectLatencyMetrics(ctx, writeHandle, "write")
}

// collectMetricsFromClient collects metrics from a Redis client using the INFO command
func collectMetricsFromClient(ctx context.Context, client redis.UniversalClient, instance string) {
	// Increment Redis read counter for the INFO command
	stats.GetMetrics().GetRedisReadCounter().Inc()

	// Get Redis INFO
	infoStr, err := client.Info(ctx).Result()
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, "Failed to get Redis INFO",
			"error", err,
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
	lines := strings.Split(info, "\r\n")

	for _, line := range lines {
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
	// Helper function to parse float values
	parseFloat := func(s string) float64 {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0
		}

		return v
	}

	// Update metrics
	if v, ok := info["connected_clients"]; ok {
		redisConnectedClients.WithLabelValues(instance).Set(parseFloat(v))
	}

	if v, ok := info["used_memory"]; ok {
		redisUsedMemory.WithLabelValues(instance).Set(parseFloat(v))
	}

	if v, ok := info["used_memory_rss"]; ok {
		redisUsedMemoryRss.WithLabelValues(instance).Set(parseFloat(v))
	}

	if v, ok := info["mem_fragmentation_ratio"]; ok {
		redisMemFragmentationRatio.WithLabelValues(instance).Set(parseFloat(v))
	}

	if v, ok := info["total_commands_processed"]; ok {
		redisCommandsProcessed.WithLabelValues(instance).Set(parseFloat(v))
	}

	if v, ok := info["keyspace_hits"]; ok {
		hits := parseFloat(v)
		redisKeyspaceHits.WithLabelValues(instance).Set(hits)

		// Calculate hit rate if both hits and misses are available
		if m, ok := info["keyspace_misses"]; ok {
			misses := parseFloat(m)
			redisKeyspaceMisses.WithLabelValues(instance).Set(misses)

			total := hits + misses
			if total > 0 {
				redisKeyspaceHitRate.WithLabelValues(instance).Set(hits / total)
			}
		}
	}

	if v, ok := info["evicted_keys"]; ok {
		redisEvictedKeys.WithLabelValues(instance).Set(parseFloat(v))
	}

	if v, ok := info["expired_keys"]; ok {
		redisExpiredKeys.WithLabelValues(instance).Set(parseFloat(v))
	}

	if v, ok := info["rejected_connections"]; ok {
		redisRejectedConnections.WithLabelValues(instance).Set(parseFloat(v))
	}

	if v, ok := info["instantaneous_ops_per_sec"]; ok {
		redisInstantaneousOpsPerSec.WithLabelValues(instance).Set(parseFloat(v))
	}

	if v, ok := info["instantaneous_input_kbps"]; ok {
		redisInstantaneousInputKbps.WithLabelValues(instance).Set(parseFloat(v))
	}

	if v, ok := info["instantaneous_output_kbps"]; ok {
		redisInstantaneousOutputKbps.WithLabelValues(instance).Set(parseFloat(v))
	}
}

// collectLatencyMetrics collects Redis command latency metrics
func collectLatencyMetrics(ctx context.Context, client redis.UniversalClient, instance string) {
	if client == nil {
		return
	}

	// Increment Redis read counter for the LATENCY command
	stats.GetMetrics().GetRedisReadCounter().Inc()

	// Get Redis command latency
	latencyCmd := client.Do(ctx, "LATENCY", "LATEST")
	if latencyCmd.Err() != nil {
		// LATENCY command might not be available in all Redis versions
		util.DebugModule(definitions.DbgStats, definitions.LogKeyMsg, "Failed to get Redis LATENCY: %v", latencyCmd.Err())

		return
	}

	// Parse latency response
	latencyData, err := latencyCmd.Slice()
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, "Failed to parse Redis LATENCY response",
			"error", err,
		)

		return
	}

	// Process each command's latency
	for _, cmdData := range latencyData {
		cmdSlice, ok := cmdData.([]interface{})
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
