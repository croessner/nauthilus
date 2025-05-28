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

package ml

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-kit/log/level"
)

var (
	// Singleton instance of DistributedBruteForceMetrics
	dbfMetrics     *DistributedBruteForceMetrics
	initDBFMetrics sync.Once
)

// DistributedBruteForceMetrics contains all Prometheus metrics related to distributed brute force detection
type DistributedBruteForceMetrics struct {
	// Global authentication metrics
	authAttempts    *prometheus.GaugeVec // Labels: window
	uniqueIPs       *prometheus.GaugeVec // Labels: window
	uniqueUsers     *prometheus.GaugeVec // Labels: window
	attemptsPerIP   *prometheus.GaugeVec // Labels: window
	attemptsPerUser *prometheus.GaugeVec // Labels: window
	ipsPerUser      *prometheus.GaugeVec // Labels: window

	// Historical metrics
	historicalAttempts        *prometheus.GaugeVec // Labels: hour
	historicalUniqueIPs       *prometheus.GaugeVec // Labels: hour
	historicalUniqueUsers     *prometheus.GaugeVec // Labels: hour
	historicalAttemptsPerIP   *prometheus.GaugeVec // Labels: hour
	historicalAttemptsPerUser *prometheus.GaugeVec // Labels: hour
	historicalIPsPerUser      *prometheus.GaugeVec // Labels: hour
}

// GetDistributedBruteForceMetrics returns the singleton instance of DistributedBruteForceMetrics
func GetDistributedBruteForceMetrics() *DistributedBruteForceMetrics {
	initDBFMetrics.Do(func() {
		if dbfMetrics == nil {
			dbfMetrics = newDistributedBruteForceMetrics()
		}
	})

	return dbfMetrics
}

// newDistributedBruteForceMetrics creates a new instance of DistributedBruteForceMetrics with all Prometheus metrics initialized
func newDistributedBruteForceMetrics() *DistributedBruteForceMetrics {
	return &DistributedBruteForceMetrics{
		// Global authentication metrics
		authAttempts: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_auth_attempts",
				Help: "Number of authentication attempts in a sliding window",
			},
			[]string{"window"},
		),
		uniqueIPs: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_unique_ips",
				Help: "Number of unique IPs in a sliding window",
			},
			[]string{"window"},
		),
		uniqueUsers: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_unique_users",
				Help: "Number of unique usernames in a sliding window",
			},
			[]string{"window"},
		),
		attemptsPerIP: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_attempts_per_ip",
				Help: "Average number of authentication attempts per IP",
			},
			[]string{"window"},
		),
		attemptsPerUser: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_attempts_per_user",
				Help: "Average number of authentication attempts per user",
			},
			[]string{"window"},
		),
		ipsPerUser: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_ips_per_user",
				Help: "Average number of unique IPs per user",
			},
			[]string{"window"},
		),

		// Historical metrics
		historicalAttempts: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_historical_attempts",
				Help: "Historical number of authentication attempts per hour",
			},
			[]string{"hour"},
		),
		historicalUniqueIPs: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_historical_unique_ips",
				Help: "Historical number of unique IPs per hour",
			},
			[]string{"hour"},
		),
		historicalUniqueUsers: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_historical_unique_users",
				Help: "Historical number of unique usernames per hour",
			},
			[]string{"hour"},
		),
		historicalAttemptsPerIP: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_historical_attempts_per_ip",
				Help: "Historical average number of authentication attempts per IP per hour",
			},
			[]string{"hour"},
		),
		historicalAttemptsPerUser: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_historical_attempts_per_user",
				Help: "Historical average number of authentication attempts per user per hour",
			},
			[]string{"hour"},
		),
		historicalIPsPerUser: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_historical_ips_per_user",
				Help: "Historical average number of unique IPs per user per hour",
			},
			[]string{"hour"},
		),
	}
}

// StartMetricsCollector starts a goroutine that periodically collects metrics from Redis
func (m *DistributedBruteForceMetrics) StartMetricsCollector(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		// Collect metrics immediately on startup
		m.collectMetrics()

		for {
			select {
			case <-ticker.C:
				m.collectMetrics()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// collectMetrics collects metrics from Redis and updates Prometheus metrics
func (m *DistributedBruteForceMetrics) collectMetrics() {
	// Get Redis connection
	redisClient := rediscli.GetClient().GetReadHandle()
	if redisClient == nil {
		level.Error(log.Logger).Log("msg", "Failed to get Redis client for metrics collection")
		return
	}

	// Collect current metrics
	m.collectCurrentMetrics(redisClient)

	// Collect historical metrics
	m.collectHistoricalMetrics(redisClient)
}

// collectCurrentMetrics collects current metrics from Redis
func (m *DistributedBruteForceMetrics) collectCurrentMetrics(redisClient redis.UniversalClient) {
	// Get current metrics for different windows
	windows := []int{60, 300, 900, 3600} // 1min, 5min, 15min, 1hour

	for _, window := range windows {
		windowStr := strconv.Itoa(window)

		// Get authentication attempts
		key := "ntc:multilayer:global:auth_attempts:" + windowStr
		attempts, err := redisClient.ZCount(context.Background(), key, "-inf", "+inf").Result()
		if err != nil {
			level.Error(log.Logger).Log("msg", "Failed to get auth attempts from Redis", "window", windowStr, "error", err)
			continue
		}

		// Get unique IPs
		ipKey := "ntc:multilayer:global:unique_ips:" + windowStr
		uniqueIPs, err := redisClient.ZCount(context.Background(), ipKey, "-inf", "+inf").Result()
		if err != nil {
			level.Error(log.Logger).Log("msg", "Failed to get unique IPs from Redis", "window", windowStr, "error", err)
			continue
		}

		// Get unique users
		userKey := "ntc:multilayer:global:unique_users:" + windowStr
		uniqueUsers, err := redisClient.ZCount(context.Background(), userKey, "-inf", "+inf").Result()
		if err != nil {
			level.Error(log.Logger).Log("msg", "Failed to get unique users from Redis", "window", windowStr, "error", err)
			continue
		}

		// Calculate derived metrics
		var attemptsPerIP, attemptsPerUser, ipsPerUser float64

		if uniqueIPs > 0 {
			attemptsPerIP = float64(attempts) / float64(uniqueIPs)
		}

		if uniqueUsers > 0 {
			attemptsPerUser = float64(attempts) / float64(uniqueUsers)
			ipsPerUser = float64(uniqueIPs) / float64(uniqueUsers)
		}

		// Update Prometheus metrics
		windowLabel := formatWindowLabel(window)
		m.authAttempts.WithLabelValues(windowLabel).Set(float64(attempts))
		m.uniqueIPs.WithLabelValues(windowLabel).Set(float64(uniqueIPs))
		m.uniqueUsers.WithLabelValues(windowLabel).Set(float64(uniqueUsers))
		m.attemptsPerIP.WithLabelValues(windowLabel).Set(attemptsPerIP)
		m.attemptsPerUser.WithLabelValues(windowLabel).Set(attemptsPerUser)
		m.ipsPerUser.WithLabelValues(windowLabel).Set(ipsPerUser)
	}
}

// collectHistoricalMetrics collects historical metrics from Redis
func (m *DistributedBruteForceMetrics) collectHistoricalMetrics(redisClient redis.UniversalClient) {
	// Get current time
	now := time.Now()

	// Collect metrics for the last 24 hours
	for i := 0; i < 24; i++ {
		hourTime := now.Add(time.Duration(-i) * time.Hour)
		hourKey := hourTime.Format("2006-01-02-15") // Format: YYYY-MM-DD-HH

		// Get historical metrics
		key := "ntc:multilayer:global:historical_metrics:" + hourKey

		// Check if key exists
		exists, err := redisClient.Exists(context.Background(), key).Result()
		if err != nil {
			level.Error(log.Logger).Log("msg", "Failed to check if historical metrics key exists", "hour", hourKey, "error", err)
			continue
		}

		if exists == 0 {
			continue
		}

		// Get all fields from the hash
		metrics, err := redisClient.HGetAll(context.Background(), key).Result()
		if err != nil {
			level.Error(log.Logger).Log("msg", "Failed to get historical metrics from Redis", "hour", hourKey, "error", err)
			continue
		}

		// Parse metrics
		attempts, _ := strconv.ParseFloat(metrics["attempts"], 64)
		uniqueIPs, _ := strconv.ParseFloat(metrics["unique_ips"], 64)
		uniqueUsers, _ := strconv.ParseFloat(metrics["unique_users"], 64)
		attemptsPerIP, _ := strconv.ParseFloat(metrics["attempts_per_ip"], 64)
		attemptsPerUser, _ := strconv.ParseFloat(metrics["attempts_per_user"], 64)
		ipsPerUser, _ := strconv.ParseFloat(metrics["ips_per_user"], 64)

		// Update Prometheus metrics
		hourLabel := hourTime.Format("2006-01-02 15:04")
		m.historicalAttempts.WithLabelValues(hourLabel).Set(attempts)
		m.historicalUniqueIPs.WithLabelValues(hourLabel).Set(uniqueIPs)
		m.historicalUniqueUsers.WithLabelValues(hourLabel).Set(uniqueUsers)
		m.historicalAttemptsPerIP.WithLabelValues(hourLabel).Set(attemptsPerIP)
		m.historicalAttemptsPerUser.WithLabelValues(hourLabel).Set(attemptsPerUser)
		m.historicalIPsPerUser.WithLabelValues(hourLabel).Set(ipsPerUser)
	}
}

// formatWindowLabel formats a window size in seconds to a human-readable string
func formatWindowLabel(window int) string {
	switch window {
	case 60:
		return "1m"
	case 300:
		return "5m"
	case 900:
		return "15m"
	case 3600:
		return "1h"
	default:
		return strconv.Itoa(window) + "s"
	}
}

// InitDistributedBruteForceMetrics initializes the distributed brute force metrics collector
func InitDistributedBruteForceMetrics() {
	// Check if experimental ML is enabled
	if !config.GetEnvironment().GetExperimentalML() {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Distributed brute force metrics initialization skipped: experimental_ml is not enabled",
		)
		return
	}

	metrics := GetDistributedBruteForceMetrics()
	metrics.StartMetricsCollector(context.Background())

	level.Info(log.Logger).Log(definitions.LogKeyMsg, "Distributed brute force metrics collector initialized")
}
