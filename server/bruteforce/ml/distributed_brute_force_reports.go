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
	jsonlib "encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/jwtutil"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-kit/log/level"
)

var (
	// Singleton instance of DistributedBruteForceReports
	dbfReports     *DistributedBruteForceReports
	initDBFReports sync.Once
)

// SecurityEvent represents a security event with threat level and metrics
type SecurityEvent struct {
	Timestamp   time.Time      `json:"timestamp"`
	ThreatLevel float64        `json:"threat_level"`
	Response    string         `json:"response"`
	Metrics     map[string]any `json:"metrics"`
}

// SecurityReport represents a security report for a specific time period
type SecurityReport struct {
	StartTime      time.Time       `json:"start_time"`
	EndTime        time.Time       `json:"end_time"`
	MaxThreatLevel float64         `json:"max_threat_level"`
	AvgThreatLevel float64         `json:"avg_threat_level"`
	EventCount     int             `json:"event_count"`
	SevereEvents   int             `json:"severe_events"`
	HighEvents     int             `json:"high_events"`
	ModerateEvents int             `json:"moderate_events"`
	TopTargets     []string        `json:"top_targets,omitempty"`
	TopRegions     []string        `json:"top_regions,omitempty"`
	Events         []SecurityEvent `json:"events,omitempty"`
}

// DistributedBruteForceReports contains functionality for generating security reports
type DistributedBruteForceReports struct {
	// Prometheus metrics for reporting
	reportGenerations *prometheus.CounterVec // Labels: period
	maxThreatLevel    *prometheus.GaugeVec   // Labels: period
	avgThreatLevel    *prometheus.GaugeVec   // Labels: period
	eventCount        *prometheus.GaugeVec   // Labels: period
	severeEvents      *prometheus.GaugeVec   // Labels: period
	highEvents        *prometheus.GaugeVec   // Labels: period
	moderateEvents    *prometheus.GaugeVec   // Labels: period

	// Cache for reports
	reportCache      map[string]*SecurityReport
	reportCacheMutex sync.RWMutex
}

// GetDistributedBruteForceReports returns the singleton instance of DistributedBruteForceReports
func GetDistributedBruteForceReports() *DistributedBruteForceReports {
	initDBFReports.Do(func() {
		if dbfReports == nil {
			dbfReports = newDistributedBruteForceReports()
		}
	})

	return dbfReports
}

// newDistributedBruteForceReports creates a new instance of DistributedBruteForceReports
func newDistributedBruteForceReports() *DistributedBruteForceReports {
	return &DistributedBruteForceReports{
		// Initialize Prometheus metrics
		reportGenerations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nauthilus_dbf_report_generations",
				Help: "Number of security report generations",
			},
			[]string{"period"},
		),
		maxThreatLevel: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_max_threat_level",
				Help: "Maximum threat level observed in the reporting period",
			},
			[]string{"period"},
		),
		avgThreatLevel: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_avg_threat_level",
				Help: "Average threat level observed in the reporting period",
			},
			[]string{"period"},
		),
		eventCount: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_event_count",
				Help: "Number of security events in the reporting period",
			},
			[]string{"period"},
		),
		severeEvents: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_severe_events",
				Help: "Number of severe security events in the reporting period",
			},
			[]string{"period"},
		),
		highEvents: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_high_events",
				Help: "Number of high security events in the reporting period",
			},
			[]string{"period"},
		),
		moderateEvents: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_dbf_moderate_events",
				Help: "Number of moderate security events in the reporting period",
			},
			[]string{"period"},
		),

		// Initialize report cache
		reportCache: make(map[string]*SecurityReport),
	}
}

// StartReportGenerator starts a goroutine that periodically generates security reports
func (r *DistributedBruteForceReports) StartReportGenerator(ctx context.Context) {
	go func() {
		// Generate reports every hour
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		// Generate initial reports on startup
		r.generateReports()

		for {
			select {
			case <-ticker.C:
				r.generateReports()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// generateReports generates security reports for different time periods
func (r *DistributedBruteForceReports) generateReports() {
	// Generate reports for different time periods
	r.generateReport("daily", 24*time.Hour)
	r.generateReport("weekly", 7*24*time.Hour)
	r.generateReport("monthly", 30*24*time.Hour)
}

// generateReport generates a security report for a specific time period
func (r *DistributedBruteForceReports) generateReport(period string, duration time.Duration) {
	// Get Redis connection
	redisClient := rediscli.GetClient().GetReadHandle()
	if redisClient == nil {
		level.Error(log.Logger).Log("msg", "Failed to get Redis client for report generation")

		return
	}

	// Calculate time range
	endTime := time.Now()
	startTime := endTime.Add(-duration)

	// Collect security events from Redis
	events, err := r.collectSecurityEvents(redisClient, startTime, endTime)
	if err != nil {
		level.Error(log.Logger).Log("msg", "Failed to collect security events", "period", period, "error", err)

		return
	}

	// Generate report
	report := r.generateReportFromEvents(startTime, endTime, events)

	// Cache the report
	r.reportCacheMutex.Lock()
	r.reportCache[period] = report
	r.reportCacheMutex.Unlock()

	// Update Prometheus metrics
	r.reportGenerations.WithLabelValues(period).Inc()
	r.maxThreatLevel.WithLabelValues(period).Set(report.MaxThreatLevel)
	r.avgThreatLevel.WithLabelValues(period).Set(report.AvgThreatLevel)
	r.eventCount.WithLabelValues(period).Set(float64(report.EventCount))
	r.severeEvents.WithLabelValues(period).Set(float64(report.SevereEvents))
	r.highEvents.WithLabelValues(period).Set(float64(report.HighEvents))
	r.moderateEvents.WithLabelValues(period).Set(float64(report.ModerateEvents))

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Generated security report",
		"period", period,
		"events", report.EventCount,
		"max_threat_level", report.MaxThreatLevel,
	)
}

// collectSecurityEvents collects security events from Redis logs
func (r *DistributedBruteForceReports) collectSecurityEvents(redisClient redis.UniversalClient, startTime, endTime time.Time) ([]SecurityEvent, error) {
	var events []SecurityEvent

	// Get all keys matching the pattern for security logs
	keys, err := redisClient.Keys(context.Background(), "ntc:multilayer:security:log:*").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get security log keys: %w", err)
	}

	// Process each key
	for _, key := range keys {
		// Extract timestamp from key
		timestampStr := key[len("ntc:multilayer:security:log:"):]
		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			level.Error(log.Logger).Log("msg", "Failed to parse timestamp from key", "key", key, "error", err)

			continue
		}

		eventTime := time.Unix(timestamp, 0)

		// Skip events outside the time range
		if eventTime.Before(startTime) || eventTime.After(endTime) {
			continue
		}

		// Get event data
		eventData, err := redisClient.HGetAll(context.Background(), key).Result()
		if err != nil {
			level.Error(log.Logger).Log("msg", "Failed to get event data", "key", key, "error", err)

			continue
		}

		// Parse threat level
		threatLevel, err := strconv.ParseFloat(eventData["threat_level"], 64)
		if err != nil {
			level.Error(log.Logger).Log("msg", "Failed to parse threat level", "key", key, "error", err)

			continue
		}

		// Parse metrics
		var metrics map[string]any
		if eventData["metrics"] != "" {
			if err := jsonlib.Unmarshal([]byte(eventData["metrics"]), &metrics); err != nil {
				level.Error(log.Logger).Log("msg", "Failed to parse metrics", "key", key, "error", err)

				continue
			}
		} else {
			metrics = make(map[string]any)
		}

		// Create security event
		event := SecurityEvent{
			Timestamp:   eventTime,
			ThreatLevel: threatLevel,
			Response:    eventData["response"],
			Metrics:     metrics,
		}

		events = append(events, event)
	}

	// Sort events by timestamp
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	return events, nil
}

// generateReportFromEvents generates a security report from a list of security events
func (r *DistributedBruteForceReports) generateReportFromEvents(startTime, endTime time.Time, events []SecurityEvent) *SecurityReport {
	report := &SecurityReport{
		StartTime:  startTime,
		EndTime:    endTime,
		Events:     events,
		EventCount: len(events),
	}

	// Calculate statistics
	var totalThreatLevel float64
	maxThreatLevel := 0.0

	// Maps for tracking top targets and regions
	targetCounts := make(map[string]int)
	regionCounts := make(map[string]int)

	for _, event := range events {
		// Update threat level statistics
		totalThreatLevel += event.ThreatLevel
		if event.ThreatLevel > maxThreatLevel {
			maxThreatLevel = event.ThreatLevel
		}

		// Count events by severity
		if event.ThreatLevel >= 0.9 {
			report.SevereEvents++
		} else if event.ThreatLevel >= 0.7 {
			report.HighEvents++
		} else if event.ThreatLevel >= 0.5 {
			report.ModerateEvents++
		}

		// Track targeted accounts
		if targets, ok := event.Metrics["targeted_accounts"].([]any); ok {
			for _, target := range targets {
				if targetStr, ok := target.(string); ok {
					targetCounts[targetStr]++
				}
			}
		}

		// Track suspicious regions
		if regions, ok := event.Metrics["suspicious_regions"].([]any); ok {
			for _, region := range regions {
				if regionStr, ok := region.(string); ok {
					regionCounts[regionStr]++
				}
			}
		}
	}

	// Calculate average threat level
	if len(events) > 0 {
		report.AvgThreatLevel = totalThreatLevel / float64(len(events))
	}
	report.MaxThreatLevel = maxThreatLevel

	// Get top targets
	report.TopTargets = getTopKeys(targetCounts, 5)

	// Get top regions
	report.TopRegions = getTopKeys(regionCounts, 5)

	return report
}

// getTopKeys returns the top n keys from a map, sorted by value
func getTopKeys(counts map[string]int, n int) []string {
	// Convert map to slice of key-value pairs
	type kv struct {
		Key   string
		Value int
	}

	var pairs []kv
	for k, v := range counts {
		pairs = append(pairs, kv{k, v})
	}

	// Sort by value in descending order
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Value > pairs[j].Value
	})

	// Get top n keys
	var result []string
	for i := 0; i < len(pairs) && i < n; i++ {
		result = append(result, pairs[i].Key)
	}

	return result
}

// GetReport returns a security report for a specific time period
func (r *DistributedBruteForceReports) GetReport(period string) (*SecurityReport, error) {
	r.reportCacheMutex.RLock()
	defer r.reportCacheMutex.RUnlock()

	report, ok := r.reportCache[period]
	if !ok {
		return nil, fmt.Errorf("no report available for period: %s", period)
	}

	return report, nil
}

// RegisterHTTPHandlers registers HTTP handlers for security reports
func (r *DistributedBruteForceReports) RegisterHTTPHandlers(router *gin.Engine) {
	router.GET("/api/security/reports", func(c *gin.Context) {
		// Check if JWT auth is enabled
		if config.GetFile().GetServer().GetJWTAuth().IsEnabled() {
			// Check if user has the "security" role
			if !jwtutil.HasRole(c, "security") {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Access denied: missing required role 'security'",
				})

				return
			}
		}

		// Get period from query parameter, default to daily
		period := c.DefaultQuery("period", "daily")

		// Validate period
		if period != "daily" && period != "weekly" && period != "monthly" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid period. Must be one of: daily, weekly, monthly",
			})

			return
		}

		// Get report
		report, err := r.GetReport(period)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": err.Error(),
			})

			return
		}

		// Return report as JSON
		c.JSON(http.StatusOK, report)
	})
}

// InitDistributedBruteForceReports initializes the distributed brute force reports
func InitDistributedBruteForceReports(router *gin.Engine) {
	// Check if experimental ML is enabled
	if !config.GetEnvironment().GetExperimentalML() {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Distributed brute force reports initialization skipped: experimental_ml is not enabled",
		)

		return
	}

	reports := GetDistributedBruteForceReports()
	reports.StartReportGenerator(context.Background())

	// Register HTTP handlers if router is provided
	if router != nil {
		reports.RegisterHTTPHandlers(router)
	}

	level.Info(log.Logger).Log(definitions.LogKeyMsg, "Distributed brute force reports initialized")
}
