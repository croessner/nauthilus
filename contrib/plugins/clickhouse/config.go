// Copyright (C) 2026 Christian Roessner
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

// Package main provides the bundled ClickHouse native post-action plugin.
package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/pluginutil"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	defaultBatchSize        = 100
	defaultMaxBufferRows    = 10000
	defaultCacheKey         = "clickhouse:batch:logins"
	defaultTimeout          = 10 * time.Second
	defaultMaxResponseBytes = int64(8192)
	defaultAuthDedupTTL     = 300 * time.Second
)

type moduleConfig struct {
	Deployment       string        `mapstructure:"-"`
	Instance         string        `mapstructure:"-"`
	InsertURL        string        `mapstructure:"-"`
	User             string        `mapstructure:"-"`
	Password         string        `mapstructure:"-"`
	CacheKey         string        `mapstructure:"-"`
	Timeout          time.Duration `mapstructure:"-"`
	AuthDedupTTL     time.Duration `mapstructure:"-"`
	FlushInterval    time.Duration `mapstructure:"-"`
	BatchSize        int           `mapstructure:"-"`
	MaxBufferRows    int           `mapstructure:"-"`
	MaxResponseBytes int64         `mapstructure:"-"`
	DedupSuccess     bool          `mapstructure:"-"`
	DedupFailure     bool          `mapstructure:"-"`
}

type rawModuleConfig struct {
	Deployment       string `mapstructure:"deployment"`
	Instance         string `mapstructure:"instance"`
	InsertURL        string `mapstructure:"insert_url"`
	User             string `mapstructure:"user"`
	Password         string `mapstructure:"password"`
	CacheKey         string `mapstructure:"cache_key"`
	Timeout          string `mapstructure:"timeout"`
	AuthDedupTTL     string `mapstructure:"auth_dedup_ttl"`
	FlushInterval    string `mapstructure:"flush_interval"`
	BatchSize        int    `mapstructure:"batch_size"`
	MaxBufferRows    int    `mapstructure:"max_buffer_rows"`
	MaxResponseBytes int64  `mapstructure:"max_response_bytes"`
	DedupSuccess     bool   `mapstructure:"dedup_success"`
	DedupFailure     bool   `mapstructure:"dedup_failure"`
}

// decodeModuleConfig reads and validates the ClickHouse plugin-owned config.
func decodeModuleConfig(view pluginapi.ConfigView) (moduleConfig, error) {
	raw := rawModuleConfig{DedupSuccess: true}
	if view != nil && !view.IsZero() {
		if err := view.Decode(&raw); err != nil {
			return moduleConfig{}, fmt.Errorf("decode clickhouse config: %w", err)
		}
	}

	insertURL, err := pluginutil.ValidateOptionalHTTPURL("insert_url", raw.InsertURL)
	if err != nil {
		return moduleConfig{}, err
	}

	batchSize, err := pluginutil.ParsePositiveDefaultedInt("batch_size", raw.BatchSize, defaultBatchSize)
	if err != nil {
		return moduleConfig{}, err
	}

	maxBufferRows, err := pluginutil.ParsePositiveDefaultedInt("max_buffer_rows", raw.MaxBufferRows, defaultMaxBufferRows)
	if err != nil {
		return moduleConfig{}, err
	}

	maxResponseBytes, err := pluginutil.ParsePositiveDefaultedInt64("max_response_bytes", raw.MaxResponseBytes, defaultMaxResponseBytes)
	if err != nil {
		return moduleConfig{}, err
	}

	timeout, err := pluginutil.ParsePositiveDefaultedDuration("timeout", raw.Timeout, defaultTimeout)
	if err != nil {
		return moduleConfig{}, err
	}

	authDedupTTL, err := pluginutil.ParsePositiveDefaultedDuration("auth_dedup_ttl", raw.AuthDedupTTL, defaultAuthDedupTTL)
	if err != nil {
		return moduleConfig{}, err
	}

	// Zero keeps size-only batching; a positive interval enables the periodic flush worker.
	flushInterval, err := pluginutil.ParseDefaultedDuration("flush_interval", raw.FlushInterval, 0)
	if err != nil {
		return moduleConfig{}, err
	}

	cacheKey := strings.TrimSpace(raw.CacheKey)
	if cacheKey == "" {
		cacheKey = defaultCacheKey
	}

	return moduleConfig{
		MaxBufferRows:    maxBufferRows,
		DedupSuccess:     raw.DedupSuccess,
		DedupFailure:     raw.DedupFailure,
		Deployment:       strings.TrimSpace(raw.Deployment),
		Instance:         strings.TrimSpace(raw.Instance),
		InsertURL:        insertURL,
		User:             strings.TrimSpace(raw.User),
		Password:         raw.Password,
		CacheKey:         cacheKey,
		Timeout:          timeout,
		AuthDedupTTL:     authDedupTTL,
		FlushInterval:    flushInterval,
		BatchSize:        batchSize,
		MaxResponseBytes: maxResponseBytes,
	}, nil
}
