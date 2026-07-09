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

	"github.com/croessner/nauthilus/v3/contrib/plugins/internal/pluginutil"
	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	defaultBatchSize        = 100
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
	BatchSize        int           `mapstructure:"-"`
	MaxResponseBytes int64         `mapstructure:"-"`
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
	BatchSize        int    `mapstructure:"batch_size"`
	MaxResponseBytes int64  `mapstructure:"max_response_bytes"`
}

// decodeModuleConfig reads and validates the ClickHouse plugin-owned config.
func decodeModuleConfig(view pluginapi.ConfigView) (moduleConfig, error) {
	var raw rawModuleConfig
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

	cacheKey := strings.TrimSpace(raw.CacheKey)
	if cacheKey == "" {
		cacheKey = defaultCacheKey
	}

	return moduleConfig{
		Deployment:       strings.TrimSpace(raw.Deployment),
		Instance:         strings.TrimSpace(raw.Instance),
		InsertURL:        insertURL,
		User:             strings.TrimSpace(raw.User),
		Password:         raw.Password,
		CacheKey:         cacheKey,
		Timeout:          timeout,
		AuthDedupTTL:     authDedupTTL,
		BatchSize:        batchSize,
		MaxResponseBytes: maxResponseBytes,
	}, nil
}
