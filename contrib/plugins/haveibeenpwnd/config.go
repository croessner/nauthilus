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

// Package main provides the bundled Have I Been Pwned native post-action plugin.
package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/contrib/plugins/internal/pluginutil"
	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	defaultRedisPool            = "default"
	defaultAPIBaseURL           = "https://api.pwnedpasswords.com/range/"
	defaultHTTPTimeout          = 10 * time.Second
	defaultHTTPMaxResponseBytes = int64(1 << 20)
	defaultCachePositiveTTL     = time.Hour
	defaultCacheNegativeTTL     = 10 * time.Minute
	defaultRedisPositiveTTL     = time.Hour
	defaultRedisNegativeTTL     = 24 * time.Hour
	defaultGateTTL              = 5 * time.Minute
	defaultMailServer           = "localhost"
	defaultMailPort             = 25
	defaultMailHeloName         = "localhost"
	defaultMailFrom             = "postmaster@localhost"
)

var errMailNotificationUnsupported = errors.New("haveibeenpwnd native mail notification is not implemented")

type moduleConfig struct {
	Mail                 mailConfig
	APIBaseURL           string
	RedisPool            string
	HTTPTimeout          time.Duration
	CachePositiveTTL     time.Duration
	CacheNegativeTTL     time.Duration
	RedisPositiveTTL     time.Duration
	RedisNegativeTTL     time.Duration
	GateTTL              time.Duration
	HTTPMaxResponseBytes int64
}

type mailConfig struct {
	Server   string
	HeloName string
	Username string
	Password string
	MailFrom string
	Website  string
	Port     int
	Enabled  bool
	UseLMTP  bool
	TLS      bool
	StartTLS bool
}

type rawModuleConfig struct {
	Mail                 rawMailConfig `mapstructure:"mail"`
	RedisPool            string        `mapstructure:"redis_pool"`
	APIBaseURL           string        `mapstructure:"api_base_url"`
	HTTPTimeout          string        `mapstructure:"http_timeout"`
	CachePositiveTTL     string        `mapstructure:"cache_positive_ttl"`
	CacheNegativeTTL     string        `mapstructure:"cache_negative_ttl"`
	RedisPositiveTTL     string        `mapstructure:"redis_positive_ttl"`
	RedisNegativeTTL     string        `mapstructure:"redis_negative_ttl"`
	GateTTL              string        `mapstructure:"gate_ttl"`
	HTTPMaxResponseBytes int64         `mapstructure:"http_max_response_bytes"`
}

type rawMailConfig struct {
	Server   string `mapstructure:"server"`
	HeloName string `mapstructure:"helo_name"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	MailFrom string `mapstructure:"mail_from"`
	Website  string `mapstructure:"website"`
	Port     int    `mapstructure:"port"`
	Enabled  bool   `mapstructure:"enabled"`
	UseLMTP  bool   `mapstructure:"use_lmtp"`
	TLS      bool   `mapstructure:"tls"`
	StartTLS bool   `mapstructure:"starttls"`
}

// decodeModuleConfig reads and validates the HIBP plugin-owned config.
//
//nolint:gocyclo,funlen // Config decoding stays linear so each field keeps its exact validation error.
func decodeModuleConfig(view pluginapi.ConfigView) (moduleConfig, error) {
	var raw rawModuleConfig
	if view != nil && !view.IsZero() {
		if err := view.Decode(&raw); err != nil {
			return moduleConfig{}, fmt.Errorf("decode haveibeenpwnd config: %w", err)
		}
	}

	apiBaseURL, err := normalizeAPIBaseURL(raw.APIBaseURL)
	if err != nil {
		return moduleConfig{}, err
	}

	httpMaxResponseBytes, err := pluginutil.ParsePositiveDefaultedInt64(
		"http_max_response_bytes",
		raw.HTTPMaxResponseBytes,
		defaultHTTPMaxResponseBytes,
	)
	if err != nil {
		return moduleConfig{}, err
	}

	httpTimeout, err := pluginutil.ParsePositiveDefaultedDuration("http_timeout", raw.HTTPTimeout, defaultHTTPTimeout)
	if err != nil {
		return moduleConfig{}, err
	}

	cachePositiveTTL, err := pluginutil.ParsePositiveDefaultedDuration("cache_positive_ttl", raw.CachePositiveTTL, defaultCachePositiveTTL)
	if err != nil {
		return moduleConfig{}, err
	}

	cacheNegativeTTL, err := pluginutil.ParsePositiveDefaultedDuration("cache_negative_ttl", raw.CacheNegativeTTL, defaultCacheNegativeTTL)
	if err != nil {
		return moduleConfig{}, err
	}

	redisPositiveTTL, err := pluginutil.ParsePositiveDefaultedDuration("redis_positive_ttl", raw.RedisPositiveTTL, defaultRedisPositiveTTL)
	if err != nil {
		return moduleConfig{}, err
	}

	redisNegativeTTL, err := pluginutil.ParsePositiveDefaultedDuration("redis_negative_ttl", raw.RedisNegativeTTL, defaultRedisNegativeTTL)
	if err != nil {
		return moduleConfig{}, err
	}

	gateTTL, err := pluginutil.ParsePositiveDefaultedDuration("gate_ttl", raw.GateTTL, defaultGateTTL)
	if err != nil {
		return moduleConfig{}, err
	}

	mail, err := decodeMailConfig(raw.Mail)
	if err != nil {
		return moduleConfig{}, err
	}

	redisPool := strings.TrimSpace(raw.RedisPool)
	if redisPool == "" {
		redisPool = defaultRedisPool
	}

	return moduleConfig{
		Mail:                 mail,
		RedisPool:            redisPool,
		APIBaseURL:           apiBaseURL,
		HTTPTimeout:          httpTimeout,
		HTTPMaxResponseBytes: httpMaxResponseBytes,
		CachePositiveTTL:     cachePositiveTTL,
		CacheNegativeTTL:     cacheNegativeTTL,
		RedisPositiveTTL:     redisPositiveTTL,
		RedisNegativeTTL:     redisNegativeTTL,
		GateTTL:              gateTTL,
	}, nil
}

// normalizeAPIBaseURL validates and canonicalizes the range API base URL.
func normalizeAPIBaseURL(value string) (string, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		text = defaultAPIBaseURL
	}

	validated, err := pluginutil.ValidateOptionalHTTPURL("api_base_url", text)
	if err != nil {
		return "", err
	}

	return strings.TrimRight(validated, "/") + "/", nil
}

// decodeMailConfig validates mail settings and rejects enabled mail until parity is implemented.
func decodeMailConfig(raw rawMailConfig) (mailConfig, error) {
	port := raw.Port
	if port == 0 {
		port = defaultMailPort
	}

	if port <= 0 || port > 65535 {
		return mailConfig{}, fmt.Errorf("mail.port must be a valid TCP port")
	}

	server := strings.TrimSpace(raw.Server)
	if server == "" {
		server = defaultMailServer
	}

	heloName := strings.TrimSpace(raw.HeloName)
	if heloName == "" {
		heloName = defaultMailHeloName
	}

	mailFrom := strings.TrimSpace(raw.MailFrom)
	if mailFrom == "" {
		mailFrom = defaultMailFrom
	}

	if raw.Enabled {
		return mailConfig{}, errMailNotificationUnsupported
	}

	return mailConfig{
		Server:   server,
		HeloName: heloName,
		Username: strings.TrimSpace(raw.Username),
		Password: raw.Password,
		MailFrom: mailFrom,
		Website:  strings.TrimSpace(raw.Website),
		Port:     port,
		Enabled:  raw.Enabled,
		UseLMTP:  raw.UseLMTP,
		TLS:      raw.TLS,
		StartTLS: raw.StartTLS,
	}, nil
}
