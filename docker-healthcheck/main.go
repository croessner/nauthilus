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

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const nauthilusURL = "http://127.0.0.1:9080/healthz"

type Config struct {
	URL           string
	Verbose       bool
	TLSSkipVerify bool
	Timeout       time.Duration
}

type HealthzResult struct {
	Status string `json:"status"`
}

type Client struct {
	cfg        Config
	logger     *slog.Logger
	httpClient *http.Client
}

func NewClient(cfg Config, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify},
	}

	return &Client{
		cfg:    cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
	}
}

func (c *Client) Run(ctx context.Context) error {
	if c.cfg.URL == "" {
		return fmt.Errorf("healthz url is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	var result HealthzResult
	if err := json.Unmarshal(content, &result); err != nil {
		return fmt.Errorf("decode healthz response: %w", err)
	}

	status := strings.ToLower(strings.TrimSpace(result.Status))
	if status == "" {
		return fmt.Errorf("healthz status missing")
	}

	switch status {
	case "up":
		if c.cfg.Verbose {
			c.logger.Info("Healthz OK", "url", c.cfg.URL, "status", status)
		}
		return nil
	case "degraded":
		c.logger.Warn("Healthz degraded", "url", c.cfg.URL, "status", status)
		return nil
	case "down":
		return fmt.Errorf("healthz reported down")
	default:
		return fmt.Errorf("unknown healthz status: %s", status)
	}
}

func main() {
	pflag.StringP("url", "u", nauthilusURL, "nauthilus url to test")
	pflag.BoolP("verbose", "v", false, "Be verbose")
	pflag.BoolP("tls-skip-verify", "t", false, "Skip TLS server certificate verification")
	pflag.Parse()
	_ = viper.BindPFlags(pflag.CommandLine)

	cfg := Config{
		URL:           viper.GetString("url"),
		Verbose:       viper.GetBool("verbose"),
		TLSSkipVerify: viper.GetBool("tls-skip-verify"),
		Timeout:       10 * time.Second,
	}

	logLevel := slog.LevelWarn
	if cfg.Verbose {
		logLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	client := NewClient(cfg, logger)

	if cfg.Verbose {
		logger.Info("Checking healthz", "url", cfg.URL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if err := client.Run(ctx); err != nil {
		logger.Error("Healthz check failed", "url", cfg.URL, "error", err)
		os.Exit(1)
	}

	os.Exit(0)
}
