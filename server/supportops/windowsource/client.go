// Copyright (C) 2026 Christian Rößner
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

// Package windowsource is the shared engine of the historical operational diagnostics sources. A source compiles a
// fixed profile of instant vector queries (Loki metric LogQL, Prometheus PromQL), and the engine runs them below one
// fixed endpoint, bounds every answer in bytes and series, and turns the per-instance counts into findings. No caller
// value reaches a query and redirects are never followed.
package windowsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/secret"
)

const (
	userAgent     = "nauthilus-operations-diagnostics"
	statusSuccess = "success"
	resultVector  = "vector"
)

var (
	// ErrTruncated reports a response above the byte or series bound.
	ErrTruncated = errors.New("instant query response truncated")

	// ErrRejected reports a non-success answer of the endpoint.
	ErrRejected = errors.New("instant query rejected")
)

// ClientConfig is the fixed endpoint, credential, and bound set of one instant query client.
type ClientConfig struct {
	// HTTP is copied; its redirects are never followed.
	HTTP *http.Client

	// Endpoint is the base URL; QueryPath is appended to its path.
	Endpoint *url.URL

	// Headers are fixed request headers, such as a Loki tenant.
	Headers map[string]string

	// TimeParam renders the evaluation time as the endpoint expects it.
	TimeParam func(time.Time) string

	BearerToken secret.Value
	Password    secret.Value
	QueryPath   string
	Username    string

	MaxResponseBytes int64
	MaxSeries        int
}

// Client runs instant vector queries against one fixed endpoint with fixed headers and credentials.
type Client struct {
	http             *http.Client
	endpoint         *url.URL
	headers          map[string]string
	timeParam        func(time.Time) string
	bearerToken      secret.Value
	password         secret.Value
	queryPath        string
	username         string
	maxResponseBytes int64
	maxSeries        int
}

// Sample is one series of an instant vector: its labels and its value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// vectorResponse is the subset of an instant query answer that is read; nothing else is decoded.
type vectorResponse struct {
	Data struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  []json.RawMessage `json:"value"`
		} `json:"result"`
	} `json:"data"`
	Status string `json:"status"`
}

// NewClient builds the client from a complete configuration. The HTTP client is copied and never follows redirects.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Endpoint == nil || cfg.QueryPath == "" || cfg.TimeParam == nil || cfg.MaxSeries <= 0 || cfg.MaxResponseBytes <= 0 {
		return nil, errors.New("instant query client is incompletely configured")
	}

	httpClient := &http.Client{}

	if cfg.HTTP != nil {
		copied := *cfg.HTTP
		httpClient = &copied
	}

	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &Client{http: httpClient, endpoint: cfg.Endpoint, headers: maps.Clone(cfg.Headers), timeParam: cfg.TimeParam,
		bearerToken: cfg.BearerToken, password: cfg.Password, queryPath: cfg.QueryPath, username: cfg.Username,
		maxResponseBytes: cfg.MaxResponseBytes, maxSeries: cfg.MaxSeries}, nil
}

// Instant runs one instant query evaluated at at. It returns the samples, a truncation flag, and an error for a
// failed or rejected request. A truncated answer keeps the first maxSeries samples in label order.
func (c *Client) Instant(ctx context.Context, query string, at time.Time) ([]Sample, bool, error) {
	request, err := c.newRequest(ctx, query, at)
	if err != nil {
		return nil, false, err
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, false, err
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, c.maxResponseBytes))

		return nil, false, fmt.Errorf("%w: HTTP %d", ErrRejected, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, false, err
	}

	if int64(len(body)) > c.maxResponseBytes {
		return nil, true, ErrTruncated
	}

	return c.decode(body)
}

// newRequest builds the GET request with the fixed headers and credentials; the query is the only variable part.
func (c *Client) newRequest(ctx context.Context, query string, at time.Time) (*http.Request, error) {
	target := *c.endpoint
	target.Path = strings.TrimRight(target.Path, "/") + c.queryPath
	target.RawQuery = url.Values{"query": {query}, "time": {c.timeParam(at)}}.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)

	for name, value := range c.headers {
		request.Header.Set(name, value)
	}

	switch {
	case !c.bearerToken.IsZero():
		c.bearerToken.WithString(func(token string) { request.Header.Set("Authorization", "Bearer "+token) })
	case c.username != "":
		c.password.WithString(func(password string) { request.SetBasicAuth(c.username, password) })
	}

	return request, nil
}

// decode reads a success vector answer and bounds the number of series.
func (c *Client) decode(body []byte) ([]Sample, bool, error) {
	var answer vectorResponse

	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, false, err
	}

	if answer.Status != statusSuccess || answer.Data.ResultType != resultVector {
		return nil, false, ErrRejected
	}

	samples := make([]Sample, 0, min(len(answer.Data.Result), c.maxSeries))

	for _, series := range answer.Data.Result {
		value, ok := sampleValue(series.Value)
		if !ok {
			return nil, false, ErrRejected
		}

		samples = append(samples, Sample{Labels: series.Metric, Value: value})
	}

	slices.SortFunc(samples, func(left, right Sample) int {
		return strings.Compare(labelsKey(left.Labels), labelsKey(right.Labels))
	})

	if len(samples) > c.maxSeries {
		return samples[:c.maxSeries], true, nil
	}

	return samples, false, nil
}

// sampleValue reads the [timestamp, "value"] pair of a vector sample.
func sampleValue(raw []json.RawMessage) (float64, bool) {
	if len(raw) != 2 {
		return 0, false
	}

	var text string
	if err := json.Unmarshal(raw[1], &text); err != nil {
		return 0, false
	}

	value, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, false
	}

	return value, true
}

// labelsKey renders labels in a stable order.
func labelsKey(labels map[string]string) string {
	var builder strings.Builder

	for _, name := range slices.Sorted(maps.Keys(labels)) {
		builder.WriteString(name)
		builder.WriteByte('=')
		builder.WriteString(labels[name])
		builder.WriteByte(';')
	}

	return builder.String()
}
