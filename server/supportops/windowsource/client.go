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
	resultMatrix  = "matrix"

	// queryParam carries the query of instant and range requests.
	queryParam = "query"
)

var (
	// ErrTruncated reports a response above the byte or series bound.
	ErrTruncated = errors.New("query response truncated")

	// ErrRejected reports a non-success answer of the endpoint.
	ErrRejected = errors.New("query rejected")
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

	// RangePath is the range query path; without it the client runs instant queries only.
	RangePath string
	Username  string

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
	rangePath        string
	username         string
	maxResponseBytes int64
	maxSeries        int
}

// Sample is one series of an instant vector: its labels and its value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Point is one evaluation of a range series.
type Point struct {
	At    time.Time
	Value float64
}

// Series is one series of a range matrix: its labels and its points in time order.
type Series struct {
	Labels map[string]string
	Points []Point
}

// matrixResponse is the subset of a range query answer that is read; nothing else is decoded.
type matrixResponse struct {
	Data struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string   `json:"metric"`
			Values [][]json.RawMessage `json:"values"`
		} `json:"result"`
	} `json:"data"`
	Status string `json:"status"`
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
		bearerToken: cfg.BearerToken, password: cfg.Password, queryPath: cfg.QueryPath, rangePath: cfg.RangePath, username: cfg.Username,
		maxResponseBytes: cfg.MaxResponseBytes, maxSeries: cfg.MaxSeries}, nil
}

// Instant runs one instant query evaluated at at. It returns the samples, a truncation flag, and an error for a
// failed or rejected request. A truncated answer keeps the first maxSeries samples in label order.
func (c *Client) Instant(ctx context.Context, query string, at time.Time) ([]Sample, bool, error) {
	body, err := c.get(ctx, c.queryPath, url.Values{queryParam: {query}, "time": {c.timeParam(at)}})
	if err != nil {
		return nil, errors.Is(err, ErrTruncated), err
	}

	return c.decode(body)
}

// Range runs one range query with evaluations from start to end every step. It returns the series, a truncation flag,
// and an error for a failed or rejected request. A truncated answer keeps the maxSeries series with the largest sums.
func (c *Client) Range(ctx context.Context, query string, start time.Time, end time.Time, step time.Duration) ([]Series, bool, error) {
	if c.rangePath == "" || step < time.Second {
		return nil, false, ErrRejected
	}

	body, err := c.get(ctx, c.rangePath, url.Values{queryParam: {query}, "start": {c.timeParam(start)}, "end": {c.timeParam(end)},
		"step": {strconv.FormatInt(int64(step/time.Second), 10)}})
	if err != nil {
		return nil, errors.Is(err, ErrTruncated), err
	}

	return c.decodeMatrix(body)
}

// get sends one bounded GET request below path and returns the body of a 200 answer.
func (c *Client) get(ctx context.Context, path string, values url.Values) ([]byte, error) {
	request, err := c.newRequest(ctx, path, values)
	if err != nil {
		return nil, err
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, c.maxResponseBytes))

		return nil, fmt.Errorf("%w: HTTP %d", ErrRejected, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, err
	}

	if int64(len(body)) > c.maxResponseBytes {
		return nil, ErrTruncated
	}

	return body, nil
}

// newRequest builds the GET request with the fixed headers and credentials; the query values are the only variable
// part.
func (c *Client) newRequest(ctx context.Context, path string, values url.Values) (*http.Request, error) {
	target := *c.endpoint
	target.Path = strings.TrimRight(target.Path, "/") + path
	target.RawQuery = values.Encode()

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

// decodeMatrix reads a success matrix answer and keeps the maxSeries series with the largest sums.
func (c *Client) decodeMatrix(body []byte) ([]Series, bool, error) {
	var answer matrixResponse

	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, false, err
	}

	if answer.Status != statusSuccess || answer.Data.ResultType != resultMatrix {
		return nil, false, ErrRejected
	}

	type ranked struct {
		key    string
		series Series
		sum    float64
	}

	entries := make([]ranked, 0, len(answer.Data.Result))

	for _, raw := range answer.Data.Result {
		entry := ranked{key: labelsKey(raw.Metric), series: Series{Labels: raw.Metric, Points: make([]Point, 0, len(raw.Values))}}

		for _, pair := range raw.Values {
			point, ok := matrixPoint(pair)
			if !ok {
				return nil, false, ErrRejected
			}

			entry.series.Points = append(entry.series.Points, point)
			entry.sum += point.Value
		}

		entries = append(entries, entry)
	}

	slices.SortFunc(entries, func(left, right ranked) int {
		if order := cmpDescending(left.sum, right.sum); order != 0 {
			return order
		}

		return strings.Compare(left.key, right.key)
	})

	kept := min(len(entries), c.maxSeries)
	series := make([]Series, 0, kept)

	for _, entry := range entries[:kept] {
		series = append(series, entry.series)
	}

	return series, len(entries) > kept, nil
}

// cmpDescending orders larger values first.
func cmpDescending(left float64, right float64) int {
	switch {
	case left > right:
		return -1
	case left < right:
		return 1
	default:
		return 0
	}
}

// matrixPoint reads the [timestamp, "value"] pair of a matrix point; the timestamp is in seconds.
func matrixPoint(raw []json.RawMessage) (Point, bool) {
	value, ok := sampleValue(raw)
	if !ok {
		return Point{}, false
	}

	var seconds float64
	if err := json.Unmarshal(raw[0], &seconds); err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 {
		return Point{}, false
	}

	whole, fraction := math.Modf(seconds)

	return Point{At: time.Unix(int64(whole), int64(math.Round(fraction*1e9))).UTC(), Value: value}, true
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
