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

package lokisource

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
	queryPath     = "/loki/api/v1/query"
	tenantHeader  = "X-Scope-OrgID"
	userAgent     = "nauthilus-operations-diagnostics"
	statusSuccess = "success"
	resultVector  = "vector"
)

var (
	// errTruncated reports a response above the byte or series bound.
	errTruncated = errors.New("loki response truncated")

	// errRejected reports a non-success answer of Loki.
	errRejected = errors.New("loki rejected the query")
)

// queryClient runs instant metric queries against one fixed Loki endpoint with fixed tenant and credentials.
type queryClient struct {
	http             *http.Client
	endpoint         *url.URL
	bearerToken      secret.Value
	password         secret.Value
	username         string
	tenant           string
	maxResponseBytes int64
	maxSeries        int
}

// vectorSample is one series of an instant vector: its labels and its value.
type vectorSample struct {
	labels map[string]string
	value  float64
}

// lokiResponse is the subset of the Loki query response that is read; nothing else is decoded.
type lokiResponse struct {
	Data struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  []json.RawMessage `json:"value"`
		} `json:"result"`
	} `json:"data"`
	Status string `json:"status"`
}

// instant runs one instant query evaluated at at. It returns the samples, a truncation flag, and an error for a
// failed or rejected request. A truncated answer keeps the first maxSeries samples in label order.
func (c *queryClient) instant(ctx context.Context, query string, at time.Time) ([]vectorSample, bool, error) {
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

		return nil, false, fmt.Errorf("%w: HTTP %d", errRejected, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, false, err
	}

	if int64(len(body)) > c.maxResponseBytes {
		return nil, true, errTruncated
	}

	return c.decode(body)
}

// newRequest builds the GET request with the fixed tenant and credentials; the query is the only variable part.
func (c *queryClient) newRequest(ctx context.Context, query string, at time.Time) (*http.Request, error) {
	target := *c.endpoint
	target.Path = strings.TrimRight(target.Path, "/") + queryPath
	target.RawQuery = url.Values{"query": {query}, "time": {strconv.FormatInt(at.UnixNano(), 10)}}.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)

	if c.tenant != "" {
		request.Header.Set(tenantHeader, c.tenant)
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
func (c *queryClient) decode(body []byte) ([]vectorSample, bool, error) {
	var answer lokiResponse

	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, false, err
	}

	if answer.Status != statusSuccess || answer.Data.ResultType != resultVector {
		return nil, false, errRejected
	}

	samples := make([]vectorSample, 0, min(len(answer.Data.Result), c.maxSeries))

	for _, series := range answer.Data.Result {
		value, ok := sampleValue(series.Value)
		if !ok {
			return nil, false, errRejected
		}

		samples = append(samples, vectorSample{labels: series.Metric, value: value})
	}

	slices.SortFunc(samples, func(left, right vectorSample) int {
		return strings.Compare(labelsKey(left.labels), labelsKey(right.labels))
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
