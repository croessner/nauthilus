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

// Package lokisource is the optional historical source of the operational diagnostics. It runs only the compiled
// nauthilus_diagnostics profile: metric LogQL queries that count lines with fixed message literals per instance,
// below a selector and tenant fixed in the configuration. No caller value reaches a query, no log line leaves Loki,
// redirects are never followed, and every answer is bounded in bytes and series.
package lokisource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/supportops"
)

const (
	// maxParallelQueries bounds the concurrent requests one diagnostics call sends to Loki.
	maxParallelQueries = 4

	instanceDigestPrefix = "sha256:"

	// messageField is the slog message key of every Nauthilus log line (definitions.LogKeyMsg).
	messageField = "msg"
)

// safeInstancePattern lets plain instance names through; anything else is replaced by a digest.
var safeInstancePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// Config is the fixed connection and query boundary of one Loki source.
type Config struct {
	Selector         map[string]string
	HTTPClient       *http.Client
	BaseURL          *url.URL
	BearerToken      secret.Value
	Password         secret.Value
	Username         string
	Tenant           string
	InstanceLabel    string
	Timeout          time.Duration
	MaxTimeWindow    time.Duration
	MaxSeries        int
	MaxResponseBytes int64
}

// Source is the Loki diagnostics source.
type Source struct {
	client        *queryClient
	selector      string
	instanceLabel string
	timeout       time.Duration
	maxTimeWindow time.Duration
}

// New validates the boundary and builds the source. The HTTP client never follows redirects.
func New(cfg Config) (*Source, error) {
	if cfg.BaseURL == nil || cfg.InstanceLabel == "" || len(cfg.Selector) == 0 || cfg.MaxSeries <= 0 ||
		cfg.MaxResponseBytes <= 0 || cfg.Timeout <= 0 || cfg.MaxTimeWindow <= 0 {
		return nil, errors.New("loki diagnostics source is incompletely configured")
	}

	client := &http.Client{}

	if cfg.HTTPClient != nil {
		copied := *cfg.HTTPClient
		client = &copied
	}

	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &Source{
		client: &queryClient{http: client, endpoint: cfg.BaseURL, bearerToken: cfg.BearerToken, password: cfg.Password,
			username: cfg.Username, tenant: cfg.Tenant, maxResponseBytes: cfg.MaxResponseBytes, maxSeries: cfg.MaxSeries},
		selector: streamSelector(cfg.Selector), instanceLabel: cfg.InstanceLabel, timeout: cfg.Timeout,
		maxTimeWindow: cfg.MaxTimeWindow,
	}, nil
}

// Name returns the source name.
func (s *Source) Name() string {
	return supportops.SourceLoki
}

// Kind returns the source kind.
func (s *Source) Kind() supportops.SourceKind {
	return supportops.SourceKindHistorical
}

// streamSelector renders the fixed selector with quoted values in label order.
func streamSelector(selector map[string]string) string {
	names := make([]string, 0, len(selector))
	for name := range selector {
		names = append(names, name)
	}

	slices.Sort(names)

	matchers := make([]string, 0, len(names))
	for _, name := range names {
		matchers = append(matchers, name+"="+strconv.Quote(selector[name]))
	}

	return "{" + strings.Join(matchers, ",") + "}"
}

// countQuery returns the metric query counting matching lines per instance over rangeSeconds. A profile literal
// is matched only as the value of the log message field, never anywhere in the line.
func (s *Source) countQuery(literal string, rangeSeconds int64) string {
	filter := ""
	if literal != "" {
		filter = " |~ " + strconv.Quote(messagePattern(literal))
	}

	return fmt.Sprintf("sum by (%s) (count_over_time(%s%s [%ds]))", s.instanceLabel, s.selector, filter, rangeSeconds)
}

// messagePattern returns the RE2 line filter that matches literal as the complete msg field of a slog JSON line
// ("msg":"...") or a slog text line (msg="..."). Both encoders escape quotes inside values, so a client-supplied
// value such as a typed username can never form the anchored field, and a substring elsewhere in the line does not
// match.
func messagePattern(literal string) string {
	quoted := regexp.QuoteMeta(literal)

	return `"` + messageField + `":"` + quoted + `"|(^|\s)` + messageField + `="` + quoted + `"`
}

// Collect runs the coverage query and the profile queries of the requested components inside the window.
func (s *Source) Collect(ctx context.Context, query supportops.Query) supportops.SourceResult {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	window, clipped := s.coveredWindow(query.Window)
	collection := newCollection(s, query, window)

	if clipped {
		collection.degrade(supportops.SourceStatusPartial, "LOKI_WINDOW_CLIPPED")
	}

	entries := profileComponents(query)
	if len(entries) == 0 {
		return collection.result(nil)
	}

	coverage, ok := collection.run(ctx, profileEntry{})
	if !ok {
		return collection.result(nil)
	}

	counts := make([][]vectorSample, len(entries))
	failed := make([]bool, len(entries))
	semaphore := make(chan struct{}, maxParallelQueries)

	var wait sync.WaitGroup

	for index, entry := range entries {
		wait.Go(func() {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			samples, succeeded := collection.run(ctx, entry)
			counts[index], failed[index] = samples, !succeeded
		})
	}

	wait.Wait()

	return collection.result(collection.findings(entries, coverage, counts, failed))
}

// coveredWindow clips the requested window to its newest MaxTimeWindow part.
func (s *Source) coveredWindow(requested supportops.Window) (supportops.Window, bool) {
	if requested.Until.Sub(requested.From) <= s.maxTimeWindow {
		return requested, false
	}

	return supportops.Window{From: requested.Until.Add(-s.maxTimeWindow), Until: requested.Until}, true
}

// instanceName returns a plain instance label value, or a digest for anything that is not a plain name.
func instanceName(value string) string {
	if safeInstancePattern.MatchString(value) {
		return value
	}

	sum := sha256.Sum256([]byte(value))

	return instanceDigestPrefix + hex.EncodeToString(sum[:8])
}
