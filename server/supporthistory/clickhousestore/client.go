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

// Package clickhousestore is the bounded, read-only ClickHouse implementation of the support history stores.
//
// It talks to the ClickHouse HTTP interface with typed {name:Type} query parameters only, reads self-terminating
// FORMAT JSON bodies, never treats a truncated or unparseable body as an empty result, and enforces read budgets
// either per query (readonly=2 profile) or by verifying the reader's settings profile (readonly=1).
package clickhousestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

// BudgetMode selects how read budgets are enforced.
type BudgetMode string

const (
	// BudgetQuerySettings sends every budget with each query; the reader profile must be readonly=2.
	BudgetQuerySettings BudgetMode = "query_settings"

	// BudgetProfile relies on the reader profile (readonly=1) and verifies its effective values.
	BudgetProfile BudgetMode = "profile"
)

// Budget is the per-query read budget.
type Budget struct {
	MaxExecutionTime time.Duration
	MaxRowsToRead    uint64
	MaxBytesToRead   uint64
	MaxResponseBytes int64
}

// Config configures one reader.
type Config struct {
	HTTPClient *http.Client
	Password   secret.Value
	URL        string
	Database   string
	Username   string
	Deployment string
	Mode       BudgetMode
	Budget     Budget
}

// overflowThrow is the only accepted overflow mode: a hit budget must be an error, never truncated rows.
const overflowThrow = "throw"

// identifierPattern restricts the database name that is interpolated into SQL.
var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// exceptionCodePattern extracts a ClickHouse error code from a body.
var exceptionCodePattern = regexp.MustCompile(`Code: (\d+)\.`)

// client executes bounded read-only queries.
type client struct {
	http     *http.Client
	endpoint *url.URL
	password secret.Value
	database string
	username string
	mode     BudgetMode
	budget   Budget
}

// newClient validates the configuration.
func newClient(config Config) (*client, error) {
	endpoint, err := validateEndpoint(config.URL)
	if err != nil {
		return nil, err
	}

	if err = validateReaderConfig(config); err != nil {
		return nil, err
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: config.Budget.MaxExecutionTime + 2*time.Second}
	}

	return &client{http: httpClient, endpoint: endpoint, password: config.Password, database: config.Database,
		username: config.Username, mode: config.Mode, budget: config.Budget}, nil
}

// validateEndpoint accepts an absolute http(s) URL without query parameters or embedded credentials.
func validateEndpoint(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" {
		return nil, errors.New("support history ClickHouse URL must be an absolute http(s) URL")
	}

	if endpoint.RawQuery != "" || endpoint.User != nil {
		return nil, errors.New("support history ClickHouse URL must not carry query parameters or credentials")
	}

	return endpoint, nil
}

// validateReaderConfig checks the identifier, the budget mode, and that every budget is positive.
func validateReaderConfig(config Config) error {
	if !identifierPattern.MatchString(config.Database) {
		return errors.New("support history ClickHouse database must be a plain identifier")
	}

	if config.Mode != BudgetQuerySettings && config.Mode != BudgetProfile {
		return fmt.Errorf("unsupported support history budget mode %q", config.Mode)
	}

	budget := config.Budget
	if budget.MaxExecutionTime <= 0 || budget.MaxRowsToRead == 0 || budget.MaxBytesToRead == 0 || budget.MaxResponseBytes <= 0 {
		return errors.New("support history ClickHouse budgets must be positive")
	}

	return nil
}

// table returns the qualified name of one table; the database is a validated identifier.
func (c *client) table(name string) string {
	return c.database + "." + name
}

// jsonBody is the self-terminating FORMAT JSON envelope.
type jsonBody struct {
	Rows      *int              `json:"rows"`
	Exception *string           `json:"exception"`
	Data      []json.RawMessage `json:"data"`
}

// query runs one SELECT with typed parameters and decodes each data row into a fresh value from newRow.
func (c *client) query(ctx context.Context, statement string, params map[string]string, decode func(json.RawMessage) error) error {
	request, err := c.request(ctx, statement, params)
	if err != nil {
		return err
	}

	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		return fmt.Errorf("%w: transport", supporthistory.ErrSourceUnavailable)
	}

	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, c.budget.MaxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: body", supporthistory.ErrSourceUnavailable)
	}

	if int64(len(body)) > c.budget.MaxResponseBytes {
		return fmt.Errorf("%w: response exceeds the configured size", supporthistory.ErrBudgetExceeded)
	}

	envelope, err := parseEnvelope(response, body)
	if err != nil {
		return err
	}

	for _, row := range envelope.Data {
		if err = decode(row); err != nil {
			return fmt.Errorf("%w: row", supporthistory.ErrSourceUnavailable)
		}
	}

	return nil
}

// request builds the POST request with credentials in headers and budgets as query settings.
func (c *client) request(ctx context.Context, statement string, params map[string]string) (*http.Request, error) {
	values := url.Values{}
	for name, value := range params {
		values.Set("param_"+name, value)
	}

	if c.mode == BudgetQuerySettings {
		for name, value := range c.settings() {
			values.Set(name, value)
		}
	}

	target := *c.endpoint
	target.RawQuery = values.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(),
		bytes.NewBufferString(statement+" FORMAT JSON"))
	if err != nil {
		return nil, fmt.Errorf("%w: request", supporthistory.ErrSourceUnavailable)
	}

	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	request.Header.Set("X-ClickHouse-User", c.username)
	c.password.WithString(func(password string) { request.Header.Set("X-ClickHouse-Key", password) })

	return request, nil
}

// settings returns the per-query budget settings of query_settings mode.
func (c *client) settings() map[string]string {
	return map[string]string{
		"max_execution_time":    strconv.FormatInt(max(1, int64(c.budget.MaxExecutionTime/time.Second)), 10),
		"max_rows_to_read":      strconv.FormatUint(c.budget.MaxRowsToRead, 10),
		"max_bytes_to_read":     strconv.FormatUint(c.budget.MaxBytesToRead, 10),
		"read_overflow_mode":    overflowThrow,
		"result_overflow_mode":  overflowThrow,
		"timeout_overflow_mode": overflowThrow,
	}
}

// parseEnvelope validates status, completeness, and embedded exceptions of one response.
func parseEnvelope(response *http.Response, body []byte) (jsonBody, error) {
	var envelope jsonBody

	decodeErr := json.Unmarshal(body, &envelope)

	switch {
	case decodeErr != nil:
		return envelope, classify(response.Header.Get("X-ClickHouse-Exception-Code"), body)
	case envelope.Exception != nil:
		return envelope, classify(response.Header.Get("X-ClickHouse-Exception-Code"), []byte(*envelope.Exception))
	case response.StatusCode != http.StatusOK:
		return envelope, classify(response.Header.Get("X-ClickHouse-Exception-Code"), body)
	case envelope.Rows == nil || *envelope.Rows != len(envelope.Data):
		return envelope, fmt.Errorf("%w: incomplete body", supporthistory.ErrSourceUnavailable)
	default:
		return envelope, nil
	}
}

// classify maps a ClickHouse error code to a store error without keeping server text.
func classify(header string, body []byte) error {
	code, _ := strconv.Atoi(strings.TrimSpace(header))
	if code == 0 {
		if match := exceptionCodePattern.FindSubmatch(body); match != nil {
			code, _ = strconv.Atoi(string(match[1]))
		}
	}

	switch code {
	case 158, 159, 160, 307, 396:
		return fmt.Errorf("%w: code %d", supporthistory.ErrBudgetExceeded, code)
	case 60, 81:
		return fmt.Errorf("%w: code %d", supporthistory.ErrSourceNotInstalled, code)
	case 164, 452:
		return fmt.Errorf("%w: code %d", supporthistory.ErrReaderUnsafe, code)
	case 0:
		return fmt.Errorf("%w: unparseable body", supporthistory.ErrSourceUnavailable)
	default:
		return fmt.Errorf("%w: code %d", supporthistory.ErrSourceUnavailable, code)
	}
}
