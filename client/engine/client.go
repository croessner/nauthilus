package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
)

var fastJSON = jsoniter.ConfigFastest

// AuthClient describes the exported AuthClient type.
type AuthClient struct {
	config       *Config
	httpClient   *http.Client
	bfHeaderName string
}

// NewAuthClient provides the exported NewAuthClient function.
func NewAuthClient(cfg *Config) *AuthClient {
	bfHeaderName := strings.TrimSpace(os.Getenv("BRUTEFORCE_HEADER_NAME"))
	if bfHeaderName == "" {
		bfHeaderName = "X-Nauthilus-Bruteforce"
	}

	transport := newAuthClientTransport(cfg)

	return &AuthClient{
		config:       cfg,
		bfHeaderName: bfHeaderName,
		httpClient: &http.Client{
			Timeout:   time.Duration(cfg.TimeoutMs) * time.Millisecond,
			Transport: transport,
		},
	}
}

// newAuthClientTransport builds the HTTP transport and keeps TLS verification enabled unless explicitly disabled.
func newAuthClientTransport(cfg *Config) *http.Transport {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          8192,
		MaxIdleConnsPerHost:   8192,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
	}

	if cfg != nil && cfg.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	return transport
}

// BaseHeader provides the exported BaseHeader method.
func (c *AuthClient) BaseHeader() http.Header {
	h := make(http.Header)

	if c.config.HeadersList != "" {
		pairs := strings.SplitSeq(c.config.HeadersList, "||")
		for p := range pairs {
			kv := strings.SplitN(p, ":", 2)
			if len(kv) == 2 {
				h.Set(strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1]))
			}
		}
	}

	if c.config.BasicAuth != "" {
		kv := strings.SplitN(c.config.BasicAuth, ":", 2)
		if len(kv) == 2 {
			// Use standard SetBasicAuth if possible, but we need to return Header
			req, _ := http.NewRequest("GET", "http://empty", nil)
			req.SetBasicAuth(kv[0], kv[1])
			h.Set("Authorization", req.Header.Get("Authorization"))
		}
	}

	return h
}

// HTTPClient provides the exported HTTPClient method.
func (c *AuthClient) HTTPClient() *http.Client {
	return c.httpClient
}

// Stop provides the exported Stop method.
func (c *AuthClient) Stop() {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.DisableKeepAlives = true
		transport.CloseIdleConnections()
	}
}

// DoRequest provides the exported DoRequest method.
func (c *AuthClient) DoRequest(ctx context.Context, row Row) (ok bool, isMatch bool, isHTTPErr bool, isTooManyRequests bool, isToleratedBF bool, isAborted bool, latency time.Duration, respBody []byte, statusCode int, err error) {
	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()

	c.scheduleAbort(reqCancel)

	start := time.Now()
	body := c.requestBody(row)

	req, err := c.newAuthRequest(reqCtx, row, body)
	if err != nil {
		return false, false, false, false, false, false, 0, nil, 0, err
	}

	resp, err := c.httpClient.Do(req)
	latency = time.Since(start)

	if err != nil {
		aborted := requestAborted(ctx, reqCtx)

		return false, false, !aborted, false, false, aborted, latency, nil, 0, err
	}

	defer func() { _ = resp.Body.Close() }()

	statusCode = resp.StatusCode

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		aborted := requestAborted(ctx, reqCtx)

		return false, false, !aborted, false, false, aborted, latency, nil, statusCode, err
	}

	outcome := c.evaluateResponse(row, resp, respBody)

	return outcome.ok, outcome.isMatch, outcome.isHTTPErr, outcome.isTooManyRequests, outcome.isToleratedBF, false, latency, respBody, statusCode, nil
}

// scheduleAbort installs a probabilistic request cancellation timer.
func (c *AuthClient) scheduleAbort(cancel context.CancelFunc) {
	if c.config.AbortProb <= 0 || rand.Float64() >= c.config.AbortProb {
		return
	}

	maxMs := max(c.config.TimeoutMs/2, 1)
	delay := time.Duration(rand.IntN(maxMs+1)) * time.Millisecond
	time.AfterFunc(delay, cancel)
}

// requestBody builds the JSON request body from row fields and mutations.
func (c *AuthClient) requestBody(row Row) []byte {
	payload := c.makePayload(row.RawFields)
	if row.BadPass {
		applyBadPassword(payload)
	}

	body, _ := fastJSON.Marshal(payload)

	return body
}

// applyBadPassword replaces a present password with the deterministic bad-password marker.
func applyBadPassword(payload map[string]any) {
	if _, ok := payload[csvFieldPassword]; !ok {
		return
	}

	payload[csvFieldPassword] = "wrong-password-" + hex.EncodeToString(sha256.New().Sum(nil)[:4])
}

// newAuthRequest creates a configured HTTP request for one row.
func (c *AuthClient) newAuthRequest(ctx context.Context, row Row, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, c.config.Method, c.requestURL(row), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	applyHeaders(req, c.BaseHeader())
	c.applyIdempotencyKey(req, body)

	return req, nil
}

// requestURL applies the no-auth query mode when the row requests it.
func (c *AuthClient) requestURL(row Row) string {
	if !row.NoAuth {
		return c.config.Endpoint
	}

	u, err := url.Parse(c.config.Endpoint)
	if err != nil {
		return c.config.Endpoint
	}

	q := u.Query()
	if q.Get("mode") != "" {
		return c.config.Endpoint
	}

	q.Set("mode", "no-auth")
	u.RawQuery = q.Encode()

	return u.String()
}

// applyHeaders copies a prepared header set onto a request.
func applyHeaders(req *http.Request, header http.Header) {
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
}

// applyIdempotencyKey attaches a stable body hash when configured.
func (c *AuthClient) applyIdempotencyKey(req *http.Request, body []byte) {
	if !c.config.UseIdemKey {
		return
	}

	hash := sha256.Sum256(body)
	req.Header.Set("Idempotency-Key", hex.EncodeToString(hash[:]))
}

// requestAborted reports whether either request context was canceled.
func requestAborted(parent context.Context, request context.Context) bool {
	return parent.Err() != nil || request.Err() != nil
}

type responseOutcome struct {
	ok                bool
	isMatch           bool
	isHTTPErr         bool
	isTooManyRequests bool
	isToleratedBF     bool
}

// evaluateResponse converts the HTTP response into the client result flags.
func (c *AuthClient) evaluateResponse(row Row, resp *http.Response, body []byte) responseOutcome {
	if resp.StatusCode == http.StatusTooManyRequests {
		return responseOutcome{isTooManyRequests: true}
	}

	ok := c.responseOK(resp.StatusCode, body)
	isMatch := ok == effectiveExpectOK(row)
	isToleratedBF := resp.Header.Get(c.bfHeaderName) != ""

	return responseOutcome{
		ok:            ok,
		isMatch:       isMatch,
		isHTTPErr:     (!isMatch && !isToleratedBF) || resp.StatusCode >= 500,
		isToleratedBF: isToleratedBF,
	}
}

// responseOK interprets success either from JSON or the configured status code.
func (c *AuthClient) responseOK(statusCode int, body []byte) bool {
	if !c.config.UseJSONFlag {
		return statusCode == c.config.OKStatus
	}

	var res struct {
		OK bool `json:"ok"`
	}

	_ = jsoniter.Unmarshal(body, &res)

	return res.OK
}

// effectiveExpectOK applies row-level mutations to the expected result.
func effectiveExpectOK(row Row) bool {
	if row.BadPass && !row.NoAuth {
		return false
	}

	return row.ExpectOK
}

func (c *AuthClient) makePayload(fields map[string]string) map[string]any {
	p := make(map[string]any)

	for k, v := range fields {
		if k == csvFieldExpectedOK {
			continue
		}

		p[k] = v
	}

	return p
}
