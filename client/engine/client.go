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

var fastJson = jsoniter.ConfigFastest

type AuthClient struct {
	config       *Config
	httpClient   *http.Client
	bfHeaderName string
}

func NewAuthClient(cfg *Config) *AuthClient {
	bfHeaderName := strings.TrimSpace(os.Getenv("BRUTEFORCE_HEADER_NAME"))
	if bfHeaderName == "" {
		bfHeaderName = "X-Nauthilus-Bruteforce"
	}

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
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &AuthClient{
		config:       cfg,
		bfHeaderName: bfHeaderName,
		httpClient: &http.Client{
			Timeout:   time.Duration(cfg.TimeoutMs) * time.Millisecond,
			Transport: transport,
		},
	}
}

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

func (c *AuthClient) HTTPClient() *http.Client {
	return c.httpClient
}

func (c *AuthClient) Stop() {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.DisableKeepAlives = true
		transport.CloseIdleConnections()
	}
}

func (c *AuthClient) DoRequest(ctx context.Context, row Row) (ok bool, isMatch bool, isHttpErr bool, isTooManyRequests bool, isToleratedBF bool, isAborted bool, latency time.Duration, respBody []byte, statusCode int, err error) {
	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()

	if c.config.AbortProb > 0 && rand.Float64() < c.config.AbortProb {
		maxMs := max(c.config.TimeoutMs/2, 1)
		d := time.Duration(rand.IntN(maxMs+1)) * time.Millisecond
		time.AfterFunc(d, reqCancel)
	}

	start := time.Now()

	payload := c.makePayload(row.RawFields)

	// Random effects (pre-determined by row flags)
	if row.BadPass {
		if _, ok := payload["password"]; ok {
			payload["password"] = "wrong-password-" + hex.EncodeToString(sha256.New().Sum(nil)[:4])
		}
	}

	body, _ := fastJson.Marshal(payload)

	reqURL := c.config.Endpoint
	if row.NoAuth {
		if u, err := url.Parse(reqURL); err == nil {
			q := u.Query()
			if q.Get("mode") == "" {
				q.Set("mode", "no-auth")
				u.RawQuery = q.Encode()
				reqURL = u.String()
			}
		}
	}

	req, err := http.NewRequestWithContext(reqCtx, c.config.Method, reqURL, bytes.NewReader(body))
	if err != nil {
		return false, false, false, false, false, false, 0, nil, 0, err
	}

	// Add headers
	if c.config.HeadersList != "" {
		pairs := strings.SplitSeq(c.config.HeadersList, "||")
		for p := range pairs {
			kv := strings.SplitN(p, ":", 2)
			if len(kv) == 2 {
				req.Header.Set(strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1]))
			}
		}
	}

	if c.config.BasicAuth != "" {
		kv := strings.SplitN(c.config.BasicAuth, ":", 2)
		if len(kv) == 2 {
			req.SetBasicAuth(kv[0], kv[1])
		}
	}

	if c.config.UseIdemKey {
		h := sha256.Sum256(body)
		req.Header.Set("Idempotency-Key", hex.EncodeToString(h[:]))
	}

	resp, err := c.httpClient.Do(req)
	latency = time.Since(start)
	if err != nil {
		aborted := false
		if ctx.Err() != nil || reqCtx.Err() != nil {
			aborted = true
		}

		return false, false, !aborted, false, false, aborted, latency, nil, 0, err
	}
	defer resp.Body.Close()

	statusCode = resp.StatusCode
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		aborted := false
		if ctx.Err() != nil || reqCtx.Err() != nil {
			aborted = true
		}

		return false, false, !aborted, false, false, aborted, latency, nil, statusCode, err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return false, false, false, true, false, false, latency, respBody, statusCode, nil
	}

	if c.config.UseJSONFlag {
		var res struct {
			OK bool `json:"ok"`
		}
		_ = jsoniter.Unmarshal(respBody, &res)
		ok = res.OK
	} else {
		ok = resp.StatusCode == c.config.OKStatus
	}

	effectiveExpectOK := row.ExpectOK
	if row.BadPass && !row.NoAuth {
		effectiveExpectOK = false
	}

	isMatch = ok == effectiveExpectOK
	isToleratedBF = resp.Header.Get(c.bfHeaderName) != ""
	isHttpErr = (!isMatch && !isToleratedBF) || (resp.StatusCode >= 500)

	return ok, isMatch, isHttpErr, false, isToleratedBF, false, latency, respBody, statusCode, nil
}

func (c *AuthClient) makePayload(fields map[string]string) map[string]any {
	p := make(map[string]any)
	for k, v := range fields {
		if k == "expected_ok" {
			continue
		}
		p[k] = v
	}
	return p
}
