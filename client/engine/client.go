package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
)

type AuthClient struct {
	config     *Config
	httpClient *http.Client
}

func NewAuthClient(cfg *Config) *AuthClient {
	return &AuthClient{
		config: cfg,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
		},
	}
}

func (c *AuthClient) DoRequest(ctx context.Context, row Row) (ok bool, isMatch bool, isHttpErr bool, isTooManyRequests bool, latency time.Duration, respBody []byte, statusCode int, err error) {
	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()

	if c.config.AbortProb > 0 && rand.Float64() < c.config.AbortProb {
		maxMs := c.config.TimeoutMs / 2
		if maxMs < 1 {
			maxMs = 1
		}
		d := time.Duration(rand.IntN(maxMs+1)) * time.Millisecond
		time.AfterFunc(d, reqCancel)
	}

	start := time.Now()

	payload := c.makePayload(row.RawFields)

	// Random effects
	if c.config.RandomBadPass && rand.Float64() < c.config.RandomBadPassProb {
		if _, ok := payload["password"]; ok {
			payload["password"] = "wrong-password-" + hex.EncodeToString(sha256.New().Sum(nil)[:4])
		}
	}

	body, _ := jsoniter.Marshal(payload)

	reqURL := c.config.Endpoint
	if c.config.RandomNoAuth && row.ExpectOK && rand.Float64() < c.config.RandomNoAuthProb {
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
		return false, false, false, false, 0, nil, 0, err
	}

	// Add headers
	if c.config.HeadersList != "" {
		pairs := strings.Split(c.config.HeadersList, "||")
		for _, p := range pairs {
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
		return false, false, true, false, latency, nil, 0, err
	}
	defer resp.Body.Close()

	statusCode = resp.StatusCode
	respBody, _ = io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusTooManyRequests {
		return false, false, false, true, latency, respBody, statusCode, nil
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

	isMatch = ok == row.ExpectOK
	isHttpErr = resp.StatusCode >= 400 && resp.StatusCode != http.StatusTooManyRequests

	return ok, isMatch, isHttpErr, false, latency, respBody, statusCode, nil
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
