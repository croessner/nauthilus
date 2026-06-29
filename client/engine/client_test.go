package engine

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthClientDefaultTransportVerifiesCertificates(t *testing.T) {
	cfg := DefaultConfig()
	client := NewAuthClient(cfg)

	transport, ok := client.HTTPClient().Transport.(*http.Transport)
	assert.True(t, ok)

	assert.False(t, transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify)
}

func TestAuthClientExplicitInsecureTLSMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InsecureTLS = true
	client := NewAuthClient(cfg)

	transport, ok := client.HTTPClient().Transport.(*http.Transport)
	assert.True(t, ok)

	assert.Equal(t, &tls.Config{InsecureSkipVerify: true}, transport.TLSClientConfig)
}

func TestIdempotencyKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UseIdemKey = true
	cfg.Endpoint = testLocalHTTPEndpoint // placeholder

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		assert.NotEmpty(t, key)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"ok": true}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	cfg.Endpoint = server.URL
	client := NewAuthClient(cfg)
	row := Row{
		RawFields: map[string]string{"user": "test"},
		ExpectOK:  true,
	}

	ok, _, _, _, _, _, _, _, _, err := client.DoRequest(context.Background(), row)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestRandomEffects(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RandomBadPass = true
	cfg.RandomBadPassProb = 1.0 // Force it
	cfg.Endpoint = testLocalHTTPEndpoint

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Just return something
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"ok": false}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	cfg.Endpoint = server.URL
	client := NewAuthClient(cfg)
	row := Row{
		RawFields: map[string]string{csvFieldPassword: "correct"},
		ExpectOK:  true,
	}

	// Should have changed password to something else
	ok, _, _, _, _, _, _, _, _, err := client.DoRequest(context.Background(), row)
	assert.NoError(t, err)
	assert.False(t, ok)
}
