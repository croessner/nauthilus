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

package zstdmw

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// fakeEncoder implements ZstdEncoder for testing.
type fakeEncoder struct {
	wrote  int
	closed bool
}

func (f *fakeEncoder) Write(p []byte) (int, error) { f.wrote += len(p); return len(p), nil }
func (f *fakeEncoder) Close() error                { f.closed = true; return nil }

func TestZstdMiddleware_NoAcceptEncoding_NoCompression(t *testing.T) {
	gin.SetMode(gin.TestMode)

	called := 0
	origFactory := newEncoder
	newEncoder = func(w io.Writer, lvl Level) (ZstdEncoder, error) {
		called++

		return &fakeEncoder{}, nil
	}

	defer func() { newEncoder = origFactory }()

	r := gin.New()

	r.Use(Zstd(DefaultCompression))
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "hello") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No Accept-Encoding header
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("expected no Content-Encoding, got %q", got)
	}

	if called != 0 {
		t.Fatalf("expected factory not to be called, called=%d", called)
	}
}

func TestZstdMiddleware_AcceptsZstd_CompressesAndSetsHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fe := &fakeEncoder{}
	origFactory := newEncoder

	newEncoder = func(w io.Writer, lvl Level) (ZstdEncoder, error) {
		return fe, nil
	}

	defer func() { newEncoder = origFactory }()

	r := gin.New()

	r.Use(Zstd(DefaultCompression))
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "hello world") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	req.Header.Set("Accept-Encoding", "zstd")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("expected Content-Encoding=zstd, got %q", got)
	}

	vary := w.Header().Get("Vary")
	if !strings.Contains(vary, "Accept-Encoding") {
		t.Fatalf("expected Vary to contain Accept-Encoding, got %q", vary)
	}

	if w.Header().Get("Content-Length") != "" {
		t.Fatalf("expected Content-Length to be removed for compressed response")
	}

	if !fe.closed {
		t.Fatalf("expected encoder to be closed")
	}

	if fe.wrote == 0 {
		t.Fatalf("expected some bytes to be written to encoder")
	}
}

func TestZstdMiddleware_NoBodyStatuses_NoEncoder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	called := 0
	origFactory := newEncoder

	newEncoder = func(w io.Writer, lvl Level) (ZstdEncoder, error) {
		called++

		return &fakeEncoder{}, nil
	}

	defer func() { newEncoder = origFactory }()

	r := gin.New()

	r.Use(Zstd(DefaultCompression))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) }) // 204

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	req.Header.Set("Accept-Encoding", "zstd")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("expected no Content-Encoding for 204, got %q", got)
	}

	if called != 0 {
		t.Fatalf("expected factory not to be called for 204, called=%d", called)
	}
}

func TestZstdWithOptionsBuilder_ExcludePath_SkipsCompression(t *testing.T) {
	gin.SetMode(gin.TestMode)

	called := 0
	origFactory := newEncoder
	newEncoder = func(w io.Writer, lvl Level) (ZstdEncoder, error) {
		called++

		return &fakeEncoder{}, nil
	}

	defer func() { newEncoder = origFactory }()

	r := gin.New()
	opts := NewOptions().WithExcludePaths("/")

	r.Use(ZstdWith(DefaultCompression, opts))
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "x") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	req.Header.Set("Accept-Encoding", "zstd")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("expected no Content-Encoding due to excluded path, got %q", got)
	}

	if called != 0 {
		t.Fatalf("expected factory not to be called when excluded, called=%d", called)
	}
}
