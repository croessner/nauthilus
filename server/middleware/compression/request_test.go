// Copyright (C) 2026 Christian Roessner
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

package compression

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
)

type compressionTestWriter interface {
	io.Writer
	io.Closer
}

type compressedRequestCase struct {
	name     string
	encoding string
	body     []byte
	mw       gin.HandlerFunc
}

func TestDecompressedBodyLimitRejectsExpandedGzipAndBrotli(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := strings.Repeat("A", int(util.DefaultHTTPRequestBodyLimit)+1)
	tests := []compressedRequestCase{
		{
			name:     "gzip",
			encoding: "gzip",
			body:     gzipRequestBody(t, payload),
			mw:       DecompressRequestMiddleware(newCompressionTestConfig()),
		},
		{
			name:     "brotli",
			encoding: "br",
			body:     brotliRequestBody(t, payload),
			mw:       DecompressBrRequestMiddleware(newCompressionTestConfig()),
		},
		{
			name:     "zstd",
			encoding: "zstd",
			body:     zstdRequestBody(t, payload),
			mw:       DecompressZstdRequestMiddleware(newCompressionTestConfig()),
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			w := serveCompressedRequest(testCase)

			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
			}
		})
	}
}

func TestDecompressedBodyLimitPreservesValidGzipAndBrotli(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := `{"username":"alice"}`
	tests := []compressedRequestCase{
		{
			name:     "gzip",
			encoding: "gzip",
			body:     gzipRequestBody(t, payload),
			mw:       DecompressRequestMiddleware(newCompressionTestConfig()),
		},
		{
			name:     "brotli",
			encoding: "br",
			body:     brotliRequestBody(t, payload),
			mw:       DecompressBrRequestMiddleware(newCompressionTestConfig()),
		},
		{
			name:     "zstd",
			encoding: "zstd",
			body:     zstdRequestBody(t, payload),
			mw:       DecompressZstdRequestMiddleware(newCompressionTestConfig()),
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			w := serveCompressedRequest(testCase)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}

			if w.Body.String() != payload {
				t.Fatalf("body = %q, want %q", w.Body.String(), payload)
			}
		})
	}
}

// serveCompressedRequest sends a compressed body through one decompression middleware.
func serveCompressedRequest(testCase compressedRequestCase) *httptest.ResponseRecorder {
	router := gin.New()
	router.Use(testCase.mw)
	router.POST("/body", func(ctx *gin.Context) {
		body, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			ctx.AbortWithStatus(http.StatusRequestEntityTooLarge)

			return
		}

		ctx.String(http.StatusOK, string(body))
	})

	req := httptest.NewRequest(http.MethodPost, "/body", bytes.NewReader(testCase.body))
	req.Header.Set("Content-Encoding", testCase.encoding)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	return w
}

// gzipRequestBody returns a gzip-compressed request payload for middleware tests.
func gzipRequestBody(t *testing.T, payload string) []byte {
	t.Helper()

	return compressedRequestBody(t, payload, "gzip", func(writer io.Writer) compressionTestWriter {
		return gzip.NewWriter(writer)
	})
}

// brotliRequestBody returns a brotli-compressed request payload for middleware tests.
func brotliRequestBody(t *testing.T, payload string) []byte {
	t.Helper()

	return compressedRequestBody(t, payload, "brotli", func(writer io.Writer) compressionTestWriter {
		return brotli.NewWriter(writer)
	})
}

// zstdRequestBody returns a zstd-compressed request payload for middleware tests.
func zstdRequestBody(t *testing.T, payload string) []byte {
	t.Helper()

	var body bytes.Buffer

	writer, err := zstd.NewWriter(&body)
	if err != nil {
		t.Fatalf("create zstd writer: %v", err)
	}

	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatalf("write zstd payload: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close zstd writer: %v", err)
	}

	return body.Bytes()
}

// compressedRequestBody writes one compressed request body using the provided encoder.
func compressedRequestBody(t *testing.T, payload string, name string, newWriter func(io.Writer) compressionTestWriter) []byte {
	t.Helper()

	var body bytes.Buffer

	writer := newWriter(&body)
	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatalf("write %s payload: %v", name, err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close %s writer: %v", name, err)
	}

	return body.Bytes()
}

// newCompressionTestConfig enables request decompression for middleware tests.
func newCompressionTestConfig() config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{
			Compression: config.Compression{
				Enabled: true,
			},
		},
	}
}
