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

package compression

import (
	"fmt"
	"io"
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
)

type zstdReadCloser struct {
	dec *zstd.Decoder
	src io.Closer
}

func (z zstdReadCloser) Read(p []byte) (int, error) {
	return z.dec.Read(p)
}

func (z zstdReadCloser) Close() error {
	z.dec.Close()
	if z.src != nil {
		return z.src.Close()
	}

	return nil
}

// DecompressZstdRequestMiddleware returns a middleware that decompresses HTTP requests with zstd Content-Encoding.
// It checks if the request has a Content-Encoding header with value "zstd"/"zst" and if so, replaces the request body
// with a decompressed version and clears the encoding header.
func DecompressZstdRequestMiddleware(cfg config.File) gin.HandlerFunc {
	return func(c *gin.Context) {
		compressionConfig := cfg.GetServer().GetCompression()

		// Skip if compression is disabled
		if !compressionConfig.IsEnabled() {
			c.Next()

			return
		}

		enc := c.Request.Header.Get("Content-Encoding")
		if enc == "zstd" || enc == "zst" || enc == "zstandard" {
			dec, err := zstd.NewReader(c.Request.Body)
			if err != nil {
				c.AbortWithError(http.StatusBadRequest, fmt.Errorf("failed to decompress zstd request body: %w", err))

				return
			}

			// Replace the request body with a ReadCloser that ties Decoder lifecycle to the original body
			c.Request.Body = zstdReadCloser{dec: dec, src: c.Request.Body}

			// Remove Content-Encoding and Content-Length headers since we've decompressed the body
			c.Request.Header.Del("Content-Encoding")
			c.Request.Header.Del("Content-Length")
		}

		c.Next()
	}
}
