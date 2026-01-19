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
	"compress/gzip"
	"fmt"
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
)

// DecompressRequestMiddleware returns a middleware that decompresses HTTP requests with gzip Content-Encoding.
// If Content-Encoding is "gzip", it replaces the request body with a gzip reader and removes encoding/length headers.
func DecompressRequestMiddleware(cfg config.File) gin.HandlerFunc {
	return func(c *gin.Context) {
		compressionConfig := cfg.GetServer().GetCompression()

		// Skip if compression is disabled
		if !compressionConfig.IsEnabled() {
			c.Next()

			return
		}

		// Check if request is gzip compressed
		if c.Request.Header.Get("Content-Encoding") == "gzip" {
			// Get the compressed body
			compressedBody := c.Request.Body

			defer compressedBody.Close()

			// Create a gzip reader
			gzipReader, err := gzip.NewReader(compressedBody)
			if err != nil {
				c.AbortWithError(http.StatusBadRequest, fmt.Errorf("failed to decompress request body: %w", err))

				return
			}

			defer gzipReader.Close()

			// Replace the request body with the decompressed content
			c.Request.Body = gzipReader

			// Remove Content-Encoding header since we've decompressed the body
			c.Request.Header.Del("Content-Encoding")

			// Update Content-Length if it exists
			c.Request.Header.Del("Content-Length")
		}

		c.Next()
	}
}
