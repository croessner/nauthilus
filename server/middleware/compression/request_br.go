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
	"io"

	"github.com/andybalholm/brotli"
	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
)

type brReadCloser struct {
	r   io.Reader
	src io.Closer
}

func (b brReadCloser) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b brReadCloser) Close() error {
	if b.src != nil {
		return b.src.Close()
	}

	return nil
}

// DecompressBrRequestMiddleware returns a middleware that decompresses HTTP requests with brotli Content-Encoding.
// It checks if the request has a Content-Encoding header with value "br"/"brotli" and if so, replaces the request body
// with a decompressed version and clears the encoding header.
func DecompressBrRequestMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		compressionConfig := config.GetFile().GetServer().GetCompression()

		// Skip if compression is disabled
		if !compressionConfig.IsEnabled() {
			c.Next()

			return
		}

		enc := c.Request.Header.Get("Content-Encoding")
		if enc == "br" || enc == "brotli" {
			reader := brotli.NewReader(c.Request.Body)
			c.Request.Body = brReadCloser{r: reader, src: c.Request.Body}

			// Remove Content-Encoding and Content-Length headers since we've decompressed the body
			c.Request.Header.Del("Content-Encoding")
			c.Request.Header.Del("Content-Length")
		}

		c.Next()
	}
}
