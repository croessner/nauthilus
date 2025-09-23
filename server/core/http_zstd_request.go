package core

import (
	"fmt"
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
)

// zstdReadCloser wraps a zstd.Decoder to satisfy io.ReadCloser explicitly.
type zstdReadCloser struct{ dec *zstd.Decoder }

// Read reads decompressed data into the provided byte slice p and returns the number of bytes read and any error encountered.
func (rc *zstdReadCloser) Read(p []byte) (int, error) {
	return rc.dec.Read(p)
}

// Close releases resources associated with the zstdReadCloser by closing the underlying zstd.Decoder.
func (rc *zstdReadCloser) Close() error {
	rc.dec.Close()

	return nil
}

// DecompressZstdRequestMiddleware decompresses request bodies with Content-Encoding: zstd/zst/zstandard
// when server compression is enabled. It mirrors the gzip request decompression behavior.
func DecompressZstdRequestMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		compressionConfig := config.GetFile().GetServer().GetCompression()

		// Skip if compression is disabled
		if !compressionConfig.IsEnabled() {
			c.Next()

			return
		}

		ce := c.Request.Header.Get("Content-Encoding")
		if ce == "zstd" || ce == "zst" || ce == "zstandard" {
			compressedBody := c.Request.Body

			defer compressedBody.Close()

			decoder, err := zstd.NewReader(compressedBody)
			if err != nil {
				c.AbortWithError(http.StatusBadRequest, fmt.Errorf("failed to decompress zstd request body: %w", err))

				return
			}

			// Replace request body with a ReadCloser that closes the decoder properly.
			c.Request.Body = &zstdReadCloser{dec: decoder}

			// Remove Content-Encoding and Content-Length since body is now decoded and length unknown.
			c.Request.Header.Del("Content-Encoding")
			c.Request.Header.Del("Content-Length")
		}

		c.Next()
	}
}
