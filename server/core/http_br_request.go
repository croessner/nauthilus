package core

import (
	"io"

	"github.com/andybalholm/brotli"
	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
)

// brReadCloser wraps a brotli reader and the original compressed body to satisfy io.ReadCloser.
// Close will close the original compressed body.
// andybalholm/brotli does not require an explicit Close on the reader itself.
type brReadCloser struct {
	r   *brotli.Reader
	src io.ReadCloser
}

func (rc *brReadCloser) Read(p []byte) (int, error) {
	return rc.r.Read(p)
}

func (rc *brReadCloser) Close() error {
	return rc.src.Close()
}

// DecompressBrRequestMiddleware decompresses request bodies with Content-Encoding: br (Brotli)
// when server compression is enabled. It mirrors the gzip/zstd request decompression behavior.
func DecompressBrRequestMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		compressionConfig := config.GetFile().GetServer().GetCompression()

		// Skip if compression is disabled
		if !compressionConfig.IsEnabled() {
			c.Next()

			return
		}

		ce := c.Request.Header.Get("Content-Encoding")
		if ce == "br" { // Brotli compressed body
			compressedBody := c.Request.Body

			// Replace request body with a ReadCloser that reads decompressed data
			br := brotli.NewReader(compressedBody)
			c.Request.Body = &brReadCloser{r: br, src: compressedBody}

			// Remove Content-Encoding and Content-Length since body is now decoded and length unknown.
			c.Request.Header.Del("Content-Encoding")
			c.Request.Header.Del("Content-Length")
		}

		c.Next()
	}
}
