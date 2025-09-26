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
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/middleware/brmw"
	"github.com/croessner/nauthilus/server/middleware/zstdmw"

	gzipmw "github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
)

// useGzipCompression applies gzip compression to the provided gin.Engine if compression is enabled in the configuration.
// It uses the compression level specified by cmp.GetLevelGzip(), falling back to a default if the value is out of range.
func useGzipCompression(router *gin.Engine, alg string, cmp *config.Compression) bool {
	if cmp == nil || !cmp.IsEnabled() {
		return false
	}

	if !strings.EqualFold(alg, "gzip") {
		return false
	}

	compressionLevel := cmp.GetLevelGzip()
	if compressionLevel < gzip.BestSpeed || compressionLevel > gzip.BestCompression {
		compressionLevel = gzip.DefaultCompression
	}

	router.Use(gzipmw.Gzip(compressionLevel))

	return true
}

// useZstdCompression applies Zstandard compression middleware to the given router with specified compression level and min length.
// It maps the level from the config to predefined zstdmw.Level constants and sets the minimum content length if specified.
func useZstdCompression(router *gin.Engine, alg string, cmp *config.Compression, minLen int) bool {
	if cmp == nil || !cmp.IsEnabled() {
		return false
	}

	if !(strings.EqualFold(alg, "zstd") || strings.EqualFold(alg, "zst") || strings.EqualFold(alg, "zstandard")) {
		return false
	}

	zlvl := cmp.GetLevelZstd()

	// map int to zstdmw.Level
	var lvl zstdmw.Level
	switch zlvl {
	case 1:
		lvl = zstdmw.BestSpeed
	case 2:
		lvl = zstdmw.BetterCompression
	case 3:
		lvl = zstdmw.BestCompression
	default:
		lvl = zstdmw.DefaultCompression
	}

	opts := zstdmw.NewOptions()
	if minLen > 0 {
		opts = opts.WithMinLength(minLen)
	}

	router.Use(zstdmw.ZstdWith(lvl, opts))

	return true
}

// useBrotliCompression enables Brotli compression middleware for the provided router, based on the given configuration.
// The function checks if compression is enabled and applies the Brotli compression level and options accordingly.
func useBrotliCompression(router *gin.Engine, alg string, cmp *config.Compression, minLen int) bool {
	if cmp == nil || !cmp.IsEnabled() {
		return false
	}

	if !(strings.EqualFold(alg, "br") || strings.EqualFold(alg, "brotli")) {
		return false
	}

	brlvl := cmp.GetLevelBrotli()

	// map int to zstdmw.Level
	var lvl brmw.Level
	switch brlvl {
	case 1:
		lvl = brmw.BestSpeed
	case 2:
		lvl = brmw.BetterCompression
	case 3:
		lvl = brmw.BestCompression
	default:
		lvl = brmw.DefaultCompression
	}

	opts := brmw.NewOptions()
	if minLen > 0 {
		opts = opts.WithMinLength(minLen)
	}

	router.Use(brmw.BrotliWith(lvl, opts))

	return true
}

// ApplyResponseCompression applies the first available compression algorithm from the config, with a sensible fallback.
func ApplyResponseCompression(router *gin.Engine, cmp *config.Compression) {
	if cmp == nil || !cmp.IsEnabled() {
		return
	}

	algs := cmp.GetAlgorithms()
	minLen := cmp.GetMinLength()
	chosen := false

	for _, alg := range algs {
		if chosen = useBrotliCompression(router, alg, cmp, minLen); chosen {
			break
		}

		if chosen = useZstdCompression(router, alg, cmp, minLen); chosen {
			break
		}

		if chosen = useGzipCompression(router, alg, cmp); chosen {
			break
		}
	}

	if !chosen {
		useZstdCompression(router, "zstd", cmp, minLen)
	}
}
