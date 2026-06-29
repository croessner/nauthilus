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
	"io"
	"net/http"

	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
)

const (
	// maxDecompressedRequestBodyBytes caps expanded request bodies before handlers parse them.
	maxDecompressedRequestBodyBytes = util.DefaultHTTPRequestBodyLimit
)

// limitDecompressedRequestBody wraps a decompressed body with the shared expanded-size cap.
func limitDecompressedRequestBody(ctx *gin.Context, body io.ReadCloser) io.ReadCloser {
	return http.MaxBytesReader(ctx.Writer, body, maxDecompressedRequestBodyBytes)
}
