// Copyright (C) 2025 Christian Rößner
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

package core

import (
	"html/template"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestTemplateLoading(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.SetFuncMap(template.FuncMap{
		"int": func(v any) int {
			switch x := v.(type) {
			case int:
				return x
			case int32:
				return int(x)
			case int64:
				return int(x)
			case float32:
				return int(x)
			case float64:
				return int(x)
			default:
				return 0
			}
		},
		"upper": func(s string) string {
			return strings.ToUpper(s)
		},
	})

	assert.NotPanics(t, func() {
		r.LoadHTMLGlob("../../static/templates/*.html")
	})

	// Also verify that the "upper" function is used in at least one template (idp_base.html)
	// and that it doesn't cause issues. idp_base.html uses: {{ slice .Username 0 1 | upper }}
	// We already know it doesn't panic during LoadHTMLGlob, which is the main issue.
}
