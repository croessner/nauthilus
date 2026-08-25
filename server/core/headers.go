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

package core

import (
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v3/server/definitions"

	"github.com/gin-gonic/gin"
)

// handleAttributeValue sets the value of a header in the given gin.Context based on the name and value provided.
// If the value length is 1, it formats the value as a string and assigns it to the headerValue variable.
// If the value length is greater than 1, it formats each value and joins them with a comma separator, unless the name is "dn",
// in which case it joins them with a semicolon separator.
// Finally, it adds the header "X-Nauthilus-" + name with the value of headerValue to the gin.Context.
// Parameters:
// - ctx: the gin.Context to set the header in
// - name: the name of the header
// - value: the value of the header
func handleAttributeValue(ctx *gin.Context, name string, value []any) {
	var headerValue string

	if valueLen := len(value); valueLen > 0 {
		switch valueLen {
		case 1:
			headerValue = fmt.Sprintf("%v", value[definitions.LDAPSingleValue])
		default:
			stringValues := formatValues(value)
			separator := ","

			if name == definitions.DistinguishedName {
				separator = ";"
			}

			headerValue = strings.Join(stringValues, separator)
		}

		ctx.Header("X-Nauthilus-"+name, fmt.Sprintf("%v", headerValue))
	}
}

// formatValues takes an array of values and formats them into strings.
// It creates an empty slice of strings called stringValues.
// It then iterates over each value in the "values" array and appends the formatted string representation of that value to stringValues using fmt.Sprintf("%v", values[index]).
// After iterating over all the values, it returns stringValues.
// Example usage:
// values := []any{"one", "two", "three"}
// result := formatValues(values)
// fmt.Println(result) // Output: ["one", "two", "three"]
func formatValues(values []any) []string {
	var stringValues []string

	for index := range values {
		stringValues = append(stringValues, fmt.Sprintf("%v", values[index]))
	}

	return stringValues
}
