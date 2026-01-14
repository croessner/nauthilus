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
	"log/slog"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"

	"github.com/gin-gonic/gin"
)

// setCommonHeaders sets common headers for the given gin.Context and AuthState.
// It sets the "Auth-Status" header to "OK" and the "X-Nauthilus-Session" header to the GUID of the AuthState.
// If the AuthState's Service is not definitions.ServBasic, and the HaveAccountField flag is true,
// it retrieves the account from the AuthState and sets the "Auth-User" header
func setCommonHeaders(ctx *gin.Context, auth *AuthState) {
	ctx.Header("Auth-Status", "OK")
	ctx.Header("X-Nauthilus-Session", auth.GUID)

	if auth.Service != definitions.ServBasic {
		if account, found := auth.GetAccountOk(); found {
			ctx.Header("Auth-User", account)
		}
	}

	cachedAuth := ctx.GetBool(definitions.CtxLocalCacheAuthKey)

	if cachedAuth {
		ctx.Header("X-Nauthilus-Memory-Cache", "Hit")
	} else {
		ctx.Header("X-Nauthilus-Memory-Cache", "Miss")
	}
}

// setNginxHeaders sets the appropriate headers for the given gin.Context and AuthState based on the configuration and feature flags.
// If the definitions.FeatureBackendServersMonitoring feature is enabled, it checks if the AuthState's UsedBackendAddress and UsedBackendPort are set.
// If they are, it sets the "Auth-Server" header to the UsedBackendAddress and the "Auth-Port" header to the UsedBackendPort.
// If the definitions.FeatureBackendServersMonitoring feature is disabled, it checks the AuthState's Protocol.
// If the Protocol is definitions.ProtoSMTP, it sets the "Auth-Server" header to the SMTPBackendAddress and the "Auth-Port" header to the SMTPBackendPort.
// If the Protocol is definitions.ProtoIMAP, it sets the "Auth-Server" header to the IMAPBackendAddress and the "Auth-Port" header to the IMAPBackendPort.
// If the Protocol is definitions.ProtoPOP3, it sets the "Auth-Server" header to the POP3BackendAddress and the "Auth-Port" header to the POP3BackendPort.
func setNginxHeaders(ctx *gin.Context, auth *AuthState) {
	setNginxHeadersWithDeps(getDefaultConfigFile(), getDefaultEnvironment(), getDefaultLogger(), ctx, auth)
}

func setNginxHeadersWithDeps(cfg config.File, env config.Environment, logger *slog.Logger, ctx *gin.Context, auth *AuthState) {
	if cfg.HasFeature(definitions.FeatureBackendServersMonitoring) {
		if BackendServers.GetTotalServers() == 0 {
			ctx.Header("Auth-Status", "Internal failure")
			level.Error(logger).Log(
				definitions.LogKeyGUID, auth.GUID,
				definitions.LogKeyMsg, "No backend servers found for backend_server_monitoring feature",
				definitions.LogKeyError, "No backend servers found for backend_server_monitoring feature",
				definitions.LogKeyInstance, cfg.GetServer().GetInstanceName(),
			)
		} else {
			if auth.UsedBackendIP != "" && auth.UsedBackendPort > 0 {
				ctx.Header("Auth-Server", auth.UsedBackendIP)
				ctx.Header("Auth-Port", fmt.Sprintf("%d", auth.UsedBackendPort))
			}
		}
	} else {
		switch auth.Protocol.Get() {
		case definitions.ProtoSMTP:
			ctx.Header("Auth-Server", env.GetSMTPBackendAddress())
			ctx.Header("Auth-Port", fmt.Sprintf("%d", env.GetSMTPBackendPort()))
		case definitions.ProtoIMAP:
			ctx.Header("Auth-Server", env.GetIMAPBackendAddress())
			ctx.Header("Auth-Port", fmt.Sprintf("%d", env.GetIMAPBackendPort()))
		case definitions.ProtoPOP3:
			ctx.Header("Auth-Server", env.GetPOP3BackendAddress())
			ctx.Header("Auth-Port", fmt.Sprintf("%d", env.GetPOP3BackendPort()))
		}
	}
}

// setHeaderHeaders sets the specified headers in the given gin.Context based on the attributes in the AuthState object.
// It iterates through the attributes and calls the handleAttributeValue function for each attribute.
//
// Parameters:
// - ctx: The gin.Context object to set the headers on.
// - a: The AuthState object containing the attributes.
//
// Example:
//
//	a := &AuthState{
//	    SearchAttributes: map[string][]any{
//	        "Attribute1": []any{"Value1"},
//	        "Attribute2": []any{"Value2_1", "Value2_2"},
//	    },
//	}
//	setHeaderHeaders(ctx, a)
//
// Resulting headers in ctx:
// - X-Nauthilus-Attribute1: "Value1"
// - X-Nauthilus-Attribute2: "Value2_1,Value2_2"
func setHeaderHeaders(ctx *gin.Context, auth *AuthState) {
	if auth.Attributes != nil && len(auth.Attributes) > 0 {
		for name, value := range auth.Attributes {
			handleAttributeValue(ctx, name, value)
		}
	}
}

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
		switch {
		case valueLen == 1:
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
