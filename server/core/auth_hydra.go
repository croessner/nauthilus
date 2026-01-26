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
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"

	openapi "github.com/ory/hydra-client-go/v2"
)

// processCustomClaims maps configured custom scope claims for the given OAuth2 client into the claims map.
func (a *AuthState) processCustomClaims(scopeIndex int, oauth2Client openapi.OAuth2Client, claims map[string]any) {
	var claim any

	customScope := a.cfg().GetOauth2().CustomScopes[scopeIndex]

	for claimIndex := range customScope.Claims {
		customClaimName := customScope.Claims[claimIndex].Name
		customClaimType := customScope.Claims[claimIndex].Type

		for clientIndex := range a.cfg().GetOauth2().Clients {
			if a.cfg().GetOauth2().Clients[clientIndex].ClientId != oauth2Client.GetClientId() {
				continue
			}

			assertOk := false
			if claim, assertOk = a.cfg().GetOauth2().Clients[clientIndex].Claims.CustomClaims[customClaimName]; !assertOk {
				break
			}

			if claimValue, assertOk := claim.(string); assertOk {
				if value, found := a.GetAttribute(claimValue); found {
					util.DebugModuleWithCfg(
						a.Ctx(),
						a.Cfg(),
						a.Logger(),
						definitions.DbgAuth,
						definitions.LogKeyGUID, a.Runtime.GUID,
						"custom_claim_name", customClaimName,
						"custom_claim_type", customClaimType,
						"value", fmt.Sprintf("%#v", value),
					)

					switch customClaimType {
					case definitions.ClaimTypeString:
						if arg, assertOk := value[definitions.SliceWithOneElement].(string); assertOk {
							claims[customClaimName] = arg
						}
					case definitions.ClaimTypeFloat:
						if arg, assertOk := value[definitions.SliceWithOneElement].(float64); assertOk {
							claims[customClaimName] = arg
						} else if arg, assertOk := value[definitions.SliceWithOneElement].(string); assertOk {
							if number, err := strconv.ParseFloat(arg, 64); err == nil {
								claims[customClaimName] = number
							}
						}
					case definitions.ClaimTypeInteger:
						if arg, assertOk := value[definitions.SliceWithOneElement].(int64); assertOk {
							claims[customClaimName] = arg
						} else if arg, assertOk := value[definitions.SliceWithOneElement].(string); assertOk {
							if number, err := strconv.ParseInt(arg, 0, 64); err == nil {
								claims[customClaimName] = number
							}
						}
					case definitions.ClaimTypeBoolean:
						if arg, assertOk := value[definitions.SliceWithOneElement].(bool); assertOk {
							claims[customClaimName] = arg
						} else if arg, assertOk := value[definitions.SliceWithOneElement].(string); assertOk {
							if boolean, err := strconv.ParseBool(arg); err == nil {
								claims[customClaimName] = boolean
							}
						}
					default:
						a.logger().Error(
							"Unknown claim type.",
							definitions.LogKeyGUID, a.Runtime.GUID,
							"custom_claim_name", customClaimName,
							definitions.LogKeyError, fmt.Sprintf("Unknown type '%s'", customClaimType),
						)
					}
				}
			}

			break
		}
	}
}

// GetOauth2SubjectAndClaims returns the subject and claims for the provided OAuth2 client
// by combining client configuration, custom scopes, and AuthState attributes.
func (a *AuthState) GetOauth2SubjectAndClaims(oauth2Client any) (string, map[string]any) {
	var (
		okay    bool
		subject string
		client  config.Oauth2Client
		claims  map[string]any
	)

	// Cast any to openapi.OAuth2Client
	clientInterface, ok := oauth2Client.(openapi.OAuth2Client)
	if !ok {
		return "", nil
	}

	if a.cfg().GetOauth2() != nil {
		claims = make(map[string]any)

		clientIDFound := false

		for _, client = range a.cfg().GetOauth2().Clients {
			if client.ClientId == clientInterface.GetClientId() {
				clientIDFound = true

				util.DebugModuleWithCfg(
					a.Ctx(),
					a.Cfg(),
					a.Logger(),
					definitions.DbgAuth,
					definitions.LogKeyGUID, a.Runtime.GUID,
					definitions.LogKeyMsg, fmt.Sprintf("Found client_id: %+v", client),
				)

				a.FillIdTokenClaims(&client.Claims, claims, nil)

				break //exit loop once first matching client found
			}
		}

		for scopeIndex := range a.cfg().GetOauth2().CustomScopes {
			a.processCustomClaims(scopeIndex, clientInterface, claims)
		}

		if client.Subject != "" {
			var value []any

			if value, okay = a.GetAttribute(client.Subject); !okay {
				a.logger().Info(
					fmt.Sprintf("SearchAttributes did not contain requested field '%s'", client.Subject),
					definitions.LogKeyGUID, a.Runtime.GUID,
					"attributes", func() string {
						var attributes []string

						a.RangeAttributes(func(key string, _ []any) bool {
							attributes = append(attributes, key)

							return true
						})

						return strings.Join(attributes, ", ")
					}(),
				)
			} else if _, okay = value[definitions.SliceWithOneElement].(string); okay {
				subject = value[definitions.SliceWithOneElement].(string)
			}
		}

		if !clientIDFound {
			a.logger().Warn("No client_id section found", definitions.LogKeyGUID, a.Runtime.GUID)
		}
	} else {
		// Default result, if no oauth2/clients definition is found
		subject = a.Runtime.AccountField
	}

	return subject, claims
}
