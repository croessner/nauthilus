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

//go:build hydra
// +build hydra

package core

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/util"

	openapi "github.com/ory/hydra-client-go/v2"
)

// processClaim copies a configured attribute (claimValue) into the output claims map under claimName.
// It is used in the Hydra/OIDC claim processing flow.
func (a *AuthState) processClaim(claimName string, claimValue string, claims map[string]any) {
	if claimValue != "" {
		if value, found := a.GetAttribute(claimValue); found {
			if arg, assertOk := value[definitions.SliceWithOneElement].(string); assertOk {
				claims[claimName] = arg

				return
			}
		}

		level.Warn(log.Logger).Log(
			definitions.LogKeyGUID, a.GUID,
			definitions.LogKeyMsg, fmt.Sprintf("Claim '%s' malformed or not returned from database", claimName),
		)
	}
}

// applyClaim applies attribute values to a specific claim using the provided handlers.
func applyClaim(claimKey string, attributeKey string, auth *AuthState, claims map[string]any, claimHandlers []ClaimHandler) {
	var success bool

	if attributeValue, found := auth.GetAttribute(attributeKey); found {
		for _, handler := range claimHandlers {
			if t := reflect.TypeOf(attributeValue).Kind(); t == handler.Type {
				success = handler.ApplyFunc(attributeValue, claims, claimKey)
				if success {
					break
				}
			}
		}
	}

	if !success {
		level.Warn(log.Logger).Log(
			definitions.LogKeyGUID, auth.GUID,
			definitions.LogKeyMsg, fmt.Sprintf("Claim '%s' malformed or not returned from Database", claimKey),
		)
	}
}

// processClientClaims evaluates standard OIDC claims configured on the client and fills them from attributes.
func (a *AuthState) processClientClaims(client *config.Oauth2Client, claims map[string]any) map[string]any {
	// Claim names to process
	claimChecks := map[string]string{
		definitions.ClaimName:              client.Claims.Name,
		definitions.ClaimGivenName:         client.Claims.GivenName,
		definitions.ClaimFamilyName:        client.Claims.FamilyName,
		definitions.ClaimMiddleName:        client.Claims.MiddleName,
		definitions.ClaimNickName:          client.Claims.NickName,
		definitions.ClaimPreferredUserName: client.Claims.PreferredUserName,
		definitions.ClaimProfile:           client.Claims.Profile,
		definitions.ClaimWebsite:           client.Claims.Website,
		definitions.ClaimPicture:           client.Claims.Picture,
		definitions.ClaimEmail:             client.Claims.Email,
		definitions.ClaimGender:            client.Claims.Gender,
		definitions.ClaimBirtDate:          client.Claims.Birthdate,
		definitions.ClaimZoneInfo:          client.Claims.ZoneInfo,
		definitions.ClaimLocale:            client.Claims.Locale,
		definitions.ClaimPhoneNumber:       client.Claims.PhoneNumber,
	}

	for claimName, claimVal := range claimChecks {
		a.processClaim(claimName, claimVal, claims)
	}

	return claims
}

// applyClientClaimHandlers applies typed transformations for specific claims (verified flags, address, updatedAt).
func (a *AuthState) applyClientClaimHandlers(client *config.Oauth2Client, claims map[string]any) map[string]any {
	claimHandlers := []ClaimHandler{
		{
			Type: reflect.String,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if strValue, ok := value.(string); ok {
					if claimKey == definitions.ClaimEmailVerified || claimKey == definitions.ClaimPhoneNumberVerified {
						if boolean, err := strconv.ParseBool(strValue); err == nil {
							claims[claimKey] = boolean

							return true
						}
					} else if claimKey == definitions.ClaimAddress {
						claims[claimKey] = struct {
							Formatted string `json:"formatted"`
						}{Formatted: strValue}

						return true
					}
				}

				return false
			},
		},
		{
			Type: reflect.Bool,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if boolValue, ok := value.(bool); ok {
					claims[claimKey] = boolValue

					return true
				}

				return false
			},
		},
		{
			Type: reflect.Float64,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if floatValue, ok := value.(float64); ok {
					claims[claimKey] = floatValue

					return true
				}

				return false
			},
		},
	}

	claimKeys := map[string]string{
		definitions.ClaimEmailVerified:       client.Claims.EmailVerified,
		definitions.ClaimPhoneNumberVerified: client.Claims.PhoneNumberVerified,
		definitions.ClaimAddress:             client.Claims.Address,
		definitions.ClaimUpdatedAt:           client.Claims.UpdatedAt,
	}

	for claimKey, attrKey := range claimKeys {
		if attrKey != "" {
			applyClaim(claimKey, attrKey, a, claims, claimHandlers)
		}
	}

	return claims
}

// processGroupsClaim populates the groups claim from the configured client groups attribute.
func (a *AuthState) processGroupsClaim(index int, claims map[string]any) {
	valueApplied := false

	if config.GetFile().GetOauth2().Clients[index].Claims.Groups != "" {
		if value, found := a.GetAttribute(config.GetFile().GetOauth2().Clients[index].Claims.Groups); found {
			var stringSlice []string

			util.DebugModule(
				definitions.DbgAuth,
				definitions.LogKeyGUID, a.GUID,
				"groups", fmt.Sprintf("%#v", value),
			)

			for anyIndex := range value {
				if arg, assertOk := value[anyIndex].(string); assertOk {
					stringSlice = append(stringSlice, arg)
				}
			}

			claims[definitions.ClaimGroups] = stringSlice
			valueApplied = true
		}

		if !valueApplied {
			level.Warn(log.Logger).Log(
				definitions.LogKeyGUID, a.GUID,
				definitions.LogKeyMsg, fmt.Sprintf("Claim '%s' malformed or not returned from Database", definitions.ClaimGroups),
			)
		}
	}
}

// processCustomClaims maps configured custom scope claims for the given OAuth2 client into the claims map.
func (a *AuthState) processCustomClaims(scopeIndex int, oauth2Client openapi.OAuth2Client, claims map[string]any) {
	var claim any

	customScope := config.GetFile().GetOauth2().CustomScopes[scopeIndex]

	for claimIndex := range customScope.Claims {
		customClaimName := customScope.Claims[claimIndex].Name
		customClaimType := customScope.Claims[claimIndex].Type

		for clientIndex := range config.GetFile().GetOauth2().Clients {
			if config.GetFile().GetOauth2().Clients[clientIndex].ClientId != oauth2Client.GetClientId() {
				continue
			}

			assertOk := false
			if claim, assertOk = config.GetFile().GetOauth2().Clients[clientIndex].Claims.CustomClaims[customClaimName]; !assertOk {
				break
			}

			if claimValue, assertOk := claim.(string); assertOk {
				if value, found := a.GetAttribute(claimValue); found {
					util.DebugModule(
						definitions.DbgAuth,
						definitions.LogKeyGUID, a.GUID,
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
						level.Error(log.Logger).Log(
							definitions.LogKeyGUID, a.GUID,
							"custom_claim_name", customClaimName,
							definitions.LogKeyMsg, "Unknown claim type.",
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
		index   int
		subject string
		client  config.Oauth2Client
		claims  map[string]any
	)

	// Cast any to openapi.OAuth2Client
	clientInterface, ok := oauth2Client.(openapi.OAuth2Client)
	if !ok {
		return "", nil
	}

	if config.GetFile().GetOauth2() != nil {
		claims = make(map[string]any)

		clientIDFound := false

		for index, client = range config.GetFile().GetOauth2().Clients {
			if client.ClientId == clientInterface.GetClientId() {
				clientIDFound = true

				util.DebugModule(
					definitions.DbgAuth,
					definitions.LogKeyGUID, a.GUID,
					definitions.LogKeyMsg, fmt.Sprintf("Found client_id: %+v", client),
				)

				claims = a.processClientClaims(&client, claims)
				claims = a.applyClientClaimHandlers(&client, claims)
				a.processGroupsClaim(index, claims)

				break //exit loop once first matching client found
			}
		}

		for scopeIndex := range config.GetFile().GetOauth2().CustomScopes {
			a.processCustomClaims(scopeIndex, clientInterface, claims)
		}

		if client.Subject != "" {
			var value []any

			if value, okay = a.GetAttribute(client.Subject); !okay {
				level.Info(log.Logger).Log(
					definitions.LogKeyGUID, a.GUID,
					definitions.LogKeyMsg, fmt.Sprintf(
						"SearchAttributes did not contain requested field '%s'",
						client.Subject,
					),
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
			level.Warn(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, "No client_id section found")
		}
	} else {
		// Default result, if no oauth2/clients definition is found
		subject = a.AccountField
	}

	return subject, claims
}
