// Copyright (C) 2026 Christian Rößner
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
	"strings"

	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

const (
	requestAttributeCaseLower = "lower"
	requestAttributeCaseUpper = "upper"
)

func (a *AuthState) recordRequestPolicyAttributes(
	policyCtx *policycollection.DecisionContext,
	ctx *gin.Context,
	operation policy.Operation,
	settings policyruntime.RequestAttributeSettings,
) {
	if a == nil || policyCtx == nil {
		return
	}

	for _, plan := range settings.Headers {
		value, ok := normalizedRequestAttributeValue(headerValues(ctx, plan.Header), plan.Normalize)
		if !ok {
			continue
		}

		policyCtx.RecordAttribute(policycollection.StringAttribute(plan.Attribute, policy.StagePreAuth, operation, value))
	}

	for _, plan := range settings.Metadata {
		value, ok := normalizedRequestAttributeValue(metadataValues(a.Request.RequestMetadata, plan.Key), plan.Normalize)
		if !ok {
			continue
		}

		policyCtx.RecordAttribute(policycollection.StringAttribute(plan.Attribute, policy.StagePreAuth, operation, value))
	}
}

func headerValues(ctx *gin.Context, header string) []string {
	if ctx == nil || ctx.Request == nil {
		return nil
	}

	return ctx.Request.Header.Values(header)
}

func metadataValues(metadata map[string][]string, key string) []string {
	if len(metadata) == 0 {
		return nil
	}

	if values := metadata[key]; len(values) > 0 {
		return values
	}

	return metadata[strings.ToLower(key)]
}

func normalizedRequestAttributeValue(
	values []string,
	normalization policyruntime.RequestAttributeNormalization,
) (string, bool) {
	if len(values) == 0 {
		return "", false
	}

	normalized := make([]string, 0, len(values))
	for _, value := range values {
		current := normalizeRequestAttributePart(value, normalization)
		if current == "" {
			continue
		}

		normalized = append(normalized, current)
	}

	if len(normalized) == 0 {
		return "", false
	}

	// Multiple values use a deterministic comma join before length limiting.
	value := strings.Join(normalized, ",")
	if normalization.MaxLength > 0 {
		value = truncateRequestAttributeValue(value, normalization.MaxLength)
	}

	return value, true
}

func normalizeRequestAttributePart(
	value string,
	normalization policyruntime.RequestAttributeNormalization,
) string {
	if normalization.Trim {
		value = strings.TrimSpace(value)
	}

	switch normalization.Case {
	case requestAttributeCaseLower:
		value = strings.ToLower(value)
	case requestAttributeCaseUpper:
		value = strings.ToUpper(value)
	}

	return value
}

func truncateRequestAttributeValue(value string, maxLength int) string {
	runes := []rune(value)
	if len(runes) <= maxLength {
		return value
	}

	return string(runes[:maxLength])
}
