// Copyright 2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"fmt"
	"slices"

	"github.com/croessner/nauthilus/v4/server/model/mfa"
)

// ConsumeRecoveryCode uses backend-owned atomic consumption or a fresh legacy backend lookup.
// Legacy backends must implement TOTPRecoveryCodeConsumer to guarantee concurrent single use.
func ConsumeRecoveryCode(auth *AuthState, manager BackendManager, code string) (valid bool, remaining int, err error) {
	defer func() {
		if valid && err == nil {
			auth.PurgeCacheFor(auth.GetAccount())
		}
	}()

	if consumer, ok := manager.(TOTPRecoveryCodeConsumer); ok {
		return consumer.ConsumeTOTPRecoveryCode(auth, code)
	}

	return consumeFreshRecoveryCode(auth, manager, code)
}

// consumeFreshRecoveryCode bypasses passdb caches for legacy replacement-only backends.
func consumeFreshRecoveryCode(auth *AuthState, manager BackendManager, code string) (bool, int, error) {
	result, err := manager.PassDB(auth)
	if err != nil {
		return false, 0, err
	}

	if result == nil || !result.UserFound {
		return false, 0, nil
	}

	if id := auth.GetUniqueUserID(); id != "" {
		values := result.Attributes[result.UniqueUserIDField]
		if len(values) != 1 || values[0] != id {
			return false, 0, fmt.Errorf("recovery consume: backend identity changed")
		}
	}

	codes := make([]string, 0, len(result.Attributes[result.TOTPRecoveryField]))
	for _, value := range result.Attributes[result.TOTPRecoveryField] {
		if candidate, ok := value.(string); ok {
			codes = append(codes, candidate)
		}
	}

	if !slices.Contains(codes, code) {
		return false, len(codes), nil
	}

	remaining := slices.DeleteFunc(slices.Clone(codes), func(candidate string) bool { return candidate == code })
	if len(remaining) == 0 {
		err = manager.DeleteTOTPRecoveryCodes(auth)
	} else {
		err = manager.AddTOTPRecoveryCodes(auth, mfa.NewTOTPRecovery(remaining))
	}

	return err == nil, len(remaining), err
}
