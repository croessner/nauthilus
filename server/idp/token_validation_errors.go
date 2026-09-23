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

package idp

import (
	stderrors "errors"
	"fmt"

	"github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/idp/dcr"
	"github.com/croessner/nauthilus/v4/server/idp/oidckeys"
	"github.com/redis/go-redis/v9"
)

// errInvalidOpaqueToken is the verdict for unknown, expired, revoked, or unreadable opaque token state.
var errInvalidOpaqueToken = stderrors.New("invalid or expired opaque token")

// tokenStateReadError marks a failed Redis command on authoritative token state as technical.
//
// Classification happens at the command site because only there a Redis failure can be told apart from
// verdicts that surface later, such as undecodable session data or a revoked user epoch. redis.Nil passes
// through unchanged: an absent record is a statement about the token, not about the store.
func tokenStateReadError(err error) error {
	if err == nil || stderrors.Is(err, redis.Nil) {
		return err
	}

	return errors.NewTokenValidationUnavailable(err)
}

// opaqueTokenLookupError turns a failed opaque-token lookup into either a technical failure or the
// uniform invalid-token verdict, so callers never learn why a presented token was rejected.
func opaqueTokenLookupError(err error) error {
	if errors.IsTokenValidationUnavailable(err) {
		return err
	}

	return errInvalidOpaqueToken
}

// dynamicClientResolveError classifies a failed dynamic-client resolution during token validation.
// Only an unreachable registry is technical; absent, expired, revoked, or corrupt records reject the token.
func dynamicClientResolveError(err error) error {
	if stderrors.Is(err, dcr.ErrUnavailable) {
		return errors.NewTokenValidationUnavailable(fmt.Errorf("resolve dynamic client: %w", err))
	}

	return fmt.Errorf("dynamic client is not active: %w", err)
}

// signingKeyLookupError classifies a failed verification-key lookup during JWT validation.
// An unreachable key store is technical; an unknown, expired, or unsupported key rejects the token.
func signingKeyLookupError(err error) error {
	if stderrors.Is(err, oidckeys.ErrKeyStoreUnavailable) {
		return errors.NewTokenValidationUnavailable(err)
	}

	return err
}
