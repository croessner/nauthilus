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

import "github.com/croessner/nauthilus/v3/server/localcache"

// AuthCacheInvalidator removes local authentication state by public identity.
type AuthCacheInvalidator interface {
	InvalidateIdentities(identities ...string) int
}

// CompositeAuthCacheInvalidator explicitly coordinates the two separated auth caches.
type CompositeAuthCacheInvalidator struct {
	backendAuthentications *PositiveBackendAuthenticationCache
	userAuth               *localcache.UserAuthCache
}

// NewCompositeAuthCacheInvalidator creates a local cache invalidator.
func NewCompositeAuthCacheInvalidator(backendAuthentications *PositiveBackendAuthenticationCache, userAuth *localcache.UserAuthCache) *CompositeAuthCacheInvalidator {
	return &CompositeAuthCacheInvalidator{backendAuthentications: backendAuthentications, userAuth: userAuth}
}

// InvalidateIdentities removes all backend-authentication variants and priority hints.
func (c *CompositeAuthCacheInvalidator) InvalidateIdentities(identities ...string) int {
	removed := 0
	if c != nil && c.backendAuthentications != nil {
		removed += c.backendAuthentications.InvalidateIdentities(identities...)
	}

	if c != nil && c.userAuth != nil {
		for _, identity := range identities {
			if _, found := c.userAuth.Get(identity); found {
				removed++
			}

			c.userAuth.Delete(identity)
		}
	}

	return removed
}

var defaultAuthCacheInvalidator = NewCompositeAuthCacheInvalidator(defaultPositiveBackendAuthenticationCache, localcache.AuthCache)
