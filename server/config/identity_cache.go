package config

import "time"

const defaultIdentityCacheTTL = time.Minute

// IdentityCache controls caching of successful LDAP identity lookups without password authority.
type IdentityCache struct {
	TTL     time.Duration `mapstructure:"ttl" validate:"omitempty,min=1s,max=8760h"`
	Enabled bool          `mapstructure:"enabled"`
}

// GetIdentityCacheEnabled reports whether positive LDAP identity caching is explicitly enabled.
func (r *Redis) GetIdentityCacheEnabled() bool {
	return r != nil && r.IdentityCache != nil && r.IdentityCache.Enabled
}

// GetIdentityCacheTTL returns the fixed entry lifetime, defaulting to one minute.
func (r *Redis) GetIdentityCacheTTL() time.Duration {
	if r == nil || r.IdentityCache == nil || r.IdentityCache.TTL == 0 {
		return defaultIdentityCacheTTL
	}

	return r.IdentityCache.TTL
}
