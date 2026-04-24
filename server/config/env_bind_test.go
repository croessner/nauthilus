package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestBindEnvs_SecretValuesFromEnv(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setDefaultEnvVars()

	t.Setenv("NAUTHILUS_STORAGE_REDIS_PASSWORD_NONCE", "nonce")
	t.Setenv("NAUTHILUS_STORAGE_REDIS_ENCRYPTION_SECRET", "redis-secret")
	t.Setenv("NAUTHILUS_STORAGE_REDIS_PRIMARY_ADDRESS", "redis.example.test:6379")
	t.Setenv("NAUTHILUS_AUTH_BACKENDS_LDAP_DEFAULT_ENCRYPTION_SECRET", "ldap-secret")
	t.Setenv("NAUTHILUS_AUTH_BACKENDS_LDAP_DEFAULT_BIND_DN", "cn=bind,dc=example,dc=test")
	t.Setenv("NAUTHILUS_AUTH_BACKENDS_LDAP_DEFAULT_BIND_PW", "bind-secret")

	if err := bindEnvs(&FileSettings{}); err != nil {
		t.Fatalf("bindEnvs failed: %v", err)
	}

	cfg := &FileSettings{}
	if err := viper.UnmarshalExact(cfg, createDecoderOption()); err != nil {
		t.Fatalf("unmarshal config failed: %v", err)
	}

	cfg.materializeLegacySections()

	if cfg.GetServer().GetRedis().GetPasswordNonce().IsZero() {
		t.Fatal("expected redis password nonce from env")
	}

	if cfg.GetServer().GetRedis().GetEncryptionSecret().IsZero() {
		t.Fatal("expected redis encryption secret from env")
	}

	if cfg.GetServer().GetRedis().GetStandaloneMaster().GetAddress() != "redis.example.test:6379" {
		t.Fatalf("expected redis primary address from env, got %q", cfg.GetServer().GetRedis().GetStandaloneMaster().GetAddress())
	}

	if cfg.GetLDAPConfigEncryptionSecret().IsZero() {
		t.Fatal("expected ldap encryption secret from env")
	}

	if cfg.GetLDAPConfigBindDN() == "" {
		t.Fatal("expected ldap bind DN from env")
	}

	if cfg.GetLDAPConfigBindPW().IsZero() {
		t.Fatal("expected ldap bind password from env")
	}
}
