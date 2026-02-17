package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestBindEnvs_SecretValuesFromEnv(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setDefaultEnvVars()

	t.Setenv("NAUTHILUS_SERVER_REDIS_PASSWORD_NONCE", "nonce")
	t.Setenv("NAUTHILUS_SERVER_REDIS_ENCRYPTION_SECRET", "redis-secret")
	t.Setenv("NAUTHILUS_LDAP_CONFIG_ENCRYPTION_SECRET", "ldap-secret")
	t.Setenv("NAUTHILUS_LDAP_CONFIG_BIND_DN", "cn=bind,dc=example,dc=test")
	t.Setenv("NAUTHILUS_LDAP_CONFIG_BIND_PW", "bind-secret")

	if err := bindEnvs(&FileSettings{}); err != nil {
		t.Fatalf("bindEnvs failed: %v", err)
	}

	cfg := &FileSettings{}
	if err := viper.UnmarshalExact(cfg, createDecoderOption()); err != nil {
		t.Fatalf("unmarshal config failed: %v", err)
	}

	if cfg.GetServer().GetRedis().GetPasswordNonce().IsZero() {
		t.Fatal("expected redis password nonce from env")
	}

	if cfg.GetServer().GetRedis().GetEncryptionSecret().IsZero() {
		t.Fatal("expected redis encryption secret from env")
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
