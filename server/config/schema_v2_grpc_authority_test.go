// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestRuntimeGRPCAuthorityBackendRefsDefaultDisabled(t *testing.T) {
	var authority RuntimeGRPCAuthServerSection

	if authority.GetBackendRefs().IsEnabled() {
		t.Fatal("backend refs must default to disabled")
	}
}

func TestRuntimeGRPCAuthorityBackendRefsExplicitlyEnabled(t *testing.T) {
	authority := RuntimeGRPCAuthServerSection{
		BackendRefs: RuntimeGRPCBackendRefsSection{Enabled: true},
	}

	if !authority.GetBackendRefs().IsEnabled() {
		t.Fatal("explicitly enabled backend refs must be enabled")
	}
}

func TestRuntimeGRPCKeepAliveDefaults(t *testing.T) {
	var authority RuntimeGRPCAuthServerSection

	keepAlive := authority.GetKeepAlive()

	assertGRPCKeepAliveDuration(t, "max_connection_age", keepAlive.GetMaxConnectionAge(), 5*time.Minute)
	assertGRPCKeepAliveDuration(t, "max_connection_age_grace", keepAlive.GetMaxConnectionAgeGrace(), 60*time.Second)
	assertGRPCKeepAliveDuration(t, "max_connection_idle", keepAlive.GetMaxConnectionIdle(), 0)
	assertGRPCKeepAliveDuration(t, "min_ping_interval", keepAlive.GetMinPingInterval(), 10*time.Second)

	if !keepAlive.PermitsWithoutStream() {
		t.Fatal("permit_without_stream must default to true")
	}
}

func TestRuntimeGRPCKeepAliveExplicitZeroDisablesAgeing(t *testing.T) {
	disabled := time.Duration(0)
	grace := 45 * time.Second
	keepAlive := &RuntimeGRPCKeepAliveSection{
		MaxConnectionAge:      &disabled,
		MaxConnectionAgeGrace: &grace,
	}

	assertGRPCKeepAliveDuration(t, "max_connection_age", keepAlive.GetMaxConnectionAge(), 0)
	assertGRPCKeepAliveDuration(t, "max_connection_age_grace", keepAlive.GetMaxConnectionAgeGrace(), 0)
}

func TestValidateGRPCKeepAlive(t *testing.T) {
	negative := -time.Second
	disabled := time.Duration(0)
	grace := 30 * time.Second

	cases := []struct {
		name      string
		wantErr   []string
		keepAlive RuntimeGRPCKeepAliveSection
	}{
		{name: "defaults"},
		{name: "ageing disabled without grace", keepAlive: RuntimeGRPCKeepAliveSection{MaxConnectionAge: &disabled}},
		{
			name:      "negative age",
			keepAlive: RuntimeGRPCKeepAliveSection{MaxConnectionAge: &negative},
			wantErr:   []string{"keep_alive.max_connection_age must not be negative"},
		},
		{
			name:      "negative grace",
			keepAlive: RuntimeGRPCKeepAliveSection{MaxConnectionAgeGrace: &negative},
			wantErr:   []string{"keep_alive.max_connection_age_grace must not be negative"},
		},
		{
			name:      "negative idle",
			keepAlive: RuntimeGRPCKeepAliveSection{MaxConnectionIdle: negative},
			wantErr:   []string{"keep_alive.max_connection_idle must not be negative"},
		},
		{
			name:      "negative ping interval",
			keepAlive: RuntimeGRPCKeepAliveSection{MinPingInterval: negative},
			wantErr:   []string{"keep_alive.min_ping_interval must not be negative"},
		},
		{
			name:      "grace without age",
			keepAlive: RuntimeGRPCKeepAliveSection{MaxConnectionAge: &disabled, MaxConnectionAgeGrace: &grace},
			wantErr:   []string{"keep_alive.max_connection_age_grace requires", "max_connection_age > 0"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			assertGRPCKeepAliveValidation(t, validateGRPCKeepAlive(grpcAuthorityKeepAlivePath, &testCase.keepAlive), testCase.wantErr)
		})
	}
}

func TestHandleFile_DecodesGRPCAuthorityKeepAlive(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setGRPCAuthorityValidationTestConfig("127.0.0.1:9444")
	setGRPCAuthBasicBackchannelTestConfig()
	viper.Set("runtime.servers.grpc.authority.keep_alive", map[string]any{
		"max_connection_age":       "0s",
		"max_connection_idle":      "15m",
		"min_ping_interval":        "20s",
		"permit_without_stream":    false,
		"max_connection_age_grace": "0s",
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	keepAlive := cfg.GetRuntimeGRPCAuthServer().GetKeepAlive()

	if keepAlive.MaxConnectionAge == nil {
		t.Fatal("explicit max_connection_age=0s must be retained as a disabling value, not as unset")
	}

	assertGRPCKeepAliveDuration(t, "max_connection_age", keepAlive.GetMaxConnectionAge(), 0)
	assertGRPCKeepAliveDuration(t, "max_connection_idle", keepAlive.GetMaxConnectionIdle(), 15*time.Minute)
	assertGRPCKeepAliveDuration(t, "min_ping_interval", keepAlive.GetMinPingInterval(), 20*time.Second)

	if keepAlive.PermitsWithoutStream() {
		t.Fatal("explicit permit_without_stream=false must be retained")
	}
}

func TestHandleFile_RejectsGRPCAuthorityGraceWithoutAge(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setGRPCAuthorityValidationTestConfig("127.0.0.1:9444")
	setGRPCAuthBasicBackchannelTestConfig()
	viper.Set("runtime.servers.grpc.authority.keep_alive", map[string]any{
		"max_connection_age":       "0s",
		"max_connection_age_grace": "30s",
	})

	cfg := &FileSettings{}

	assertGRPCKeepAliveValidation(t, cfg.HandleFile(), []string{
		"runtime.servers.grpc.authority.keep_alive.max_connection_age_grace requires",
	})
}

// assertGRPCKeepAliveDuration compares one resolved keepalive duration.
func assertGRPCKeepAliveDuration(t *testing.T, name string, got, want time.Duration) {
	t.Helper()

	if got != want {
		t.Fatalf("%s = %s, want %s", name, got, want)
	}
}

// assertGRPCKeepAliveValidation checks a validation result against expected error fragments.
func assertGRPCKeepAliveValidation(t *testing.T, err error, wantErr []string) {
	t.Helper()

	if len(wantErr) == 0 {
		if err != nil {
			t.Fatalf("validation error = %v, want nil", err)
		}

		return
	}

	if err == nil {
		t.Fatalf("validation error = nil, want %v", wantErr)
	}

	assertContainsAll(t, err.Error(), wantErr)
}
