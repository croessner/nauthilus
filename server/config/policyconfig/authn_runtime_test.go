// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"errors"
	"strings"
	"testing"
)

// assertRuntimeValidationPath verifies that one runtime section fails validation at the exact path.
func assertRuntimeValidationPath(t *testing.T, runtime RuntimeConfig, path string) {
	t.Helper()

	err := Validate(Document{Policy: PolicyConfig{Runtime: runtime}})

	var pathError *PathError
	if !errors.As(err, &pathError) || !errors.Is(err, ErrValidation) || pathError.Path != path {
		t.Fatalf("Validate() error = %v, want path %s", err, path)
	}
}

func TestNormalizeKeepsInternalAuthnRuntimeUnboundedByDefault(t *testing.T) {
	normalized := Normalize(Document{}).Policy

	if normalized.Runtime.Authn != (AuthnRuntimeConfig{}) {
		t.Fatalf("internal authn runtime defaults = %+v, want unbounded zero values", normalized.Runtime.Authn)
	}

	if normalized.API.Limits.PerClientConcurrency == 0 || normalized.API.Limits.PerClientRequestsPerSecond == 0 {
		t.Fatalf("external Policy API limits lost their finite defaults: %+v", normalized.API.Limits)
	}

	configured := Document{Policy: PolicyConfig{Runtime: RuntimeConfig{
		Authn: AuthnRuntimeConfig{MaxConcurrency: 512, RequestsPerSecond: 2000},
	}}}

	authn := Normalize(configured).Policy.Runtime.Authn
	if authn.MaxConcurrency != 512 || authn.RequestsPerSecond != 2000 {
		t.Fatalf("configured internal authn runtime was replaced: %+v", authn)
	}
}

func TestValidateInternalAuthnRuntimeBounds(t *testing.T) {
	cases := []struct {
		name  string
		authn AuthnRuntimeConfig
		path  string
	}{
		{"negative concurrency", AuthnRuntimeConfig{MaxConcurrency: -1}, "policy.runtime.authn.max_concurrency"},
		{"negative rate", AuthnRuntimeConfig{RequestsPerSecond: -1}, "policy.runtime.authn.requests_per_second"},
		{
			"too much concurrency", AuthnRuntimeConfig{MaxConcurrency: maximumAuthnMaxConcurrency + 1},
			"policy.runtime.authn.max_concurrency",
		},
		{
			"too high rate", AuthnRuntimeConfig{RequestsPerSecond: maximumAuthnRequestsPerSecond + 1},
			"policy.runtime.authn.requests_per_second",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRuntimeValidationPath(t, RuntimeConfig{Authn: tc.authn}, tc.path)
		})
	}

	for _, authn := range []AuthnRuntimeConfig{
		{},
		{MaxConcurrency: maximumAuthnMaxConcurrency, RequestsPerSecond: maximumAuthnRequestsPerSecond},
		{MaxConcurrency: 1024},
		{RequestsPerSecond: 5000},
	} {
		if err := Validate(Document{Policy: PolicyConfig{Runtime: RuntimeConfig{Authn: authn}}}); err != nil {
			t.Fatalf("Validate(%+v) rejected bounded internal authn runtime: %v", authn, err)
		}
	}
}

func TestDecodeAcceptsInternalAuthnRuntimeKeys(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`policy:
  runtime:
    authn:
      max_concurrency: 256
      requests_per_second: 1000
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if got := document.Policy.Runtime.Authn; got.MaxConcurrency != 256 || got.RequestsPerSecond != 1000 {
		t.Fatalf("decoded internal authn runtime = %+v", got)
	}

	_, err = Decode("yaml", strings.NewReader(`policy:
  runtime:
    authn:
      max_concurrent: 256
`))
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Decode(unknown authn runtime key) error = %v, want ErrUnknownField", err)
	}
}
