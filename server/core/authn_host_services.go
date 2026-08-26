// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import "fmt"

// AuthnHostServicesInput supplies the immutable host implementation bundle captured by one application owner.
type AuthnHostServicesInput struct {
	PasswordVerifier PasswordVerifier
	Cache            CacheService
	BruteForce       BruteForceService
	Subject          CapturedLuaSubject
	RBL              RBLService
}

// AuthnHostServices owns every host implementation used by candidate authn execution.
type AuthnHostServices struct {
	passwordVerifier PasswordVerifier
	cache            CacheService
	bruteForce       BruteForceService
	subject          CapturedLuaSubject
	rbl              RBLService
}

// NewAuthnHostServices validates and freezes one detached host implementation bundle.
func NewAuthnHostServices(input AuthnHostServicesInput) (AuthnHostServices, error) {
	services := AuthnHostServices{
		passwordVerifier: input.PasswordVerifier,
		cache:            input.Cache,
		bruteForce:       input.BruteForce,
		subject:          input.Subject,
		rbl:              input.RBL,
	}

	if err := services.validate(); err != nil {
		return AuthnHostServices{}, err
	}

	return services, nil
}

// Valid reports whether the bundle is complete and safe for request execution.
func (s AuthnHostServices) Valid() bool {
	return s.validate() == nil
}

// WaitDelay calculates the response delay through the captured brute-force service.
func (s AuthnHostServices) WaitDelay(maxWaitDelay, loginAttempt uint) int {
	if s.bruteForce == nil {
		return 0
	}

	return s.bruteForce.WaitDelay(maxWaitDelay, loginAttempt)
}

// validate rejects partial bundles before a production application can serve requests.
func (s AuthnHostServices) validate() error {
	dependencies := []struct {
		value any
		name  string
	}{
		{value: s.passwordVerifier, name: "password verifier"},
		{value: s.cache, name: "cache service"},
		{value: s.bruteForce, name: "brute-force service"},
		{value: s.subject, name: "subject service"},
		{value: s.rbl, name: "RBL service"},
	}

	for _, dependency := range dependencies {
		if nilAuthnCandidateDependency(dependency.value) {
			return fmt.Errorf("%w: authn host %s", ErrAuthApplicationDependencyMissing, dependency.name)
		}
	}

	return nil
}
