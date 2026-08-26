// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"context"
	"errors"
)

var errRawAuthApplicationTestHostInvoked = errors.New("raw auth application test host invoked")

type registeredAuthApplicationTestHost struct {
	*authApplicationService
}

// newRegisteredAuthApplicationServiceHost snapshots explicit test registrations for one private host.
func newRegisteredAuthApplicationServiceHost(deps AuthDeps) *registeredAuthApplicationTestHost {
	return &registeredAuthApplicationTestHost{
		authApplicationService: newAuthApplicationServiceHost(withRegisteredAuthnHostServices(deps)),
	}
}

func (*registeredAuthApplicationTestHost) Authenticate(context.Context, AuthInput) (*AuthOutcome, error) {
	return nil, errRawAuthApplicationTestHostInvoked
}

func (*registeredAuthApplicationTestHost) LookupIdentity(context.Context, AuthInput) (*AuthOutcome, error) {
	return nil, errRawAuthApplicationTestHostInvoked
}

func (*registeredAuthApplicationTestHost) ListAccounts(context.Context, AuthInput) (*ListAccountsOutcome, error) {
	return nil, errRawAuthApplicationTestHostInvoked
}

// bindRegisteredAuthnHostServicesForTest snapshots test registrations onto an existing request owner.
func bindRegisteredAuthnHostServicesForTest(auth *AuthState) {
	if auth == nil {
		return
	}

	auth.deps.HostServices = registeredAuthnHostServices()
}

// bindRegisteredAuthnApplicationHostServicesForTest snapshots test registrations onto an existing application host.
func bindRegisteredAuthnApplicationHostServicesForTest(service AuthApplicationService) {
	host, ok := service.(*registeredAuthApplicationTestHost)
	if !ok || host == nil || host.authApplicationService == nil {
		return
	}

	host.deps.HostServices = registeredAuthnHostServices()
}
