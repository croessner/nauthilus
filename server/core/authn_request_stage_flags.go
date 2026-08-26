// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import "github.com/croessner/nauthilus/v3/server/definitions"

// AuthnRequestStageFlags describes request-observed authn stage availability.
type AuthnRequestStageFlags struct {
	EnvironmentRejected      bool
	EnvironmentStageExpected bool
	SubjectStageExpected     bool
}

// AuthnRequestStageFlags derives stage visibility only from the captured request state.
func (a *AuthState) AuthnRequestStageFlags() AuthnRequestStageFlags {
	if a == nil {
		return AuthnRequestStageFlags{}
	}

	rejected := false
	if a.Request.HTTPClientContext != nil {
		rejected = a.Request.HTTPClientContext.GetBool(definitions.CtxEnvironmentRejectedKey)
	}

	flags := AuthnRequestStageFlags{
		EnvironmentRejected:      rejected,
		EnvironmentStageExpected: true,
		SubjectStageExpected:     !rejected,
	}
	if rejected && a.Runtime.EnvironmentName == definitions.ControlBruteForce {
		flags.EnvironmentStageExpected = false
	}

	return flags
}
