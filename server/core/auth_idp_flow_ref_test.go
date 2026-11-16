// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import "testing"

// TestApplyAuthIDPContextKeepsFlowRefWithoutOtherProtocolFacts reproduces the SAML-shaped password request that carries
// only the analytics flow reference: the reference must still reach the request state the post-action snapshot reads.
func TestApplyAuthIDPContextKeepsFlowRefWithoutOtherProtocolFacts(t *testing.T) {
	const flowRef = "0123456789abcdef0123456789abcdef"

	for name, request := range map[string]IDPRequestContext{
		"flow only":  {FlowRef: flowRef},
		"with grant": {FlowRef: flowRef, GrantType: "authorization_code"},
	} {
		t.Run(name, func(t *testing.T) {
			auth := &AuthState{}
			applyAuthIDPContext(auth, NewAuthIDPContext(request, nil, RemoteBackendRef{}))

			if auth.Runtime.IDPContext == nil || auth.Runtime.IDPContext.FlowRef != flowRef {
				t.Fatalf("IDPContext = %#v, want flow reference %q", auth.Runtime.IDPContext, flowRef)
			}
		})
	}
}
