// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
)

func TestNormalizeResponseMessageOwnsAttributeDetailFactIdentity(t *testing.T) {
	const baseFact = "nauthilus.auth.plugin.subject.rns_auth.rns_ldap.rejected"

	message, err := normalizeResponseMessage("policy.test.then.response_message", policyconfig.ResponseMessageConfig{
		From:      "attribute_detail",
		Attribute: baseFact,
		Detail:    "status_message",
		Fallback:  "Invalid login or password",
	})
	if err != nil {
		t.Fatalf("normalizeResponseMessage() error = %v", err)
	}

	if got, want := message.FactID(), baseFact+".status_message"; got != want {
		t.Fatalf("response fact = %q, want %q", got, want)
	}
}
