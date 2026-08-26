// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

type ldapLookupQueueProbe struct{}

func (*ldapLookupQueueProbe) Push(*bktype.LDAPRequest, int) {}

type ldapAuthQueueProbe struct{}

func (*ldapAuthQueueProbe) Push(*bktype.LDAPAuthRequest, int) {}

func TestLDAPManagerRequiresAndKeepsExplicitQueues(t *testing.T) {
	backend := &config.Backend{}
	if err := backend.Set(definitions.BackendLDAPName); err != nil {
		t.Fatalf("configure LDAP backend: %v", err)
	}

	cfg := &config.FileSettings{Server: &config.ServerSection{Backends: []*config.Backend{backend}}}
	lookup := &ldapLookupQueueProbe{}
	authentication := &ldapAuthQueueProbe{}

	if err := validateAuthApplicationLDAPQueues(AuthDeps{Cfg: cfg}); err == nil {
		t.Fatal("LDAP configuration accepted missing injected queues")
	}

	if err := validateAuthApplicationLDAPQueues(AuthDeps{Cfg: cfg, LDAPQueue: lookup}); err == nil {
		t.Fatal("LDAP configuration accepted missing authentication queue")
	}

	deps := AuthDeps{Cfg: cfg, LDAPQueue: lookup, LDAPAuthQueue: authentication}
	if err := validateAuthApplicationLDAPQueues(deps); err != nil {
		t.Fatalf("validate explicit LDAP queues: %v", err)
	}

	manager := NewLDAPManager("test", deps).(*ldapManagerImpl)
	if manager.ldapQueue() != lookup {
		t.Fatal("LDAP manager did not retain the injected lookup queue")
	}

	if manager.ldapAuthQueue() != authentication {
		t.Fatal("LDAP manager did not retain the injected authentication queue")
	}
}
