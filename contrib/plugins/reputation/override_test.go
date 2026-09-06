package main

import "testing"

// TestOverrideManagementRequiresReadyStorage prevents local management from bypassing durable model activation.
func TestOverrideManagementRequiresReadyStorage(t *testing.T) {
	owner := &stateOwner{}
	subject := subjectInput{kind: kindIP, value: "192.0.2.1"}
	_, err := owner.putOverride(t.Context(), subject, overrideInput{})
	requireError(t, err)
	_, err = owner.getOverride(t.Context(), subject)
	requireError(t, err)
	requireError(t, owner.deleteOverride(t.Context(), subject, "audit"))

	result := owner.assess(t.Context(), subject, profileOperational)
	if result.State != assessmentUnavailable {
		t.Fatal("unready storage produced a usable assessment")
	}
}

// TestOverrideMetadataRejectsControlCharactersAndInvalidLifetimes closes the authentication-independent management boundary.
func TestOverrideMetadataRejectsControlCharactersAndInvalidLifetimes(t *testing.T) {
	valid := overrideInput{Band: bandBlocked, Reason: "operator.block", Creator: "operator", AuditID: "audit", Origin: "operator"}
	requireNoError(t, valid.validate())

	cases := []func(*overrideInput){
		func(i *overrideInput) { i.Creator = "operator\nforged" },
		func(i *overrideInput) { i.AuditID = "\xff" },
		func(i *overrideInput) { i.Band = bandPositive },
		func(i *overrideInput) { i.TTL = -1 },
		func(i *overrideInput) { i.TTL = maximumRetention + 1 },
	}
	for _, mutate := range cases {
		input := valid
		mutate(&input)
		requireError(t, input.validate())
	}
}
