// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type bindingGolden struct {
	Hop struct {
		SignerDomain        string   `json:"signer_domain"`
		SignatureAlgorithms []string `json:"signature_algorithms"`
		SignatureState      string   `json:"signature_state"`
		CustodyTransition   string   `json:"custody_transition"`
		RecipeMode          string   `json:"recipe_mode"`
		RecipeBodyMode      string   `json:"recipe_body_mode"`
		ChangeClasses       []string `json:"change_classes"`
		AffectedHeaders     []string `json:"affected_headers"`
		HistoryHeaderState  string   `json:"history_header_state"`
		HistoryBodyState    string   `json:"history_body_state"`
		BodyAvailability    string   `json:"body_availability"`
		Sequence            int64    `json:"sequence"`
		MessageInstance     int64    `json:"message_instance"`
		ChangeCount         int64    `json:"change_count"`
		AffectedHeaderCount int64    `json:"affected_header_count"`
		DoNotModify         bool     `json:"do_not_modify"`
		DoNotExplode        bool     `json:"do_not_explode"`
		Feedback            bool     `json:"feedback"`
		FeedHere            bool     `json:"feed_here"`
		Exploded            bool     `json:"exploded"`
		RecipeHasHeaders    bool     `json:"recipe_has_header_changes"`
	} `json:"hop"`
	Expected struct {
		Recipe     string `json:"recipe_descriptor_digest_base64"`
		Hop        string `json:"hop_content_digest_base64"`
		Projection string `json:"projection_binding_base64"`
		BoundHop   string `json:"hop_binding_base64"`
	} `json:"expected"`
}

func TestBindingMatchesDKIM2ProducerGolden(t *testing.T) {
	fixture := readBindingGolden(t)
	hop := goldenHop(t, fixture)
	recipe := calculateRecipeDescriptorDigest(hop)
	hop.recipeDigest = recipe[:]
	hopContent := calculateHopContentDigest(hop)
	projection := calculateProjectionBinding([]verifierHop{hop})
	boundHop := calculateBoundHopBinding(projection, hop)

	assertGoldenDigest(t, "recipe", recipe[:], fixture.Expected.Recipe)
	assertGoldenDigest(t, "hop content", hopContent[:], fixture.Expected.Hop)
	assertGoldenDigest(t, "projection", projection[:], fixture.Expected.Projection)
	assertGoldenDigest(t, "bound hop", boundHop[:], fixture.Expected.BoundHop)
}

func TestBindingRejectsEveryBoundSemanticMutation(t *testing.T) {
	fixture := readBindingGolden(t)
	hop := goldenHop(t, fixture)
	recipe := calculateRecipeDescriptorDigest(hop)
	hop.recipeDigest = recipe[:]
	projection := calculateProjectionBinding([]verifierHop{hop})
	bound := calculateBoundHopBinding(projection, hop)
	hop.hopBinding = bound[:]

	tests := []struct {
		name   string
		mutate func(*verifierHop)
	}{
		{name: "signature state", mutate: func(value *verifierHop) { value.signatureState = "fail" }},
		{name: "Recipe header presence", mutate: func(value *verifierHop) { value.recipeHasHeaders = false }},
		{name: "Recipe body mode", mutate: func(value *verifierHop) { value.recipeBodyMode = stateUnavailable }},
		{name: "change classes", mutate: func(value *verifierHop) { value.changeClasses = []string{"body.rewrite"} }},
		{name: "affected headers", mutate: func(value *verifierHop) { value.affectedHeaders = []string{"subject"} }},
		{name: "change count", mutate: func(value *verifierHop) { value.changeCount++ }},
		{name: "affected header count", mutate: func(value *verifierHop) { value.affectedHeaderCount++ }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := hop
			test.mutate(&candidate)

			if validProjectionBindings(projection[:], []verifierHop{candidate}) {
				t.Fatal("validProjectionBindings() accepted a semantic mutation")
			}
		})
	}
}

// readBindingGolden reads the byte-for-byte fixture shared with the DKIM2 producer.
func readBindingGolden(t *testing.T) bindingGolden {
	t.Helper()

	payload, err := os.ReadFile("testdata/verifier-projection-v1-binding.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var fixture bindingGolden
	if err = json.Unmarshal(payload, &fixture); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	return fixture
}

// goldenHop maps the shared JSON fields into the plugin's immutable semantic model.
func goldenHop(t *testing.T, fixture bindingGolden) verifierHop {
	t.Helper()

	return verifierHop{
		signerDomain: fixture.Hop.SignerDomain, signatureAlgorithms: fixture.Hop.SignatureAlgorithms,
		signatureState: fixture.Hop.SignatureState, custodyTransition: fixture.Hop.CustodyTransition,
		recipeMode: fixture.Hop.RecipeMode, recipeBodyMode: fixture.Hop.RecipeBodyMode,
		changeClasses: fixture.Hop.ChangeClasses, affectedHeaders: fixture.Hop.AffectedHeaders,
		historyHeaderState: fixture.Hop.HistoryHeaderState, historyBodyState: fixture.Hop.HistoryBodyState,
		bodyAvailability: fixture.Hop.BodyAvailability, sequence: fixture.Hop.Sequence,
		messageInstance: fixture.Hop.MessageInstance, changeCount: fixture.Hop.ChangeCount,
		affectedHeaderCount: fixture.Hop.AffectedHeaderCount, doNotModify: fixture.Hop.DoNotModify,
		doNotExplode: fixture.Hop.DoNotExplode, feedback: fixture.Hop.Feedback, feedHere: fixture.Hop.FeedHere,
		exploded: fixture.Hop.Exploded, recipeHasHeaders: fixture.Hop.RecipeHasHeaders,
	}
}

// assertGoldenDigest compares one calculated digest with the producer-owned base64 value.
func assertGoldenDigest(t *testing.T, name string, actual []byte, encoded string) {
	t.Helper()

	expected, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString(%s) error = %v", name, err)
	}

	if string(actual) != string(expected) {
		t.Fatalf("%s digest = %s, want %s", name, base64.StdEncoding.EncodeToString(actual), encoded)
	}
}
