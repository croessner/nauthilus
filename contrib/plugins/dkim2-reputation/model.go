// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import "net/netip"

type verifierProjection struct {
	clientIP              netip.Addr
	projectionBinding     []byte
	chain                 []verifierHop
	verificationState     string
	authenticationState   string
	scope                 string
	historicalContent     string
	historicalSignatures  string
	custodyStructure      string
	disposition           string
	doNotModifyState      string
	doNotExplodeState     string
	targetSequence        int64
	targetMessageInstance int64
	claimedHopCount       int64
}

type verifierHop struct {
	signerDomain        string
	signatureAlgorithms []string
	hopBinding          []byte
	recipeDigest        []byte
	changeClasses       []string
	affectedHeaders     []string
	signatureState      string
	custodyTransition   string
	recipeMode          string
	recipeBodyMode      string
	historyHeaderState  string
	historyBodyState    string
	bodyAvailability    string
	sequence            int64
	messageInstance     int64
	changeCount         int64
	affectedHeaderCount int64
	doNotModify         bool
	doNotExplode        bool
	feedback            bool
	feedHere            bool
	exploded            bool
	recipeHasHeaders    bool
}

type hopAssessment struct {
	hop                 verifierHop
	violations          []string
	domainReputation    string
	clientIPReputation  string
	contractState       string
	recipeAuthorization string
	assessmentComplete  bool
	acceptable          bool
}
