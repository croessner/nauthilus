// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package dkim2projection

import "net/netip"

// Projection is an owned, validated semantic verifier projection.
type Projection struct {
	ClientIP              netip.Addr
	ProjectionBinding     []byte
	Chain                 []Hop
	VerificationState     string
	AuthenticationState   string
	Scope                 string
	HistoricalContent     string
	HistoricalSignatures  string
	CustodyStructure      string
	Disposition           string
	DoNotModifyState      string
	DoNotExplodeState     string
	TargetSequence        int64
	TargetMessageInstance int64
	ClaimedHopCount       int64
}

// Hop is one owned, validated and binding-correlated verifier record.
type Hop struct {
	SignerDomain        string
	SignatureAlgorithms []string
	HopBinding          []byte
	RecipeDigest        []byte
	ChangeClasses       []string
	AffectedHeaders     []string
	SignatureState      string
	CustodyTransition   string
	RecipeMode          string
	RecipeBodyMode      string
	HistoryHeaderState  string
	HistoryBodyState    string
	BodyAvailability    string
	Sequence            int64
	MessageInstance     int64
	ChangeCount         int64
	AffectedHeaderCount int64
	DoNotModify         bool
	DoNotExplode        bool
	Feedback            bool
	FeedHere            bool
	Exploded            bool
	RecipeHasHeaders    bool
}
