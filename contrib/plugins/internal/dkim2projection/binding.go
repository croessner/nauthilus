// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package dkim2projection

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

const (
	projectionBindingDomain = "dkim2-verifier-projection-binding-v1"
	hopContentBindingDomain = "dkim2-verifier-hop-binding-v1"
	boundHopBindingDomain   = "dkim2-verifier-bound-hop-v1"
	recipeDescriptorDomain  = "dkim2-recipe-descriptor-v1"
)

// ValidProjectionBindings recomputes public canonical frames solely to verify coherence.
func ValidProjectionBindings(ProjectionBinding []byte, hops []Hop) bool {
	expectedProjection := CalculateProjectionBinding(hops)
	if !bytes.Equal(ProjectionBinding, expectedProjection[:]) {
		return false
	}

	for _, hop := range hops {
		expectedRecipe := CalculateRecipeDescriptorDigest(hop)
		if !bytes.Equal(hop.RecipeDigest, expectedRecipe[:]) {
			return false
		}

		expectedHop := CalculateBoundHopBinding(expectedProjection, hop)
		if !bytes.Equal(hop.HopBinding, expectedHop[:]) {
			return false
		}
	}

	return true
}

// CalculateProjectionBinding hashes the exact ordered base-hop content digest set.
func CalculateProjectionBinding(hops []Hop) [sha256.Size]byte {
	frame := appendBindingField(nil, []byte(projectionBindingDomain))
	frame = appendBindingField(frame, []byte(ProjectionSchema))
	frame = appendBindingField(frame, []byte(DraftVersion))
	frame = appendBindingUint64(frame, uint64(len(hops)))

	for _, hop := range hops {
		digest := CalculateHopContentDigest(hop)
		frame = appendBindingField(frame, digest[:])
	}

	return sha256.Sum256(frame)
}

// CalculateHopContentDigest hashes one exact verifier record without its bindings.
func CalculateHopContentDigest(hop Hop) [sha256.Size]byte {
	frame := appendBindingField(nil, []byte(hopContentBindingDomain))
	frame = appendBindingUint64(frame, uint64(hop.Sequence))
	frame = appendBindingUint64(frame, uint64(hop.MessageInstance))
	frame = appendBindingField(frame, []byte(hop.SignerDomain))
	frame = appendBindingStrings(frame, hop.SignatureAlgorithms)
	frame = appendBindingField(frame, []byte(hop.SignatureState))
	frame = appendBindingField(frame, []byte(hop.CustodyTransition))
	frame = appendBindingFlags(frame, hop)
	frame = appendBindingField(frame, []byte(hop.RecipeMode))
	frame = appendBindingBoolean(frame, hop.RecipeHasHeaders)
	frame = appendBindingField(frame, []byte(hop.RecipeBodyMode))
	frame = appendBindingField(frame, hop.RecipeDigest)
	frame = appendBindingStrings(frame, hop.ChangeClasses)
	frame = appendBindingStrings(frame, hop.AffectedHeaders)
	frame = appendBindingUint64(frame, uint64(hop.ChangeCount))
	frame = appendBindingUint64(frame, uint64(hop.AffectedHeaderCount))
	frame = appendBindingField(frame, []byte(hop.HistoryHeaderState))
	frame = appendBindingField(frame, []byte(hop.HistoryBodyState))
	frame = appendBindingField(frame, []byte(hop.BodyAvailability))

	return sha256.Sum256(frame)
}

// CalculateRecipeDescriptorDigest validates the producer's exposed normalized descriptor.
func CalculateRecipeDescriptorDigest(hop Hop) [sha256.Size]byte {
	frame := appendBindingField(nil, []byte(recipeDescriptorDomain))
	frame = appendBindingField(frame, []byte(hop.RecipeBodyMode))
	frame = appendBindingUint64(frame, uint64(len(hop.AffectedHeaders)))

	for _, header := range hop.AffectedHeaders {
		frame = appendBindingField(frame, []byte(header))
	}

	frame = appendBindingUint64(frame, uint64(len(hop.ChangeClasses)))
	for _, change := range hop.ChangeClasses {
		frame = appendBindingField(frame, []byte(change))
	}

	return sha256.Sum256(frame)
}

// CalculateBoundHopBinding binds one hop digest to the complete projection digest.
func CalculateBoundHopBinding(projection [sha256.Size]byte, hop Hop) [sha256.Size]byte {
	digest := CalculateHopContentDigest(hop)
	frame := appendBindingField(nil, []byte(boundHopBindingDomain))
	frame = appendBindingField(frame, projection[:])
	frame = appendBindingUint64(frame, uint64(hop.Sequence))
	frame = appendBindingField(frame, digest[:])

	return sha256.Sum256(frame)
}

// appendBindingFlags writes authenticated flags in the producer's fixed order.
func appendBindingFlags(output []byte, hop Hop) []byte {
	for _, value := range []bool{hop.DoNotModify, hop.DoNotExplode, hop.Feedback, hop.FeedHere, hop.Exploded} {
		if value {
			output = append(output, 1)
		} else {
			output = append(output, 0)
		}
	}

	return output
}

// appendBindingBoolean writes one canonical raw boolean byte.
func appendBindingBoolean(output []byte, value bool) []byte {
	if value {
		return append(output, 1)
	}

	return append(output, 0)
}

// appendBindingStrings writes one ordered length-delimited string collection.
func appendBindingStrings(output []byte, values []string) []byte {
	output = appendBindingUint64(output, uint64(len(values)))
	for _, value := range values {
		output = appendBindingField(output, []byte(value))
	}

	return output
}

// appendBindingField writes one network-order length-delimited field.
func appendBindingField(output []byte, value []byte) []byte {
	var length [4]byte

	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	output = append(output, length[:]...)

	return append(output, value...)
}

// appendBindingUint64 writes one network-order unsigned integer.
func appendBindingUint64(output []byte, value uint64) []byte {
	var encoded [8]byte

	binary.BigEndian.PutUint64(encoded[:], value)

	return append(output, encoded[:]...)
}
