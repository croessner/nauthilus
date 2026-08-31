// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

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

// validProjectionBindings recomputes public canonical frames solely to verify coherence.
func validProjectionBindings(projectionBinding []byte, hops []verifierHop) bool {
	expectedProjection := calculateProjectionBinding(hops)
	if !bytes.Equal(projectionBinding, expectedProjection[:]) {
		return false
	}

	for _, hop := range hops {
		expectedRecipe := calculateRecipeDescriptorDigest(hop)
		if !bytes.Equal(hop.recipeDigest, expectedRecipe[:]) {
			return false
		}

		expectedHop := calculateBoundHopBinding(expectedProjection, hop)
		if !bytes.Equal(hop.hopBinding, expectedHop[:]) {
			return false
		}
	}

	return true
}

// calculateProjectionBinding hashes the exact ordered base-hop content digest set.
func calculateProjectionBinding(hops []verifierHop) [sha256.Size]byte {
	frame := appendBindingField(nil, []byte(projectionBindingDomain))
	frame = appendBindingField(frame, []byte(projectionSchema))
	frame = appendBindingField(frame, []byte(draftVersion))
	frame = appendBindingUint64(frame, uint64(len(hops)))

	for _, hop := range hops {
		digest := calculateHopContentDigest(hop)
		frame = appendBindingField(frame, digest[:])
	}

	return sha256.Sum256(frame)
}

// calculateHopContentDigest hashes one exact verifier record without its bindings.
func calculateHopContentDigest(hop verifierHop) [sha256.Size]byte {
	frame := appendBindingField(nil, []byte(hopContentBindingDomain))
	frame = appendBindingUint64(frame, uint64(hop.sequence))
	frame = appendBindingUint64(frame, uint64(hop.messageInstance))
	frame = appendBindingField(frame, []byte(hop.signerDomain))
	frame = appendBindingStrings(frame, hop.signatureAlgorithms)
	frame = appendBindingField(frame, []byte(hop.signatureState))
	frame = appendBindingField(frame, []byte(hop.custodyTransition))
	frame = appendBindingFlags(frame, hop)
	frame = appendBindingField(frame, []byte(hop.recipeMode))
	frame = appendBindingBoolean(frame, hop.recipeHasHeaders)
	frame = appendBindingField(frame, []byte(hop.recipeBodyMode))
	frame = appendBindingField(frame, hop.recipeDigest)
	frame = appendBindingStrings(frame, hop.changeClasses)
	frame = appendBindingStrings(frame, hop.affectedHeaders)
	frame = appendBindingUint64(frame, uint64(hop.changeCount))
	frame = appendBindingUint64(frame, uint64(hop.affectedHeaderCount))
	frame = appendBindingField(frame, []byte(hop.historyHeaderState))
	frame = appendBindingField(frame, []byte(hop.historyBodyState))
	frame = appendBindingField(frame, []byte(hop.bodyAvailability))

	return sha256.Sum256(frame)
}

// calculateRecipeDescriptorDigest validates the producer's exposed normalized descriptor.
func calculateRecipeDescriptorDigest(hop verifierHop) [sha256.Size]byte {
	frame := appendBindingField(nil, []byte(recipeDescriptorDomain))
	frame = appendBindingField(frame, []byte(hop.recipeBodyMode))
	frame = appendBindingUint64(frame, uint64(len(hop.affectedHeaders)))

	for _, header := range hop.affectedHeaders {
		frame = appendBindingField(frame, []byte(header))
	}

	frame = appendBindingUint64(frame, uint64(len(hop.changeClasses)))
	for _, change := range hop.changeClasses {
		frame = appendBindingField(frame, []byte(change))
	}

	return sha256.Sum256(frame)
}

// calculateBoundHopBinding binds one hop digest to the complete projection digest.
func calculateBoundHopBinding(projection [sha256.Size]byte, hop verifierHop) [sha256.Size]byte {
	digest := calculateHopContentDigest(hop)
	frame := appendBindingField(nil, []byte(boundHopBindingDomain))
	frame = appendBindingField(frame, projection[:])
	frame = appendBindingUint64(frame, uint64(hop.sequence))
	frame = appendBindingField(frame, digest[:])

	return sha256.Sum256(frame)
}

// appendBindingFlags writes authenticated flags in the producer's fixed order.
func appendBindingFlags(output []byte, hop verifierHop) []byte {
	for _, value := range []bool{hop.doNotModify, hop.doNotExplode, hop.feedback, hop.feedHere, hop.exploded} {
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
