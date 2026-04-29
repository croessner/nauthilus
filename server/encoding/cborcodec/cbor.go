// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package cborcodec centralizes the CBOR policy used by HTTP handlers and Lua helpers.
package cborcodec

import (
	"io"

	"github.com/fxamacker/cbor/v2"
)

const defaultMaxBodyBytes = 1 << 20

var (
	encMode = mustEncMode()
	decMode = mustDecMode()
)

// Marshal encodes v as deterministic CBOR using the shared Nauthilus CBOR policy.
func Marshal(v any) ([]byte, error) {
	return encMode.Marshal(v)
}

// Unmarshal decodes CBOR data into v using the shared Nauthilus CBOR policy.
func Unmarshal(data []byte, v any) error {
	return decMode.Unmarshal(data, v)
}

// DecodeReader reads a bounded CBOR payload from r and decodes it into v.
func DecodeReader(r io.Reader, v any) error {
	return DecodeReaderLimit(r, v, defaultMaxBodyBytes)
}

// DecodeReaderLimit reads at most limit bytes plus one sentinel byte from r and decodes v.
func DecodeReaderLimit(r io.Reader, v any, limit int64) error {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}

	if int64(len(data)) > limit {
		return io.ErrShortBuffer
	}

	return Unmarshal(data, v)
}

func mustEncMode() cbor.EncMode {
	mode, err := cbor.EncOptions{
		Sort:          cbor.SortCoreDeterministic,
		IndefLength:   cbor.IndefLengthForbidden,
		TagsMd:        cbor.TagsForbidden,
		TimeTag:       cbor.EncTagNone,
		NilContainers: cbor.NilContainerAsEmpty,
	}.EncMode()
	if err != nil {
		panic(err)
	}

	return mode
}

func mustDecMode() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		IntDec:            cbor.IntDecConvertSignedOrFail,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxNestedLevels:   32,
		MaxArrayElements:  4096,
		MaxMapPairs:       4096,
	}.DecMode()
	if err != nil {
		panic(err)
	}

	return mode
}
