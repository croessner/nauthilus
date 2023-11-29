// Copyright 2018 Philipp Brüll (pb@simia.tech)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypt

import "encoding/base64"

// Base64Encoding implements the crypt-specific base63 encoding.
var Base64Encoding = base64.StdEncoding.WithPadding(base64.NoPadding)

const (
	encode24Bit = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// Encode24BitBase64 implements a special version of base64 that is used
// with md5, sha256 and sha512.
func Encode24BitBase64(src []byte) []byte {
	if len(src) == 0 {
		return []byte{} // TODO: return nil
	}

	dstlen := (len(src)*8 + 5) / 6
	dst := make([]byte, dstlen)

	di, si := 0, 0
	n := len(src) / 3 * 3
	for si < n {
		val := uint(src[si+2])<<16 | uint(src[si+1])<<8 | uint(src[si])
		dst[di+0] = encode24Bit[val&0x3f]
		dst[di+1] = encode24Bit[val>>6&0x3f]
		dst[di+2] = encode24Bit[val>>12&0x3f]
		dst[di+3] = encode24Bit[val>>18]
		di += 4
		si += 3
	}

	rem := len(src) - si
	if rem == 0 {
		return dst
	}

	val := uint(src[si+0])
	if rem == 2 {
		val |= uint(src[si+1]) << 8
	}

	dst[di+0] = encode24Bit[val&0x3f]
	dst[di+1] = encode24Bit[val>>6&0x3f]
	if rem == 2 {
		dst[di+2] = encode24Bit[val>>12]
	}
	return dst
}
