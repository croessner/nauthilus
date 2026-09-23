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

// Package redisslot provides Redis Cluster hash-slot helpers and a CROSSSLOT guard for tests.
package redisslot

import "strings"

// SlotCount is the fixed number of Redis Cluster hash slots.
const SlotCount = 16384

// Slot returns the Redis Cluster hash slot of key, honoring the hash-tag rules of the cluster spec.
func Slot(key string) int {
	return int(crc16([]byte(HashTag(key))) % SlotCount)
}

// HashTag returns the part of key that Redis Cluster hashes: the content of the first non-empty
// {...} section, or the whole key when there is none.
func HashTag(key string) string {
	start := strings.IndexByte(key, '{')
	if start < 0 {
		return key
	}

	end := strings.IndexByte(key[start+1:], '}')
	if end <= 0 {
		return key
	}

	return key[start+1 : start+1+end]
}

// crc16 implements CRC-16/XMODEM (polynomial 0x1021, zero initial value) as used by Redis Cluster.
func crc16(data []byte) uint16 {
	var crc uint16

	for _, value := range data {
		crc ^= uint16(value) << 8

		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}

	return crc
}
