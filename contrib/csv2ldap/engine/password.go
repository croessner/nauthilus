// Copyright (C) 2024 Christian Rößner
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

package engine

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"

	srvdefs "github.com/croessner/nauthilus/server/definitions"
	srvutil "github.com/croessner/nauthilus/server/util"

	"golang.org/x/crypto/argon2"
)

// PasswordEncoder abstracts password formatting for LDIF.
type PasswordEncoder interface {
	Encode(plain string) (string, error)
}

// --- SHA encoder (unsalted SHA-1) ---

// SHAEncoder renders passwords as LDAP-style {SHA} digests.
// It computes SHA-1 over the plain text password without a salt.
// The payload can be encoded as base64 (default) or hex to match
// the SSHA encoder behavior when Encoding is set to "hex".
//
// Output format examples:
// - Base64 (default): {SHA}BASE64(SHA1(password))
// - Hex:              {SHA.HEX}HEX(SHA1(password))
type SHAEncoder struct {
	// Encoding: "b64" or "hex" (default b64)
	Encoding string
}

func (e *SHAEncoder) Encode(plain string) (string, error) {
	sum := sha1.Sum([]byte(plain))

	// Choose encoding
	enc := lower(e.Encoding)
	switch enc {
	case "", "b64":
		payload := base64.StdEncoding.EncodeToString(sum[:])

		return "{SHA}" + payload, nil
	case "hex":
		// inline hex without importing encoding/hex to keep surface small
		hex := make([]byte, len(sum)*2)
		const hexdigits = "0123456789abcdef"

		for i, b := range sum {
			hex[i*2] = hexdigits[b>>4]
			hex[i*2+1] = hexdigits[b&0x0F]
		}

		return "{SHA.HEX}" + string(hex), nil
	default:
		return "", fmt.Errorf("unsupported SHA encoding: %s", e.Encoding)
	}
}

// --- SSHA encoder (256/512) ---

type SSHAEncoder struct {
	// Alg must be "ssha256" or "ssha512"
	Alg string
	// Encoding: "b64" or "hex" (default b64)
	Encoding string
	// SaltLength in bytes (default 8)
	SaltLength int
}

func (e *SSHAEncoder) Encode(plain string) (string, error) {
	var alg srvdefs.Algorithm

	switch lower(e.Alg) {
	case "ssha256":
		alg = srvdefs.SSHA256
	case "ssha512", "":
		alg = srvdefs.SSHA512
	default:
		return "", fmt.Errorf("unsupported SSHA alg: %s", e.Alg)
	}

	var opt srvdefs.PasswordOption

	enc := lower(e.Encoding)

	switch enc {
	case "hex":
		opt = srvdefs.ENCHEX
	case "", "b64":
		opt = srvdefs.ENCB64
	default:
		return "", fmt.Errorf("unsupported SSHA encoding: %s", e.Encoding)
	}

	sl := e.SaltLength
	if sl <= 0 {
		sl = 8
	}

	salt := make([]byte, sl)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	cp := &srvutil.CryptPassword{}
	payload, err := cp.Generate(plain, salt, alg, opt)
	if err != nil {
		return "", err
	}

	// Prefix for OpenLDAP compatibility:
	// Base64 (default): {SSHA512}payload or {SSHA256}payload (NO .B64 suffix)
	// Hex:               {SSHA512.HEX}payload or {SSHA256.HEX}payload
	prefix := "{SSHA512}"
	if alg == srvdefs.SSHA256 {
		prefix = "{SSHA256}"
	}

	if opt == srvdefs.ENCHEX {
		if alg == srvdefs.SSHA256 {
			prefix = "{SSHA256.HEX}"
		} else {
			prefix = "{SSHA512.HEX}"
		}
	}

	return prefix + payload, nil
}

// --- Argon2 encoder ---

type Argon2Variant int

const (
	Argon2i Argon2Variant = iota
	Argon2id
)

type Argon2Encoder struct {
	Variant        Argon2Variant // Argon2i or Argon2id
	Time           uint32        // t
	MemoryKiB      uint32        // m in KiB
	Parallelism    uint8         // p
	KeyLen         uint32        // hash length
	OpenLDAPPrefix bool          // if true, prepend {ARGON2}
	SaltLength     int           // default 16 bytes
}

func (e *Argon2Encoder) Encode(plain string) (string, error) {
	sl := e.SaltLength
	if sl <= 0 {
		sl = 16
	}

	salt := make([]byte, sl)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	t := e.Time
	if t == 0 {
		t = 2
	}

	m := e.MemoryKiB
	if m == 0 {
		m = 65536
	}

	p := e.Parallelism
	if p == 0 {
		p = 1
	}

	keyLen := e.KeyLen
	if keyLen == 0 {
		keyLen = 32
	}

	var hash []byte
	var vStr string

	switch e.Variant {
	case Argon2i:
		hash = argon2.Key([]byte(plain), salt, t, m, p, keyLen)
		vStr = "argon2i"
	case Argon2id:
		hash = argon2.IDKey([]byte(plain), salt, t, m, p, keyLen)
		vStr = "argon2id"
	default:
		return "", fmt.Errorf("unsupported argon2 variant")
	}

	// PHC string as used widely and by OpenLDAP's argon2 module
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	phc := fmt.Sprintf("$%s$v=19$m=%d,t=%d,p=%d$%s$%s", vStr, m, t, p, b64Salt, b64Hash)

	if e.OpenLDAPPrefix {
		return "{ARGON2}" + phc, nil
	}

	return phc, nil
}

func lower(s string) string {
	if s == "" {
		return ""
	}

	// simple inline lower without extra import
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}

	return string(b)
}
