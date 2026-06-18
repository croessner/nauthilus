// Copyright (C) 2026 Christian Roessner
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

// Package password exposes Nauthilus-compatible password comparison and
// generated short-hash helpers for native Go plugins without importing server
// internals.
package password

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"regexp"
	"strings"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/simia-tech/crypt"
)

// Algorithm identifies supported salted SHA password hash algorithms.
type Algorithm uint8

const (
	// AlgorithmUnknown represents an unsupported password hash algorithm.
	AlgorithmUnknown Algorithm = iota

	// AlgorithmSSHA256 identifies salted SHA-256 password hashes.
	AlgorithmSSHA256

	// AlgorithmSSHA512 identifies salted SHA-512 password hashes.
	AlgorithmSSHA512
)

// Encoding identifies the payload encoding used by salted SHA password hashes.
type Encoding uint8

const (
	// EncodingUnknown represents an unsupported password payload encoding.
	EncodingUnknown Encoding = iota

	// EncodingBase64 stores the hash+salt payload with base64 encoding.
	EncodingBase64

	// EncodingHex stores the hash+salt payload with hexadecimal encoding.
	EncodingHex
)

var (
	// ErrUnsupportedAlgorithm is returned for password hash algorithms outside the public helper contract.
	ErrUnsupportedAlgorithm = errors.New("unsupported hash algorithm")

	// ErrUnsupportedEncoding is returned for password hash payload encodings outside the public helper contract.
	ErrUnsupportedEncoding = errors.New("unsupported password encoding")
)

var passwordPrefixPattern = regexp.MustCompile(`^\{SSHA(256|512)(?:\.(HEX|B64))?}(.+)$`)

// CryptPassword stores parsed or generated salted SHA password material.
type CryptPassword struct {
	Salt      []byte
	Password  string
	Algorithm Algorithm
	Encoding  Encoding
}

// GenerateString creates a salted SHA payload from a plain-text password string.
func (c *CryptPassword) GenerateString(plainPassword string, salt []byte, algorithm Algorithm, encoding Encoding) (string, error) {
	return c.GenerateBytes([]byte(plainPassword), salt, algorithm, encoding)
}

// GenerateBytes creates a salted SHA payload from plain password bytes.
func (c *CryptPassword) GenerateBytes(plainPassword []byte, salt []byte, algorithm Algorithm, encoding Encoding) (string, error) {
	hashValue, err := hashForAlgorithm(algorithm)
	if err != nil {
		return "", err
	}

	if _, err := hashValue.Write(plainPassword); err != nil {
		return "", err
	}

	if _, err := hashValue.Write(salt); err != nil {
		return "", err
	}

	hashSum := hashValue.Sum(nil)
	hashWithSalt := make([]byte, len(hashSum)+len(salt))
	copy(hashWithSalt, hashSum)
	copy(hashWithSalt[len(hashSum):], salt)

	switch encoding {
	case EncodingBase64:
		c.Password = base64.StdEncoding.EncodeToString(hashWithSalt)
	case EncodingHex:
		c.Password = hex.EncodeToString(hashWithSalt)
	default:
		return "", ErrUnsupportedEncoding
	}

	c.Algorithm = algorithm
	c.Encoding = encoding

	c.Salt = append([]byte(nil), salt...)

	return c.Password, nil
}

// GetParameters parses a salted SHA password hash and records the payload metadata.
func (c *CryptPassword) GetParameters(cryptedPassword string) (salt []byte, algorithm Algorithm, encoding Encoding, err error) {
	matches := passwordPrefixPattern.FindStringSubmatch(cryptedPassword)
	if len(matches) != 4 {
		return nil, AlgorithmUnknown, EncodingUnknown, ErrUnsupportedAlgorithm
	}

	algorithm, err = algorithmFromPrefix(matches[1])
	if err != nil {
		return nil, AlgorithmUnknown, EncodingUnknown, err
	}

	encoding, err = encodingFromPrefix(matches[2])
	if err != nil {
		return nil, algorithm, EncodingUnknown, err
	}

	payload := matches[3]

	decoded, err := decodePayload(payload, encoding)
	if err != nil {
		return nil, algorithm, encoding, err
	}

	salt, err = saltFromPayload(decoded, algorithm)
	if err != nil {
		return nil, algorithm, encoding, err
	}

	c.Algorithm = algorithm
	c.Encoding = encoding
	c.Password = payload

	c.Salt = append([]byte(nil), salt...)

	return salt, algorithm, encoding, nil
}

// CompareHash verifies a public plugin secret against a stored Nauthilus-compatible password hash.
func CompareHash(hashPassword string, plainPassword pluginapi.Secret) (bool, error) {
	if plainPassword == nil {
		return false, nil
	}

	var matched bool

	err := plainPassword.WithBytes(func(value []byte) error {
		result, compareErr := CompareHashBytes(hashPassword, value)
		matched = result

		return compareErr
	})
	if err != nil {
		return false, err
	}

	return matched, nil
}

// CompareHashString verifies a plain-text string against a stored Nauthilus-compatible password hash.
func CompareHashString(hashPassword string, plainPassword string) (bool, error) {
	return CompareHashBytes(hashPassword, []byte(plainPassword))
}

// CompareHashBytes verifies plain password bytes against a stored Nauthilus-compatible password hash.
func CompareHashBytes(hashPassword string, plainPassword []byte) (bool, error) {
	if strings.HasPrefix(hashPassword, "{SSHA") {
		return compareSaltedSHA(hashPassword, plainPassword)
	}

	_, _, _, passwordHash, err := crypt.DecodeSettings(hashPassword)
	if err != nil {
		return false, err
	}

	settings, _, found := strings.Cut(hashPassword, passwordHash)
	if !found {
		return false, ErrUnsupportedAlgorithm
	}

	encoded, err := crypt.Crypt(string(plainPassword), settings)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare([]byte(encoded), []byte(hashPassword)) == 1, nil
}

// HashOptions controls generated short password hashes.
type HashOptions struct {
	Nonce   []byte
	DevMode bool
}

// GenerateHash creates the Nauthilus short hash for a public plugin secret.
func GenerateHash(secret pluginapi.Secret, options HashOptions) (string, error) {
	if secret == nil {
		return "", nil
	}

	var hash string

	err := secret.WithBytes(func(value []byte) error {
		hash = GenerateHashBytes(value, options)

		return nil
	})
	if err != nil {
		return "", err
	}

	return hash, nil
}

// GenerateHashString creates the Nauthilus short hash for a plain-text password string.
func GenerateHashString(password string, options HashOptions) string {
	return GenerateHashBytes([]byte(password), options)
}

// GenerateHashBytes creates the Nauthilus short hash for plain password bytes.
func GenerateHashBytes(password []byte, options HashOptions) string {
	prepared := PrepareBytes(password, options.Nonce)
	defer clear(prepared)

	return ShortHash(prepared, options.DevMode)
}

// PrepareBytes applies the Nauthilus password nonce layout before short hashing.
func PrepareBytes(password []byte, nonce []byte) []byte {
	prepared := make([]byte, len(nonce)+1+len(password))
	copy(prepared, nonce)
	prepared[len(nonce)] = 0
	copy(prepared[len(nonce)+1:], password)

	return prepared
}

// ShortHash returns the first eight hex characters of a SHA-256 digest unless dev mode requests raw prepared bytes.
func ShortHash(value []byte, devMode bool) string {
	if devMode {
		return string(value)
	}

	hashValue := sha256.New()
	_, _ = hashValue.Write(value)

	return hex.EncodeToString(hashValue.Sum(nil))[:8]
}

// compareSaltedSHA verifies a salted SHA password hash.
func compareSaltedSHA(hashPassword string, plainPassword []byte) (bool, error) {
	password := &CryptPassword{}

	salt, algorithm, encoding, err := password.GetParameters(hashPassword)
	if err != nil {
		return false, err
	}

	newPassword := &CryptPassword{}
	if _, err := newPassword.GenerateBytes(plainPassword, salt, algorithm, encoding); err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare([]byte(password.Password), []byte(newPassword.Password)) == 1, nil
}

// hashForAlgorithm creates the digest used by a salted SHA password algorithm.
func hashForAlgorithm(algorithm Algorithm) (hash.Hash, error) {
	switch algorithm {
	case AlgorithmSSHA512:
		return sha512.New(), nil
	case AlgorithmSSHA256:
		return sha256.New(), nil
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// algorithmFromPrefix maps the SSHA prefix suffix to the public algorithm value.
func algorithmFromPrefix(value string) (Algorithm, error) {
	switch value {
	case "512":
		return AlgorithmSSHA512, nil
	case "256":
		return AlgorithmSSHA256, nil
	default:
		return AlgorithmUnknown, ErrUnsupportedAlgorithm
	}
}

// encodingFromPrefix maps the optional SSHA encoding suffix to the public encoding value.
func encodingFromPrefix(value string) (Encoding, error) {
	switch value {
	case "HEX":
		return EncodingHex, nil
	case "B64", "":
		return EncodingBase64, nil
	default:
		return EncodingUnknown, ErrUnsupportedEncoding
	}
}

// decodePayload decodes the salted SHA hash+salt payload.
func decodePayload(payload string, encoding Encoding) ([]byte, error) {
	switch encoding {
	case EncodingBase64:
		return base64.StdEncoding.DecodeString(payload)
	case EncodingHex:
		return hex.DecodeString(payload)
	default:
		return nil, ErrUnsupportedEncoding
	}
}

// saltFromPayload extracts the salt after the fixed digest length for the algorithm.
func saltFromPayload(payload []byte, algorithm Algorithm) ([]byte, error) {
	var digestLength int

	switch algorithm {
	case AlgorithmSSHA512:
		digestLength = sha512.Size
	case AlgorithmSSHA256:
		digestLength = sha256.Size
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	if len(payload) <= digestLength {
		return nil, ErrUnsupportedAlgorithm
	}

	return append([]byte(nil), payload[digestLength:]...), nil
}
