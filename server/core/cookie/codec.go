// Copyright (C) 2025 Christian Rößner
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

package cookie

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrInvalidCookie indicates the cookie value is malformed or tampered.
	ErrInvalidCookie = errors.New("cookie: invalid or tampered cookie")

	// ErrExpiredCookie indicates the cookie has exceeded its maximum age.
	ErrExpiredCookie = errors.New("cookie: expired cookie")
)

// SecureCodec provides authenticated encryption for cookie values using
// ChaCha20-Poly1305 for encryption and HMAC-SHA256 for name binding.
//
// The encoding format is:
// base64(hmac(16 bytes) + timestamp(8 bytes) + nonce(12 bytes) + ciphertext)
//
// Key derivation:
// - encKey = SHA256(secret)[:32] used for ChaCha20-Poly1305
// - authKey = SHA256(secret + "_auth")[:32] used for HMAC
type SecureCodec struct {
	encKey  []byte
	authKey []byte
	maxAge  int // Maximum age in seconds (0 = no expiry check)
}

// NewSecureCodec creates a new codec from a secret byte slice.
// The secret is used to derive encryption and authentication keys via SHA256.
func NewSecureCodec(secret []byte) *SecureCodec {
	// Derive encryption key.
	encHash := sha256.Sum256(secret)
	// Derive authentication key (different from encryption key).
	authInput := make([]byte, 0, len(secret)+len("_auth"))
	authInput = append(authInput, secret...)
	authInput = append(authInput, "_auth"...)
	authHash := sha256.Sum256(authInput)
	clear(authInput)

	return &SecureCodec{
		encKey:  encHash[:],
		authKey: authHash[:],
		maxAge:  86400 * 7, // Default 7 days
	}
}

// SetMaxAge sets the maximum age in seconds for encoded cookies.
// Use 0 to disable timestamp validation.
func (c *SecureCodec) SetMaxAge(maxAge int) {
	c.maxAge = maxAge
}

// Encode serializes and encrypts the value, binding it to the cookie name.
// Returns a base64-encoded string suitable for HTTP cookies.
func (c *SecureCodec) Encode(name string, value any) (string, error) {
	// Serialize value using gob.
	var buf bytes.Buffer

	if err := gob.NewEncoder(&buf).Encode(value); err != nil {
		return "", err
	}

	plaintext := buf.Bytes()

	// Create AEAD cipher.
	aead, err := chacha20poly1305.New(c.encKey)
	if err != nil {
		return "", err
	}

	// Generate random nonce.
	nonce := make([]byte, aead.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt plaintext.
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Build payload: timestamp + nonce + ciphertext.
	timestamp := time.Now().Unix()
	payload := make([]byte, 8+len(nonce)+len(ciphertext))

	// Encode timestamp (big-endian).
	payload[0] = byte(timestamp >> 56)
	payload[1] = byte(timestamp >> 48)
	payload[2] = byte(timestamp >> 40)
	payload[3] = byte(timestamp >> 32)
	payload[4] = byte(timestamp >> 24)
	payload[5] = byte(timestamp >> 16)
	payload[6] = byte(timestamp >> 8)
	payload[7] = byte(timestamp)

	// Copy nonce and ciphertext.
	copy(payload[8:], nonce)
	copy(payload[8+len(nonce):], ciphertext)

	// Compute HMAC over name + payload for cookie binding.
	mac := c.computeMAC(name, payload)

	// Final encoded value: mac + payload.
	result := make([]byte, len(mac)+len(payload))
	copy(result, mac)
	copy(result[len(mac):], payload)

	return base64.RawURLEncoding.EncodeToString(result), nil
}

// Decode decrypts and deserializes the cookie value.
// Returns ErrInvalidCookie if decryption fails or HMAC verification fails.
// Returns ErrExpiredCookie if the timestamp is older than maxAge.
func (c *SecureCodec) Decode(name string, encoded string, dst any) error {
	// Decode base64.
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ErrInvalidCookie
	}

	// Minimum length: 16 (HMAC) + 8 (timestamp) + 12 (nonce) + 16 (min ciphertext with tag).
	if len(data) < 52 {
		return ErrInvalidCookie
	}

	// Extract HMAC and payload.
	mac := data[:16]
	payload := data[16:]

	// Verify HMAC.
	expectedMAC := c.computeMAC(name, payload)

	if !hmac.Equal(mac, expectedMAC) {
		return ErrInvalidCookie
	}

	// Extract timestamp.
	timestamp := int64(payload[0])<<56 | int64(payload[1])<<48 |
		int64(payload[2])<<40 | int64(payload[3])<<32 |
		int64(payload[4])<<24 | int64(payload[5])<<16 |
		int64(payload[6])<<8 | int64(payload[7])

	// Check expiry.
	if c.maxAge > 0 {
		if time.Now().Unix()-timestamp > int64(c.maxAge) {
			return ErrExpiredCookie
		}
	}

	// Create AEAD cipher.
	aead, err := chacha20poly1305.New(c.encKey)
	if err != nil {
		return err
	}

	nonceSize := aead.NonceSize()

	if len(payload) < 8+nonceSize+aead.Overhead() {
		return ErrInvalidCookie
	}

	nonce := payload[8 : 8+nonceSize]
	ciphertext := payload[8+nonceSize:]

	// Decrypt.
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ErrInvalidCookie
	}

	// Deserialize.
	return gob.NewDecoder(bytes.NewReader(plaintext)).Decode(dst)
}

// computeMAC computes a truncated HMAC-SHA256 over the cookie name and payload.
func (c *SecureCodec) computeMAC(name string, payload []byte) []byte {
	h := hmac.New(sha256.New, c.authKey)
	h.Write([]byte(name))
	h.Write(payload)

	// Truncate to 16 bytes for space efficiency.
	return h.Sum(nil)[:16]
}
