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

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidKeySize = errors.New("crypto: invalid key size")
	ErrDecryption     = errors.New("crypto: decryption failed")
)

// DeriveKey derives a 32-byte key from a secret using SHA-256.
func DeriveKey(secret []byte) []byte {
	hash := sha256.Sum256(secret)
	return hash[:]
}

// Encrypt encrypts data using ChaCha20-Poly1305 and a secret.
func Encrypt(data []byte, secret []byte) ([]byte, error) {
	key := DeriveKey(secret)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends the ciphertext and tag to the nonce.
	return aead.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts data using ChaCha20-Poly1305 and a secret.
func Decrypt(data []byte, secret []byte) ([]byte, error) {
	key := DeriveKey(secret)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrDecryption
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryption
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns the encrypted bytes.
func EncryptString(plaintext string, secret []byte) ([]byte, error) {
	return Encrypt([]byte(plaintext), secret)
}

// DecryptString decrypts bytes and returns the decrypted string.
func DecryptString(ciphertext []byte, secret []byte) (string, error) {
	plaintext, err := Decrypt(ciphertext, secret)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
