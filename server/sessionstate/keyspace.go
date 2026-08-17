// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionstate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const minimumDigestSecretBytes = 32

// Keyspace derives non-disclosing Redis Cluster keys from opaque handles.
type Keyspace struct {
	prefix string
	secret []byte
}

// NewKeyspace creates a keyed-digest namespace for durable browser-session records.
func NewKeyspace(prefix string, secret []byte) (Keyspace, error) {
	if len(secret) < minimumDigestSecretBytes {
		return Keyspace{}, fmt.Errorf("session keyspace: digest secret must contain at least %d bytes", minimumDigestSecretBytes)
	}

	prefix = strings.Trim(prefix, ":")
	if prefix == "" {
		return Keyspace{}, fmt.Errorf("session keyspace: empty prefix")
	}

	secretCopy := append([]byte(nil), secret...)

	return Keyspace{prefix: prefix, secret: secretCopy}, nil
}

// Key returns a namespaced record key whose hash tag is shared by one browser session.
func (k Keyspace) Key(owner Owner, reference Reference) (string, error) {
	if owner == "" || owner == OwnerEnvelope || owner == OwnerDeletion {
		return "", fmt.Errorf("session keyspace: invalid record owner")
	}

	if err := validateReference(reference); err != nil {
		return "", err
	}

	sessionDigest := k.digest(reference.Session)
	recordDigest := k.digest(reference.Record)

	return fmt.Sprintf("%s:{%s}:%s:%s", k.prefix, sessionDigest, owner, recordDigest), nil
}

// RedisClusterHashTag returns the explicit cluster hash tag from a derived key.
func RedisClusterHashTag(key string) string {
	start := strings.IndexByte(key, '{')
	if start < 0 {
		return ""
	}

	remaining := key[start+1:]

	end := strings.IndexByte(remaining, '}')
	if end < 0 {
		return ""
	}

	return remaining[:end]
}

// digest returns a keyed digest and never exposes its raw handle input.
func (k Keyspace) digest(handle Handle) string {
	mac := hmac.New(sha256.New, k.secret)
	_, _ = mac.Write([]byte(handle))

	return hex.EncodeToString(mac.Sum(nil))
}

// validateReference requires canonical session and record handles.
func validateReference(reference Reference) error {
	if err := validateHandle(reference.Session); err != nil {
		return fmt.Errorf("session reference: invalid session: %w", err)
	}

	if err := validateHandle(reference.Record); err != nil {
		return fmt.Errorf("session reference: invalid record: %w", err)
	}

	return nil
}
