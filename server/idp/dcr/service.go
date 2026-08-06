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

package dcr

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
)

const clientIDRandomBytes = 32

// RegistrationService validates and persists effective native-client registrations.
type RegistrationService struct {
	repository *Repository
	policy     config.OIDCDynamicClientRegistrationConfig
	now        func() time.Time
	random     func([]byte) (int, error)
}

// NewRegistrationService creates a registration service for one validated profile.
func NewRegistrationService(repository *Repository, policy config.OIDCDynamicClientRegistrationConfig) *RegistrationService {
	return &RegistrationService{repository: repository, policy: policy, now: time.Now, random: rand.Read}
}

// ReserveAttempt consumes source and global budget before metadata parsing.
func (s *RegistrationService) ReserveAttempt(ctx context.Context, source string) error {
	if s == nil || s.repository == nil {
		return ErrUnavailable
	}

	return s.repository.ReserveAttempt(ctx, s.sourceHash(source), s.policy.GetLimits())
}

// Register creates one dynamic client from effective metadata and a privacy-safe source identifier.
func (s *RegistrationService) Register(ctx context.Context, metadata EffectiveMetadata, source string) (RegistrationResponse, error) {
	if s == nil || s.repository == nil {
		return RegistrationResponse{}, ErrUnavailable
	}

	sourceHash := s.sourceHash(source)
	for range 3 {
		clientID, err := s.generateClientID()
		if err != nil {
			return RegistrationResponse{}, fmt.Errorf("generate client id: %w", err)
		}

		now := s.now().UTC()
		record := &DynamicClientRecord{
			EffectiveMetadata: metadata,
			ClientID:          clientID,
			Profile:           s.policy.GetProfile(),
			SourceHash:        sourceHash,
			ProfileVersion:    s.policy.GetProfileVersion(),
			RequiredMFALevel:  s.policy.RequiredMFALevel,
			CreatedAt:         now,
			AccessTokenTTL:    s.policy.GetAccessTokenLifetime(),
			RefreshTokenTTL:   s.policy.GetRefreshTokenLifetime(),
		}

		err = s.repository.Register(ctx, record, s.policy.GetLimits())
		if err == nil {
			return record.Response(), nil
		}

		if !errors.Is(err, errClientIDCollision) {
			return RegistrationResponse{}, err
		}
	}

	return RegistrationResponse{}, fmt.Errorf("client id collision retry exhausted")
}

// generateClientID creates an unguessable unpadded base64url client identifier.
func (s *RegistrationService) generateClientID() (string, error) {
	randomBytes := make([]byte, clientIDRandomBytes)
	if _, err := s.random(randomBytes); err != nil {
		return "", err
	}

	return ClientIDPrefix + base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

// sourceHash pseudonymizes a canonical source with the operator-owned HMAC key.
func (s *RegistrationService) sourceHash(source string) string {
	var digest []byte

	s.policy.SourceHMACKey.WithBytes(func(key []byte) {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(source))
		digest = mac.Sum(nil)
	})

	return base64.RawURLEncoding.EncodeToString(digest)
}
