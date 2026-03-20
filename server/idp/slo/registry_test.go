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

package slo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
)

func TestSessionRegistry_UpsertParticipant(t *testing.T) {
	db, mock := redismock.NewClientMock()
	registry := NewSessionRegistry(db, "test:")

	session := &ParticipantSession{
		Account:      "alice",
		SPEntityID:   "https://sp.example.com",
		NameID:       "alice@example.com",
		SessionIndex: "_saml-session-index",
		AuthnInstant: time.Date(2026, time.March, 18, 12, 0, 0, 0, time.UTC),
	}

	ttl := 2 * time.Hour
	participantKey := registry.participantKey(session.Account, session.SPEntityID)
	indexKey := registry.accountIndexKey(session.Account)
	expectedRaw, err := jsoniter.ConfigFastest.Marshal(session)
	if !assert.NoError(t, err) {
		return
	}

	mock.ExpectSet(participantKey, expectedRaw, ttl).SetVal("OK")
	mock.ExpectSAdd(indexKey, participantKey).SetVal(1)
	mock.ExpectExpireNX(indexKey, ttl).SetVal(true)
	mock.ExpectExpireGT(indexKey, ttl).SetVal(true)

	err = registry.UpsertParticipant(context.Background(), session, ttl)
	if !assert.NoError(t, err) {
		return
	}

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSessionRegistry_UpsertParticipant_InvalidInput(t *testing.T) {
	db, _ := redismock.NewClientMock()
	registry := NewSessionRegistry(db, "test:")

	tests := []struct {
		name    string
		session *ParticipantSession
		ttl     time.Duration
		wantErr error
	}{
		{
			name: "empty account",
			session: &ParticipantSession{
				SPEntityID: "https://sp.example.com",
			},
			ttl:     time.Hour,
			wantErr: ErrEmptyAccount,
		},
		{
			name: "empty sp entity id",
			session: &ParticipantSession{
				Account: "alice",
			},
			ttl:     time.Hour,
			wantErr: ErrEmptySPEntityID,
		},
		{
			name: "invalid ttl",
			session: &ParticipantSession{
				Account:    "alice",
				SPEntityID: "https://sp.example.com",
			},
			ttl:     0,
			wantErr: ErrInvalidTTL,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := registry.UpsertParticipant(context.Background(), tc.session, tc.ttl)
			assert.Error(t, err)
			assert.True(t, errors.Is(err, tc.wantErr))
		})
	}
}

func TestSessionRegistry_LookupParticipants(t *testing.T) {
	db, mock := redismock.NewClientMock()
	registry := NewSessionRegistry(db, "test:")
	ctx := context.Background()

	account := "alice"
	indexKey := registry.accountIndexKey(account)

	record1 := ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp1.example.com",
		NameID:       "alice@example.com",
		SessionIndex: "_idx_1",
		AuthnInstant: time.Date(2026, time.March, 18, 10, 0, 0, 0, time.UTC),
	}
	record2 := ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp2.example.com",
		NameID:       "alice@example.com",
		SessionIndex: "_idx_2",
		AuthnInstant: time.Date(2026, time.March, 18, 10, 30, 0, 0, time.UTC),
	}

	record1Raw, err := jsoniter.ConfigFastest.Marshal(record1)
	if !assert.NoError(t, err) {
		return
	}

	record2Raw, err := jsoniter.ConfigFastest.Marshal(record2)
	if !assert.NoError(t, err) {
		return
	}

	key1 := registry.participantKey(account, record1.SPEntityID)
	key2 := registry.participantKey(account, record2.SPEntityID)

	mock.ExpectSMembers(indexKey).SetVal([]string{key1, key2})
	mock.ExpectGet(key1).SetVal(string(record1Raw))
	mock.ExpectGet(key2).SetVal(string(record2Raw))

	result, err := registry.LookupParticipants(ctx, account)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.Len(t, result, 2) {
		return
	}

	assert.Equal(t, record1.SPEntityID, result[0].SPEntityID)
	assert.Equal(t, record2.SPEntityID, result[1].SPEntityID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSessionRegistry_LookupParticipants_RemovesStaleIndexMembers(t *testing.T) {
	db, mock := redismock.NewClientMock()
	registry := NewSessionRegistry(db, "test:")
	ctx := context.Background()

	account := "alice"
	indexKey := registry.accountIndexKey(account)

	record := ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp2.example.com",
		NameID:       "alice@example.com",
		SessionIndex: "_idx_2",
		AuthnInstant: time.Date(2026, time.March, 18, 10, 30, 0, 0, time.UTC),
	}

	recordRaw, err := jsoniter.ConfigFastest.Marshal(record)
	if !assert.NoError(t, err) {
		return
	}

	staleKey := registry.participantKey(account, "https://sp1.example.com")
	validKey := registry.participantKey(account, record.SPEntityID)

	mock.ExpectSMembers(indexKey).SetVal([]string{staleKey, validKey})
	mock.ExpectGet(staleKey).RedisNil()
	mock.ExpectGet(validKey).SetVal(string(recordRaw))
	mock.ExpectSRem(indexKey, staleKey).SetVal(1)

	result, err := registry.LookupParticipants(ctx, account)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.Len(t, result, 1) {
		return
	}

	assert.Equal(t, record.SPEntityID, result[0].SPEntityID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSessionRegistry_DeleteParticipant(t *testing.T) {
	db, mock := redismock.NewClientMock()
	registry := NewSessionRegistry(db, "test:")
	ctx := context.Background()

	account := "alice"
	spEntityID := "https://sp.example.com"
	participantKey := registry.participantKey(account, spEntityID)
	indexKey := registry.accountIndexKey(account)

	mock.ExpectDel(participantKey).SetVal(1)
	mock.ExpectSRem(indexKey, participantKey).SetVal(1)

	err := registry.DeleteParticipant(ctx, account, spEntityID)
	if !assert.NoError(t, err) {
		return
	}

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSessionRegistry_DeleteAccount(t *testing.T) {
	db, mock := redismock.NewClientMock()
	registry := NewSessionRegistry(db, "test:")
	ctx := context.Background()

	account := "alice"
	indexKey := registry.accountIndexKey(account)
	key1 := registry.participantKey(account, "https://sp1.example.com")
	key2 := registry.participantKey(account, "https://sp2.example.com")

	mock.ExpectSMembers(indexKey).SetVal([]string{key1, key2})
	mock.ExpectDel(key1).SetVal(1)
	mock.ExpectDel(key2).SetVal(1)
	mock.ExpectDel(indexKey).SetVal(1)

	err := registry.DeleteAccount(ctx, account)
	if !assert.NoError(t, err) {
		return
	}

	assert.NoError(t, mock.ExpectationsWereMet())
}
