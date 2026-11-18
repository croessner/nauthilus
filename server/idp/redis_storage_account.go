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

package idp

import (
	"context"
	stderrors "errors"
	"slices"
	"time"

	"github.com/redis/go-redis/v9"
)

// BindAccountSubject records that tokens of the session's subject are issued for its backend account.
//
// Token state is keyed by the subject (the backend unique user ID), while operators flush by account name.
// The binding lets FlushAccountTokens find the subject when both differ. Callers write it before any token
// leaves the IdP and pass the longest lifetime of the tokens they issue, so every revocable token stays
// reachable. Service tokens, sessions without account, and subjects named like their account need no
// binding: FlushAccountTokens always revokes the subject named like the account.
func (s *RedisTokenStorage) BindAccountSubject(ctx context.Context, session *OIDCSession, ttl time.Duration) error {
	if !needsAccountSubjectBinding(session) || ttl <= 0 {
		return nil
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.redis.GetWriteHandle().Eval(
		writeCtx,
		accountSubjectBindScript,
		[]string{s.keys.accountSubjects(session.Username)},
		oidcSubjectSlot(session.UserID),
		ttl.Milliseconds(),
	).Err()
}

// needsAccountSubjectBinding reports whether a user session's subject differs from its account name.
func needsAccountSubjectBinding(session *OIDCSession) bool {
	return session != nil && !session.ServiceToken && session.Username != "" && session.UserID != "" &&
		session.Username != session.UserID
}

// FlushAccountTokens revokes every OIDC token issued for one backend account.
//
// It flushes each subject bound to the account and the subject named like the account; the latter covers
// deployments whose unique user ID equals the account name. Flushed subjects leave the binding set, while
// subjects bound concurrently stay for the next flush. A failed binding read fails the flush, so it never
// reports success for subjects it could not see.
func (s *RedisTokenStorage) FlushAccountTokens(ctx context.Context, account string) error {
	if account == "" {
		return nil
	}

	slots, err := s.accountSubjectSlots(ctx, account)
	if err != nil {
		return err
	}

	var (
		result  error
		flushed []any
	)

	for _, slot := range slots {
		if flushErr := s.flushSubject(ctx, s.keys.subjectBySlot(slot)); flushErr != nil {
			result = stderrors.Join(result, flushErr)

			continue
		}

		flushed = append(flushed, slot)
	}

	if !slices.Contains(slots, oidcSubjectSlot(account)) {
		result = stderrors.Join(result, s.flushSubject(ctx, s.keys.subject(account)))
	}

	return stderrors.Join(result, s.unbindAccountSubjects(ctx, account, flushed))
}

// accountSubjectSlots reads the subject slots bound to an account from the authoritative handle.
// Members that are not subject digests are ignored, so a planted value can never redirect key building.
func (s *RedisTokenStorage) accountSubjectSlots(ctx context.Context, account string) ([]string, error) {
	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	members, err := s.redis.GetWriteHandle().SMembers(writeCtx, s.keys.accountSubjects(account)).Result()
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return nil, err
	}

	slots := make([]string, 0, len(members))
	for _, member := range members {
		if isHexDigest(member) {
			slots = append(slots, member)
		}
	}

	slices.Sort(slots)

	return slots, nil
}

// unbindAccountSubjects removes flushed subject slots from the account binding set.
func (s *RedisTokenStorage) unbindAccountSubjects(ctx context.Context, account string, slots []any) error {
	if len(slots) == 0 {
		return nil
	}

	writeCtx, cancel := s.redisWriteContext(ctx)
	defer cancel()

	return s.redis.GetWriteHandle().SRem(writeCtx, s.keys.accountSubjects(account), slots...).Err()
}
