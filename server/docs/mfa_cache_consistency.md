# MFA writes and cached identity state

Canonical MFA mutations invalidate the canonical account used by the next identity
lookup, rather than a browser-supplied login alias. TOTP enrollment/deletion and
recovery-code enrollment/regeneration invalidate after the backend write succeeds.
Remote recovery generation persists at the authority, so invalidation belongs to
generation rather than the later browser acknowledgement. Authority-side writes
also invalidate their own caches. Existing WebAuthn mutation paths use the same
account invalidation and treat cache maintenance as best effort after persistence.
Cache failures are logged; they do not turn an already persisted factor into a
reported write failure.

Recovery verification never authorizes consumption from cached recovery values.
The frontend (including recovery codes submitted on the TOTP step) and gRPC
authority share `ConsumeRecoveryCode`. Cached membership on the TOTP step only
selects the recovery path; it never establishes validity. The selected backend
name is retained when resolving the manager:

- LDAP reads the current stored attribute values, decrypts them for comparison,
  compares plaintext using `subtle.ConstantTimeCompare`, and deletes all exact
  stored values matching the submitted code in one LDAP
  modify request. Undecryptable values are skipped with a fixed warning that
  contains no stored value or decryption error; other valid codes remain usable.
  The delete retains the original ciphertext. A missing value
  rejects a competing consumer; other LDAP errors fail closed. No replacement of
  the remaining set can restore codes consumed by another request.
- Backends implementing `TOTPRecoveryCodeConsumer` own atomic consumption.
- Legacy replacement-only backends are read directly through `PassDB` before
  consumption. This prevents sequential replay from a stale cache, but cannot
  guarantee concurrent single use across processes. Such backends must implement
  `TOTPRecoveryCodeConsumer` for that guarantee; a process-local lock would not
  establish distributed atomicity.

A successful consume also invalidates the account cache. `PurgeCacheFor` evicts
in-process positive backend authentication snapshots by identity as well as the
existing account and host-service caches. Login aliases and canonical accounts
indexed on those snapshots invalidate the associated variants. LDAP replay rejection
still holds when that invalidation fails or an old snapshot is served afterward.
The remaining-code count is informational and may race with consumption of other
codes; validity is decided by the atomic delete result.

Regression tests exercise canonical required-factor checks before and after
writes, independent stale cache snapshots, encrypted duplicate values, concurrent
consumption through both recovery and TOTP entry points, undecryptable LDAP values,
positive backend snapshot eviction by login and canonical account, remote write
success/failure, and legacy fresh-read failure handling. Constant-time comparison
is enforced by the standard-library primitive; functional tests cover matching,
nonmatching, and duplicate values rather than making timing assertions.
The LDAP queue fixture is a hermetic test double, not a production LDAP rollout
or browser acceptance proof.
