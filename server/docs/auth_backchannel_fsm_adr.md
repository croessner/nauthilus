# Auth Backchannel FSM ADR

## Status

Proposed

## Context

The current backchannel authentication flow in `server/core/rest.go` is functionally a state machine, but expressed as
distributed conditional logic across:

- `HandleAuthentication`
- `ProcessFeatures`
- `ProcessAuthentication`

This makes transition rules and side effects (abort, status code, toleration updates, response mode) harder to reason
about and test as a coherent system.

## Decision

Model backchannel authentication as an explicit finite state machine (FSM), introduced incrementally.

Phase 1 (this step):

- Define explicit state/event types and transition table in `server/core/auth_fsm.go`.
- Add unit tests for transition validity and invalid transitions.
- Do not change runtime behavior yet.

Phase 2+:

- Route existing flow outcomes (`HandleFeatures`, `HandlePassword`, basic-auth checks) through FSM events.
- Centralize side effects in terminal state handlers.
- Keep endpoint/API behavior stable while refactoring.

## State Matrix (target model)

States:

- `init`
- `input_parsed`
- `features_checked`
- `password_checked`
- `auth_ok` (terminal)
- `auth_fail` (terminal)
- `auth_tempfail` (terminal)
- `aborted` (terminal)

Events:

- `parse_ok`, `parse_fail`
- `features_ok`, `features_fail`, `features_tempfail`, `features_unset`
- `password_ok`, `password_fail`, `password_tempfail`, `password_empty_user`, `password_empty_pass`
- `basic_auth_ok`, `basic_auth_fail`
- `abort`

Allowed transitions:

1. `init + parse_ok -> input_parsed`
2. `init + parse_fail -> aborted`
3. `input_parsed + basic_auth_ok -> auth_ok`
4. `input_parsed + basic_auth_fail -> auth_fail`
5. `input_parsed + features_ok -> features_checked`
6. `input_parsed + features_fail -> auth_fail`
7. `input_parsed + features_tempfail -> auth_tempfail`
8. `input_parsed + features_unset -> aborted`
9. `features_checked + password_ok -> auth_ok`
10. `features_checked + password_fail -> auth_fail`
11. `features_checked + password_tempfail -> auth_tempfail`
12. `features_checked + password_empty_user -> auth_tempfail`
13. `features_checked + password_empty_pass -> auth_fail`
14. `* + abort -> aborted` for non-terminal states

Terminal-state rule:

- No outgoing transitions from `auth_ok`, `auth_fail`, `auth_tempfail`, `aborted`.

## Consequences

Pros:

- Explicit, testable transition model.
- Safer extension points for future auth feature gates.
- Clear separation of transition logic and effect execution.

Tradeoffs:

- Adds conceptual and code structure overhead.
- Requires phased migration to avoid regressions.

