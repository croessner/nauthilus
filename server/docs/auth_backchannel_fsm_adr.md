# Auth Backchannel FSM ADR

## Status

Accepted

## Context

Backchannel authentication is represented by a target finite state machine (FSM). The FSM is policy-owned: policy
evaluation selects response markers, effect requests, and FSM event markers, while the runtime applies those markers to
the request-local authentication state.

The target model keeps brute-force handling inside policy material through check facts, decision obligations, and
response rendering. It does not maintain a separate bypass path for brute-force outcomes.

## Decision

The authentication boundary uses the target FSM marker vocabulary as the stable contract:

- `auth.fsm.event.parse_ok`
- `auth.fsm.event.parse_fail`
- `auth.fsm.event.pre_auth_ok`
- `auth.fsm.event.pre_auth_deny`
- `auth.fsm.event.pre_auth_tempfail`
- `auth.fsm.event.pre_auth_abort`
- `auth.fsm.event.auth_evaluated`
- `auth.fsm.event.account_provider_evaluated`
- `auth.fsm.event.auth_permit`
- `auth.fsm.event.auth_deny`
- `auth.fsm.event.auth_tempfail`
- `auth.fsm.event.auth_empty_user`
- `auth.fsm.event.auth_empty_pass`
- `auth.fsm.event.basic_auth_ok`
- `auth.fsm.event.basic_auth_fail`
- `auth.fsm.event.abort`

`standard_auth` is the built-in default policy set. Configured policy sets live under `auth.policy` and use the same
target markers, response markers, and decision effects as the default set. Observe mode compares a configured policy set
with `standard_auth`; enforce mode applies the selected policy result without emitting migration comparison reports.

## State Matrix

States:

- `init`
- `input_parsed`
- `pre_auth_checked`
- `auth_checked`
- `account_provider_checked`
- `auth_ok` (terminal)
- `auth_fail` (terminal)
- `auth_tempfail` (terminal)
- `aborted` (terminal)

Allowed transitions:

1. `init + auth.fsm.event.parse_ok -> input_parsed`
2. `init + auth.fsm.event.parse_fail -> aborted`
3. `input_parsed + auth.fsm.event.pre_auth_ok -> pre_auth_checked`
4. `input_parsed + auth.fsm.event.pre_auth_deny -> auth_fail`
5. `input_parsed + auth.fsm.event.pre_auth_tempfail -> auth_tempfail`
6. `input_parsed + auth.fsm.event.pre_auth_abort -> aborted`
7. `input_parsed + auth.fsm.event.basic_auth_ok -> auth_ok`
8. `input_parsed + auth.fsm.event.basic_auth_fail -> auth_fail`
9. `pre_auth_checked + auth.fsm.event.basic_auth_ok -> auth_ok`
10. `pre_auth_checked + auth.fsm.event.basic_auth_fail -> auth_fail`
11. `pre_auth_checked + auth.fsm.event.auth_evaluated -> auth_checked`
12. `pre_auth_checked + auth.fsm.event.account_provider_evaluated -> account_provider_checked`
13. `auth_checked + auth.fsm.event.auth_permit -> auth_ok`
14. `auth_checked + auth.fsm.event.auth_deny -> auth_fail`
15. `auth_checked + auth.fsm.event.auth_tempfail -> auth_tempfail`
16. `auth_checked + auth.fsm.event.auth_empty_user -> auth_tempfail`
17. `auth_checked + auth.fsm.event.auth_empty_pass -> auth_fail`
18. `account_provider_checked + auth.fsm.event.auth_permit -> auth_ok`
19. `account_provider_checked + auth.fsm.event.auth_deny -> auth_fail`
20. `account_provider_checked + auth.fsm.event.auth_tempfail -> auth_tempfail`
21. Any non-terminal state plus `auth.fsm.event.abort -> aborted`

Terminal-state rule:

- No outgoing transitions from `auth_ok`, `auth_fail`, `auth_tempfail`, or `aborted`.

## Consequences

- The FSM vocabulary is explicit, testable, and shared by default and configured policies.
- Observe-mode reports are limited to supported default-vs-configured comparisons.
- Enforce-mode request handling no longer emits temporary old-vs-new decision diagnostics.
- Runtime response rendering remains behavior-compatible while policy decisions become the stable authority boundary.
