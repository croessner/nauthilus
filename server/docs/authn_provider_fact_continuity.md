# Authentication provider fact continuity

Generic provider output must survive subsequent checkpoints in the same admitted
Decision Service session. It is separate from caller admission and from mutable
host observations. A native authentication subject receives the completed public
Lua/plugin evidence through `BackendResult.Facts`; consumers use the standard
exchange projection rather than assuming an environment provider wrote a runtime
map as a side effect.

The reported failure was a correct GeoIP country (`DE`) disappearing before an
account history subject and the final analytics action. The subject consequently
counted domestic addresses as unknown/foreign and could deny a valid password
after the foreign-address limit was reached.

The session retains only the evaluator's collected provider output. Before a
provider is scheduled again, its declared output is removed from carried evidence;
a skipped or failed refresh cannot reuse the earlier value. Caller facts retain
their original admission authority and collisions still fail closed. The public
subject projection excludes caller, token, transport, and host-only facts.

Regression coverage includes loss across checkpoints, real evaluator output and
repeat execution without stale facts or ownership collisions. RNS account-history
and reputation consumers additionally require their own generic-fact tests.
