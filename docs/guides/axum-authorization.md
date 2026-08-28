# Axum Authorization

`gatekeep-axum` applies a policy before a handler returns protected data. The
adapter resolves request facts, evaluates the policy, records audit, and maps
denials into HTTP responses.

Use the adapter when an endpoint has one clear authorization decision. Keep
authentication, session loading, tenant lookup, and application data reads in
your Axum stack.

## Request Setup

An Axum integration usually has three parts:

1. Build a `Context` from request state.
2. Resolve policy facts from application services.
3. Attach an audit sink when decisions must be durable.

For durable audit with Postgres:

The compile-checked [`axum-durable-audit`](../../examples/axum-durable-audit/src/main.rs)
example is the canonical setup: it imports `gatekeep_axum::Gatekeeper`, uses an
application-owned `FactResolver`, checks the Dovecote schema, and attaches
`PgDovecoteAudit` with `Gatekeeper::new(resolver).with_audit_sink(audit)`. The
workspace builds this example as part of its checks.

The audit sink is awaited before the response is returned. If audit persistence
fails, the request reports the adapter error and no successful authorization
result leaves the boundary. Each entry contains a stable decision identity and
one authoritative occurrence time. A caller that may retry an ambiguous write
can supply the same `DecisionAuditOccurrence` in its `Context`; the successful
authorization result and audit-persistence error also return that value for
retention by the owning operation. The default clock is internal to the
adapter.

## Denial Responses

Use denial reason codes for stable response contracts. `DenyShape::Forbidden`
maps to a visible denial. `DenyShape::Hidden` supports responses that hide the
protected resource.

Pair reason codes with `gatekeep-fluent` when the API or UI needs localized
messages.

## Example

See `examples/axum-authorized-list` for an in-process fact resolver and
`examples/axum-keepsake-authorized-list` for relation-backed facts resolved from
Keepsake.
