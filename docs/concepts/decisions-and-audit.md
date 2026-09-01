# Decisions And Audit

A Gatekeep decision is more than a boolean. It records the effect, obligations,
facts consulted by evaluation, and the clause that fixed the result.

## Decision Shape

`Decision<O>` contains:

- `effect`: `Permit(O)` or `Deny`
- `obligations`: follow-up work attached to a permit path
- `trace.consulted`: facts read during evaluation
- `trace.decisive`: the permit or deny clause that decided the result

The outcome type `O` remains typed during evaluation. Use `Decision::to_trace`
when a durable sink needs a non-generic serialized trace.

## Denial Reasons

Grant clauses can carry reason codes. A denial reason gives UI, API, and audit
layers a stable code plus structured parameters.

```rust
# use gatekeep::{condition, policy, Fact, GatekeepResult, Lattice, StaticFactId};
# #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
# enum ReadAccess { Redacted, Full }
# impl Lattice for ReadAccess {
#     fn meet(&self, other: &Self) -> Self { (*self).min(*other) }
#     fn join(&self, other: &Self) -> Self { (*self).max(*other) }
#     fn top() -> Self { Self::Full }
#     fn bottom() -> Self { Self::Redacted }
# }
# struct CaseOwner;
# impl Fact for CaseOwner { const ID: StaticFactId = StaticFactId::new("case_owner"); }
# fn main() -> GatekeepResult<()> {
let policy = policy::grant(ReadAccess::Full, condition::has::<CaseOwner>())
    .try_labeled("owner_full_read")?
    .try_reason("not_case_owner")?;
# Ok(())
# }
```

The reason code should be stable enough to translate and search. Human wording
belongs in a reason catalog such as `gatekeep-fluent`, not in the policy value.

## Audit Entries

`AuditEntry` stores the complete decision envelope:

- stable `decision_audit_id` and authoritative `occurred_at`
- tenant binding, tenant, principal, locale, request id, and named subjects
- policy anchor
- effect
- obligations
- consulted facts
- decisive clause and trace data
- denial reason parameters
- bounded fact-set evidence: the resolver envelope's source observation time,
  an optional source and revision, optional freshness deadline, and a
  fixed-size digest of the complete resolved set. Gatekeep keeps a separate
  receipt/decision time for binding and freshness checks. Gatekeep does not
  claim individual fact provenance, and it records the digest even when source
  metadata is absent.

Build current entries with the typed constructor. It requires a validated
`DecisionAuditOccurrence`, binding, and fact evidence, and current entries
cannot represent the historical optional binding/evidence state. Every current
payload carries `AUDIT_ENTRY_SCHEMA_VERSION`; its `PolicyAnchor` carries and
validates `POLICY_HASH_FORMAT_VERSION`. Serde decoding routes the identity and
timestamp through `DecisionAuditOccurrence`, so sub-microsecond timestamps are
canonicalized and out-of-range or reserved legacy identities are rejected.

`LegacyAuditEntry` and `LegacyPolicyAnchor` are migration-only representations.
Use the explicitly named legacy SQLx decoder and map the result through
`LegacyAuditEntry::into_current` with a caller-supplied current occurrence,
binding, evidence, and known hash format. Legacy data is never silently
deserialized as a current `AuditEntry`.

`DecisionAuditId::new` reserves the exact, case-sensitive `legacy-` prefix for
explicit migration identities. The current decoder does not import those
records; a separately versioned migration importer must construct and validate
the historical representation before producing a current entry.

The core `AuditSink` trait is async because durable audit usually performs IO.
`Gatekeeper::new` requires an explicit sink. Use `Gatekeeper::unaudited` when
durable audit is out of scope. The test feature exposes `InMemoryAuditSink` for
assertions.

Obligations in an audit entry describe obligations attached to the selected
policy path. They are not evidence that obligation execution occurred; the
application must record execution separately when that matters.

`gatekeep-sqlx` serializes this value into one Dovecote event and pending
delivery. Dovecote owns SQL persistence, claiming, retries, and paging; the
Axum adapter awaits the audit sink before returning the authorization result.
Consumers deduplicate at-least-once publication with the tenant-scoped
Dovecote identity `(tenant_id, source, event_id)`. A transport projection must
preserve tenant routing alongside the CloudEvents `(source, id)` pair.
