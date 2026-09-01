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
let policy = policy::grant(ReadAccess::Full, condition::has::<CaseOwner>())
    .try_labeled("owner_full_read")?
    .try_reason("not_case_owner")?;
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
binding whose tenant matches the entry tenant. The optional binding and
evidence fields exist only for serde compatibility with pre-3.0 bytes. The
current [Dovecote](https://github.com/plethu/dovecote) decoder requires a
storage-row tenant, binding, and evidence; it rejects legacy-shaped payloads.

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
