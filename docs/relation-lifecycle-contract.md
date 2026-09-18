# Effective relation facts

Relation facts use effective state at an explicit authoritative observation time.
Unknown, stale or regressed time, disabled definitions and missing fulfillment
evidence are typed unavailable outcomes, never fabricated permission or an
indefinitely continued restriction. Reconciliation is a separate durable audited
transition.

Gatekeep's ordinary resolver uses its caller-supplied Clock as the authoritative
time assertion and validates returned tenant, subject and relation scopes. It is
a snapshot resolver, not a lock or freshness guarantee for a protected write.
The transaction composition path must acquire and retain Keepsake's scope locks,
resolve current state, evaluate policy, and write business state in that same
transaction. Cached decisions cannot substitute for that procedure.

An application may encode a directed pair as an opaque subject using an injective
encoding and bind two request subject slots for either-direction admission checks.
Applications own identity mapping, fulfillment evidence, time authority and
freshness policy. A denial changes no lifecycle or business state; an optional
denial audit has a separately specified commit. Existing sessions are independent
business records and do not change merely because a later admission is denied.

Disabled definitions suspend durable reconciliation. Effective evaluation still
recognizes a due deadline or satisfied fulfillment using Keepsake's policy
function. Before expiry, a disabled definition yields unavailable evidence.
Unknown or stale time and storage failure are unavailable outcomes; callers must
report an operation as unavailable rather than recording a restriction denial.
Clock regressions require recovery of authoritative time, not extending expiry.

The ordinary resolver has no fulfillment provider. It reports missing evidence
for fulfillment policies; transaction callers can pass their scoped current
fulfillment evidence to `KeepsakeRelationTarget::effective_presence`. The supplied
`Clock` is an explicit application assertion of current authoritative time. For
unknown/stale time classification use the composition helper's `ObservationTime`.

See [the executable transaction consumer](https://github.com/plethu/gatekeep/blob/main/examples/relation-lifecycle/README.md).

`RelationSnapshot` binds absent observations to a tenant, subject and relation as
well as checking any present assignment. Constructing one attests neither storage
completeness nor a transaction lock. `effective_presence` rejects scope substitution
for both presence and absence. Ordinary resolver metadata identifies an effective
snapshot and bounds known timed presence by its earliest expiry deadline; absence
and manual relations still require current revalidation before a protected write.

`FulfillmentEvidence` retains the tenant and assignment identity alongside policy
evidence. The transaction read binds these values; `effective_presence` rejects
another tenant, an older revoked/reapplied assignment, or evidence attached to an
absent relation. Low-level deterministic evaluation still accepts raw snapshots;
its caller owns scope validation. The evidence type does not authenticate its
source or prove completeness of application-defined checklist membership.
