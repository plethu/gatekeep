# A decision worth keeping

A record service often needs a small rule: a participant may see shared notes,
a parent may see a released summary, and an owner may see the full record. An
administrator's ability to operate the service need not grant access to content.
An emergency grant may permit a read when ordinary access denies it.

Those rules belong beside the application's types and tests. Gatekeep represents
them as policy values over named observations. A check can call ordinary Rust
code; the evaluator only receives its boolean result. This keeps database reads,
authentication and side effects out of deterministic evaluation.

The decision then travels through a second boundary. The application needs to
know which tenant and resource were checked, which policy revision ran, what was
observed and whether the audit event actually reached storage. A serializable
trace alone cannot answer all of those questions. The authorizer validates the
context and evidence, writes the event and returns only after the required sink
succeeds.

The [record service](guides/record-service.md) makes that boundary executable.
It resolves metadata and projects allowed fields under one SQLite write fence.
The audit event commits before the HTTP response. If the operation rolls back,
its event rolls back too; a denial therefore needs its own successful commit.
If a write's outcome is uncertain, a frozen event can be retried without
silently changing the observations under its identity.

This still depends on the application. Gatekeep cannot prove that a provider
supplied truthful facts, that a caller authenticated a principal correctly, or
that a client received a response. Keeping those limits visible makes the
resulting audit useful: it describes a particular decision and its evidence,
rather than claiming to certify the whole system.
