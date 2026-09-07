# Fighting-game integration notes

These notes describe one application consuming the general
[user blocking and restriction example](../examples/relation-lifecycle/README.md).
They impose no game-specific types, dependencies or rules on the libraries.

Replace the custom authoritative block and mechanical restriction assignment
stores with Keepsake assignments. Keep reports, evidence custody, cases,
decisions, appeals, staff policy, taxonomy, product notifications and business
receipts in the game. A game decision may reference a Keepsake assignment ID;
that reference does not become a second current lifecycle head.

1. Maintain one fixed block definition and one definition per application-chosen
   restriction meaning. Map the directed account pair to a subject for blocks;
   map an individually restricted account to its subject. Use the per-assignment
   expiry field for its authoritative deadline, never arbitrary metadata.
2. Authenticate and lock current actor authority before reading an old receipt.
   Acquire Keepsake observations for every relevant direction and restriction
   before business rows; use the documented backend lock order. The PostgreSQL
   implementation takes coarse table locks, so reconcile its placement with
   the game's ProductClock / aggregate lock order for **all** writers and workers.
3. Convert the game's authoritative time through its existing OffsetDateTime
   mapping. Supply unavailable/stale/regressed time as typed evidence failures;
   persist the game's clock high-water mark. Resolve each scoped snapshot through
   `KeepsakeRelationTarget::effective_presence`, then run pure Gatekeep policy.
4. Within the same SQLx transaction, conditionally mutate Keepsake, write the
   game-owned business result, record Gatekeep audit and enqueue required intent.
   Commit once. Roll back on any error; after an unknown commit, authenticate
   again and recover the exact stable command outcome before repeating effects.
5. Gate invitations, membership changes, matchmaking composition and future
   admissions where game policy requires. Preserve already-admitted session
   records and deterministic match simulation; applying a block is not a command
   to disconnect, rewrite a lobby or adjudicate a result.

Migration of the game's unfinished custom stores remains game-agent work.
Quiesce affected writers, map existing stable identities and deadlines, and
reconcile assignment/current-state counts before switching the single writer.
Do not silently turn existing terminal history into new applies or pending
notifications. Retain its case/decision/evidence history, link it to the mapped
assignments, and use explicit historical Dovecote import only where required.
The library's existing old-version migration tools preserve historical audit
and delivery state; they do not infer the game's identity mapping or workflow.

Effective expiry stops a timed restriction at its deadline but does not release
persisted uniqueness. To renew while reconciliation is delayed, authenticate
current authority and reconcile (or revoke) the old assignment before applying
a fresh command in the same caller-owned transaction. A plain apply against the
still-persisted `Applied` row reports `duplicate_prevented` and retains its old
identity; it is not a renewal. The consumer's reconciliation scenario verifies
that distinction, atomic rollback/commit of expiry plus reapplication, fresh
assignment evidence, and no repeated terminal events.
