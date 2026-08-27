# Dovecote migration bridge

Gatekeep 1.1.0 includes an opt-in bridge from the existing SQLx audit outbox
to Dovecote. The normal `SqlxDecisionAuditRepository` constructors and
`AuditSink` implementation remain legacy-only. Applications opt in by
calling the explicit `record_decision_audit_with_dovecote` method on the
backend repository.

## Enablement

Select the backend and its matching bridge feature. The `dovecote` feature is
an all-backend convenience alias.

```toml
[dependencies]
gatekeep-sqlx = { version = "1.1", features = ["postgres", "dovecote-postgres"] }
```

Apply the Dovecote adapter's `0001_dovecote.sql` first, then Gatekeep's
historical `0001_audit.sql`, and finally the additive
`0002_dovecote_bridge.sql` migration for the same backend. Existing migration
files are release artifacts and are not rewritten.

```rust
use gatekeep_sqlx::{DovecoteAuditBridge, PgDecisionAuditRepository};

let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
let audit = PgDecisionAuditRepository::new(pool.clone());
let outcome = audit
    .record_decision_audit_with_dovecote(&entry, &bridge)
    .await?;
```

The source is an application-owned absolute URI. The default stream is
`gatekeep-audit`; `DovecoteAuditBridge::with_stream` selects another validated
stream explicitly.

## Dual-write contract

The bridge method owns one concrete backend transaction. It inserts the
current normalized decision, child rows, and legacy outbox row; captures that
legacy outbox row's ID; derives `gatekeep-outbox-<legacy outbox id>`; inserts
the Dovecote event and delivery; and persists a mapping ledger before commit.
The Dovecote delivery is always `pending`, and the legacy publisher remains
the sole owner of publication during migration.

On SQLite the dual-write transaction begins with Dovecote's immediate write
transaction, so legacy and Dovecote writes share the same writer lock.

The event type is the existing
`gatekeep.decision_audit_recorded`, content type is `application/json`, and
the payload is the deterministic JSON serialization used by Gatekeep. No
CloudEvents time is written: Gatekeep's legacy audit schema has no occurrence
time, and `recorded_at`/`created_at` are not substitutes. The bridge does not
invent a time capture that would change the legacy representation.

`legacy_outbox_publication` reads the persisted mapping ledger. A publisher
must use that API rather than reconstructing an event from current
configuration. Changing source or stream after a mapping/state row exists is
a typed `StateConflict`; changing any persisted identity or payload is a
typed `MappingConflict`.

The bridge-aware legacy publisher must acquire a row through the backend's
`claim_legacy_outbox_with_dovecote` method. That concrete transaction claims
the legacy row and records a fresh opaque generation in the mapping ledger;
the returned token must be retained by the publisher. After publication,
acknowledgement uses `acknowledge_legacy_outbox_with_dovecote` with the owner,
that token, and delivery time. A later claim by the same worker cannot be
acknowledged with an older token, even when the legacy owner and expiry happen
to repeat. The method conditionally clears the legacy claim and marks the
legacy row delivered, then calls Dovecote's migration finalizer using the
persisted mapping row ID in the same transaction. External raw SQL updates to
`delivered_at` are not a safe substitute: they can leave the Dovecote delivery
pending or permit a stale publisher acknowledgement.

Each mapping records payload provenance, the versioned codec name
`gatekeep-audit-json-v1`, and a SHA-256 digest of the exact stored bytes. A
dual-write mapping is marked `gatekeep-dual-write-v1`. SQLite history imports
retain the legacy text bytes and are marked `gatekeep-legacy-text-v1`;
Postgres JSONB and MySQL JSON history rows are necessarily reconstructed by
the named codec and are marked `gatekeep-legacy-json-value-v1`. Once a mapping
exists, reconciliation and publisher reads use its stored bytes and metadata,
not a fresh serialization of the legacy row.

The project-owned `encode_reconstructed_audit_v1` function is the narrow
versioned codec for normalized JSON/JSONB values. It is migration infrastructure
only; callers must record its codec/provenance and must not mark its output as
the original database bytes. A legacy decision row without a matching outbox,
where supported by a project-owned importer, reserves the
`gatekeep-audit-legacy-<decision id>` identity; new 2.0 decision identities do
not use that namespace.

## Complete-history import

After the additive migration, import all legacy decision rows with the bounded
backend method:

```rust
let options = gatekeep_sqlx::BridgeImportOptions::new(
    100,
    "gatekeep-history-1",
    std::time::Duration::from_secs(300),
)?;
let report = audit.import_legacy_history(&bridge, &options).await?;
```

The state table stores one source/stream configuration, an inclusive high-water
decision ID/cursor pair, an independent inclusive high-water outbox ID/cursor
pair, and a database-time claim lease. Concurrent importers
therefore either process separate committed batches or receive a typed
`Claimed` result. Cursor advances, mapping writes, and Dovecote imports share
the transaction. An interruption rolls all of them back; rerunning the batch
uses Dovecote's exact identity/content checks and is safe. A committed range
is not scanned again. Once the cursor reaches the stored high-water mark, the
next invocation captures the current maximum atomically, so rows committed by
later legacy writers are eventually included. A complete rerun with no later
rows returns a zero-change report. The importer drains the outbox cursor before
advancing the decision cursor past decisions that currently have outbox rows;
this preserves a normalized decision as a recoverable reconstruction if an
operator removes a legacy outbox row during the rollback window. A batch may
therefore report decision progress separately from outbox progress internally,
but `complete` is true only when both source cursors reach their high-water
marks.

The importer drains `gatekeep_audit_outbox` independently by outbox ID, then
scans `gatekeep_audit_decisions` by decision ID with a `NOT EXISTS` outbox
test. It does not use a left join or a shared cursor: the published schema
does not require one outbox row per decision, and every outbox identity must be
retained. When an outbox row exists, its identity and payload remain
authoritative and the mapping ledger is `gatekeep_dovecote_bridge_outbox`.
When a decision has no outbox row, Gatekeep reconstructs the typed JSON value
from the decision row with the named `gatekeep-audit-json-v1` codec, records
`gatekeep-legacy-json-value-v1` provenance in
`gatekeep_dovecote_bridge_audit`, and uses the reserved
`gatekeep-audit-legacy-<decision id>` identity. Such a reconstructed event is
pending and has no legacy publisher claim to carry across cutover. The
separate mapping table is a migration ledger, not a second delivery queue.

Legacy `delivered_at` rows import as delivered with that same timestamp;
undelivered rows import as pending. The importer locks the selected legacy
outbox rows and reads `claimed_by`/`claimed_until` when an outbox row exists; an
active legacy claim is a typed `LegacyClaimed` error and is never silently
imported as pending. Expired claims are conditionally fenced (the owner and
expiry must still match) before import, so a stale publisher cannot later
acknowledge the row. If that fence does not affect exactly the observed row,
import stops with `LegacyClaimed`.
Retries and quarantine state are not inferred from the legacy schema. Import
identity conflicts and delivery state conflicts remain typed Dovecote adapter
errors and stop the transaction.

The bridge mapping tables are deliberately narrow export ledgers, not a
general-purpose repository. They exist so the legacy publisher can expose
authoritative source, event ID, type, and exact payload bytes while the
migration remains inspectable and reversible at the application cutover.
