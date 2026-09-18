# Application recipes

| Need | Pattern |
| --- | --- |
| Ownership | Name the equality check, record it with `with_bool`, and grant on that fact. |
| Membership | Resolve the relation in the selected tenant and resource scope; return explicit absence. |
| Required restriction | Put the restriction in `all` alongside positive grants. |
| Hidden records | Mark grant denials `hidden`; keep internal reasons out of public messages. |
| Emergency read | Use `or_else(normal, emergency)` with authoritative expiry and lifecycle audit. |
| Localized denial | Use Fluent's stable reason code and generic hidden message; check exact-locale coverage. |
| Required audit failure | Return an application error before disclosure; retain the frozen entry for reconciliation. |
| Permission change during a write | Resolve under the operation's lock/revision/isolation contract and write its event in the same transaction. |
| Bulk checks | Use a provider `BatchFactResolver`; retain each result and enforce a caller-selected bound. |

Keepsake's `FactBinding::resolve_relation` and `defer_relation` cover common typed
bindings. Use `for_relation_spec_on_subject` when the relation names a resource
slot. Active, expired and revoked relations resolve according to Keepsake's
lifecycle contract; unavailable storage is an error, not absence. An absence
observation is evidence about the queried scope and observation time, not a
claim that the relation has never existed.

## Your own audit store

Implement `AuditSink::record` by validating `entry.validate_current()`, encoding
the complete record, and committing it in your existing audit store. Enforce a
unique occurrence identity within tenant/source scope. An identical retry is
idempotent; the same identity with different bytes is a conflict. Return only
after the selected durability boundary succeeds. Keep one authoritative owner;
you do not need a second outbox merely to adopt Gatekeep.

Implement `AttemptAuditSink` separately when pre-evaluation failures need durable
history. Validate the attempt, store its separate event type, and preserve its
frozen identity on retry. Never route an untrusted request to a guessed tenant's
history stream.

## HTTP errors

Axum's default mapping keeps hidden denials generic. Applications can match
`GatekeepRejection` to produce their own Problem Details response: use a stable
application `type`, the corresponding status, and a generic title. Never format
a backend error or the complete internal trace into `detail`. Request IDs may
link to access-controlled operator diagnostics. This changes presentation, not
the audit requirement or authorization outcome.

## Lists and disclosure history

Apply the authorization filter before `COUNT`, `LIMIT` and `OFFSET`. Use
`SqlxLowerer::lower_result` for both resolved and pending policies; it guards the
filter and grade projection with the tenant. Grade projection requires a total
order. Opaque checks need explicit trusted SQL mappings.

A query-authorization event explains the policy and parameters used to select a
list. It does not prove which rows were returned. If disclosure history matters,
record the actual row references and grades assembled for the response in an
application event. SQL lowering cannot manufacture point-check traces for those
rows. A response event is still not proof of client receipt.
