# Audit Export

`gatekeep-sqlx` enqueues one Dovecote delivery for each decision audit record.
External workers claim Dovecote deliveries and publish the projected
CloudEvent.

## Delivery Contract

Treat Dovecote as the stable integration boundary:

- page and claim deliveries through the selected Dovecote adapter
- deliver each payload to the external system
- acknowledge only after the destination accepts the message
- retry or release rows that were not accepted downstream

Gatekeep does not include broker or object-storage clients. Keep those clients
in the application worker so deployment, credentials, batching, and backoff
match the service.

## Payload Use

Decode the complete Dovecote event payload into `AuditEntry` for reporting.
When paging, use `gatekeep_sqlx::decode_decision_audit` with the complete
`PagedEvent`; it rejects a payload whose tenant differs from the storage row.
Gatekeep does not maintain structured child tables or bespoke delivery state.

For high-volume exports, keep worker queries bounded and checkpoint by the last
accepted Dovecote row id. Delivery is at least once: consumers preserve tenant
routing and deduplicate by the Dovecote identity `(tenant_id, source,
event_id)`. A transport projection carries tenant routing separately from the
CloudEvents `(source, id)` pair.
