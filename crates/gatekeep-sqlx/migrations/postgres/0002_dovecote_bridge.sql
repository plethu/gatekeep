-- Gatekeep 1.1.0 opt-in Dovecote bridge state.  The 0001 audit migration is
-- historical and must remain byte-for-byte unchanged.
create table gatekeep_dovecote_bridge_state (
  id smallint primary key check (id = 1),
  source text not null,
  stream text not null,
  -- cursor/high_water walk normalized decisions without an outbox.
  high_water bigint,
  cursor bigint not null default 0 check (cursor >= 0),
  -- Outbox rows have an independent ID sequence and may repeat a decision.
  outbox_high_water bigint,
  outbox_cursor bigint not null default 0 check (outbox_cursor >= 0),
  claimed_by text,
  claim_token text,
  claim_until bigint,
  check ((claimed_by is null) = (claim_token is null)),
  check ((claim_token is null) = (claim_until is null)),
  check (high_water is null or high_water >= 0),
  check (high_water is null or cursor <= high_water),
  check (outbox_high_water is null or outbox_high_water >= 0),
  check (outbox_high_water is null or outbox_cursor <= outbox_high_water)
);

-- The mapping is written in the same transaction as the legacy outbox and
-- Dovecote event.  Publishers read it as the authoritative identity surface.
create table gatekeep_dovecote_bridge_outbox (
  legacy_outbox_id bigint primary key references gatekeep_audit_outbox(id) on delete restrict,
  source text not null,
  event_id text not null,
  event_type text not null,
  payload bytea not null check (convert_from(payload, 'UTF8')::jsonb is not null),
  payload_provenance text not null,
  payload_codec text not null,
  payload_digest bytea not null check (octet_length(payload_digest) = 32),
  legacy_claim_token text,
  dovecote_row_id bigint not null,
  unique (source, event_id)
);

create index gatekeep_dovecote_bridge_outbox_event
  on gatekeep_dovecote_bridge_outbox (dovecote_row_id);

-- Normalized decision rows that predate (or deliberately lack) an outbox row
-- still need a durable migration identity and reconciliation ledger.  This
-- table is not a publisher queue: only the outbox mapping has claim state.
create table gatekeep_dovecote_bridge_audit (
  decision_id bigint primary key references gatekeep_audit_decisions(id) on delete restrict,
  source text not null,
  event_id text not null,
  event_type text not null,
  payload bytea not null check (convert_from(payload, 'UTF8')::jsonb is not null),
  payload_provenance text not null,
  payload_codec text not null,
  payload_digest bytea not null check (octet_length(payload_digest) = 32),
  dovecote_row_id bigint not null,
  unique (source, event_id)
);

create index gatekeep_dovecote_bridge_audit_event
  on gatekeep_dovecote_bridge_audit (dovecote_row_id);
