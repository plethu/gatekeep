-- Gatekeep 1.1.0 opt-in Dovecote bridge state.  The 0001 audit migration is
-- historical and must remain byte-for-byte unchanged.
create table gatekeep_dovecote_bridge_state (
  id smallint primary key,
  source text not null,
  stream text not null,
  -- cursor/high_water walk normalized decisions without an outbox.
  high_water bigint,
  `cursor` bigint not null default 0,
  -- Outbox rows have an independent ID sequence and may repeat a decision.
  outbox_high_water bigint,
  outbox_cursor bigint not null default 0,
  claimed_by text,
  claim_token text,
  claim_until bigint,
  check (id = 1),
  check (`cursor` >= 0),
  check (high_water is null or high_water >= 0),
  check (high_water is null or `cursor` <= high_water),
  check (outbox_high_water is null or outbox_high_water >= 0),
  check (outbox_high_water is null or outbox_cursor <= outbox_high_water),
  check ((claimed_by is null) = (claim_token is null)),
  check ((claim_token is null) = (claim_until is null))
);

create table gatekeep_dovecote_bridge_outbox (
  legacy_outbox_id bigint primary key,
  source varbinary(2048) not null,
  event_id varbinary(1024) not null,
  event_type varbinary(1024) not null,
  payload longblob not null,
  payload_provenance varchar(128) not null,
  payload_codec varchar(128) not null,
  payload_digest binary(32) not null,
  legacy_claim_token varchar(64) null,
  dovecote_row_id bigint not null,
  check (json_valid(cast(payload as char character set utf8mb4))),
  check (octet_length(payload_digest) = 32),
  unique key gatekeep_dovecote_bridge_outbox_identity (source, event_id),
  constraint gatekeep_dovecote_bridge_outbox_legacy_fk foreign key (legacy_outbox_id)
    references gatekeep_audit_outbox(id) on delete restrict
);

create index gatekeep_dovecote_bridge_outbox_event
  on gatekeep_dovecote_bridge_outbox (dovecote_row_id);

-- Normalized decision rows that predate (or deliberately lack) an outbox row
-- still need a durable migration identity and reconciliation ledger.  This
-- table is not a publisher queue: only the outbox mapping has claim state.
create table gatekeep_dovecote_bridge_audit (
  decision_id bigint primary key,
  source varbinary(2048) not null,
  event_id varbinary(1024) not null,
  event_type varbinary(1024) not null,
  payload longblob not null,
  payload_provenance varchar(128) not null,
  payload_codec varchar(128) not null,
  payload_digest binary(32) not null,
  dovecote_row_id bigint not null,
  check (json_valid(cast(payload as char character set utf8mb4))),
  check (octet_length(payload_digest) = 32),
  unique key gatekeep_dovecote_bridge_audit_identity (source, event_id),
  constraint gatekeep_dovecote_bridge_audit_decision_fk foreign key (decision_id)
    references gatekeep_audit_decisions(id) on delete restrict
);

create index gatekeep_dovecote_bridge_audit_event
  on gatekeep_dovecote_bridge_audit (dovecote_row_id);
