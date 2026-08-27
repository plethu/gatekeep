use async_trait::async_trait;
use gatekeep::{AuditEntry, ReasonValue};
#[cfg(feature = "dovecote-sqlite")]
use sqlx::Row;
use sqlx::Transaction;
#[cfg(feature = "dovecote-sqlite")]
use std::time::Duration;

#[cfg(feature = "dovecote-sqlite")]
use super::bridge::{
    BRIDGE_PAYLOAD_PROVENANCE_LEGACY_TEXT, BridgeEventError, BridgeImportOptions,
    BridgeImportReport, BridgeWriteOutcome, DovecoteAuditBridge, GATEKEEP_AUDIT_EVENT_TYPE,
    LegacyAuditPublication, LegacyOutboxClaim, count_import, encode_reconstructed_audit_v1,
    import_row_id, new_claim_token, outcome_row_id,
};
use super::support::{
    deny_shape_label, effect_label, position_i32, presence_label, records_from_text_rows,
};
use super::{DecisionAuditRecord, SqlxAuditError, SqlxAuditStore, SqlxDecisionAuditRepository};
#[cfg(feature = "dovecote-sqlite")]
use dovecote::ImportedDeliveryState;

/// SQLite-backed decision audit repository.
pub type SqliteDecisionAuditRepository = SqlxDecisionAuditRepository<crate::SqliteBackend>;

impl SqliteDecisionAuditRepository {
    /// Creates a repository from a `SQLite` pool.
    #[must_use]
    pub const fn new(pool: sqlx::SqlitePool) -> Self {
        Self::from_pool(pool)
    }
}

#[async_trait]
impl SqlxAuditStore<crate::SqliteBackend> for SqliteDecisionAuditRepository {
    async fn record_decision_audit(&self, entry: &AuditEntry) -> Result<i64, SqlxAuditError> {
        let entry_json = serde_json::to_string(entry)?;
        let trace_json = serde_json::to_string(&entry.trace)?;
        let decisive_json = serde_json::to_string(&entry.decisive)?;
        let denial_reason_json = entry
            .denial_reason
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r"
            insert into gatekeep_audit_decisions
              (request_id, policy_id, policy_hash, effect, trace, decisive_clause,
               denial_reason_code, denial_reason_shape, denial_reason, entry)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(entry.request_id.as_ref().map(gatekeep::RequestId::as_str))
        .bind(entry.anchor.policy_id.as_str())
        .bind(entry.anchor.policy_hash.as_str())
        .bind(effect_label(entry))
        .bind(trace_json)
        .bind(decisive_json)
        .bind(
            entry
                .denial_reason
                .as_ref()
                .map(|reason| reason.code.as_str()),
        )
        .bind(
            entry
                .denial_reason
                .as_ref()
                .map(|reason| deny_shape_label(reason.shape)),
        )
        .bind(denial_reason_json)
        .bind(entry_json)
        .execute(&mut *tx)
        .await?;
        let id = sqlx::query_scalar::<_, i64>("select last_insert_rowid()")
            .fetch_one(&mut *tx)
            .await?;
        insert_children(&mut tx, id, entry).await?;
        insert_outbox(&mut tx, id, entry).await?;
        tx.commit().await?;
        Ok(id)
    }

    async fn decision_audit_records(
        &self,
        after_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<DecisionAuditRecord>, SqlxAuditError> {
        let rows = sqlx::query(
            "select id, entry from gatekeep_audit_decisions where (? is null or id > ?) order by id limit ?",
        )
        .bind(after_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        records_from_text_rows(rows)
    }
}

#[cfg(feature = "dovecote-sqlite")]
impl SqliteDecisionAuditRepository {
    /// Records legacy normalized audit rows and a pending Dovecote event in
    /// one concrete `SQLite` transaction.  The legacy outbox remains the
    /// publication owner; this method never claims or delivers Dovecote work.
    ///
    /// # Errors
    ///
    /// Returns [`SqliteBridgeError`] when the legacy write, bridge mapping, or
    /// Dovecote enqueue cannot be completed atomically.
    pub async fn record_decision_audit_with_dovecote(
        &self,
        entry: &AuditEntry,
        bridge: &DovecoteAuditBridge,
    ) -> Result<BridgeWriteOutcome, SqliteBridgeError> {
        let entry_json = serde_json::to_string(entry)?;
        let trace_json = serde_json::to_string(&entry.trace)?;
        let decisive_json = serde_json::to_string(&entry.decisive)?;
        let denial_reason_json = entry
            .denial_reason
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let dovecote = dovecote_sqlx_sqlite::SqliteDovecote::new(self.pool.clone());
        let mut tx = dovecote
            .begin_write()
            .await
            .map_err(SqliteBridgeError::DovecoteBegin)?;
        ensure_bridge_configuration(&mut tx, bridge).await?;
        sqlx::query(
            r"
            insert into gatekeep_audit_decisions
              (request_id, policy_id, policy_hash, effect, trace, decisive_clause,
               denial_reason_code, denial_reason_shape, denial_reason, entry)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(entry.request_id.as_ref().map(gatekeep::RequestId::as_str))
        .bind(entry.anchor.policy_id.as_str())
        .bind(entry.anchor.policy_hash.as_str())
        .bind(effect_label(entry))
        .bind(trace_json)
        .bind(decisive_json)
        .bind(
            entry
                .denial_reason
                .as_ref()
                .map(|reason| reason.code.as_str()),
        )
        .bind(
            entry
                .denial_reason
                .as_ref()
                .map(|reason| deny_shape_label(reason.shape)),
        )
        .bind(denial_reason_json)
        .bind(&entry_json)
        .execute(&mut *tx)
        .await?;
        let decision_id = sqlx::query_scalar::<_, i64>("select last_insert_rowid()")
            .fetch_one(&mut *tx)
            .await?;
        insert_children(&mut tx, decision_id, entry)
            .await
            .map_err(SqliteBridgeError::Audit)?;
        let legacy_outbox_id = insert_outbox_with_id(&mut tx, decision_id, &entry_json).await?;
        let event = bridge.event(
            legacy_outbox_id,
            GATEKEEP_AUDIT_EVENT_TYPE,
            entry_json.clone().into_bytes(),
        )?;
        let dovecote = dovecote_sqlx_sqlite::enqueue(&mut tx, event)
            .await
            .map_err(SqliteBridgeError::Dovecote)?;
        insert_bridge_mapping(
            &mut tx,
            &bridge.publication(
                legacy_outbox_id,
                GATEKEEP_AUDIT_EVENT_TYPE,
                entry_json.into_bytes(),
            )?,
            outcome_row_id(&dovecote)
                .ok_or(SqliteBridgeError::UnsupportedOutcome)?
                .get(),
        )
        .await?;
        tx.commit().await?;
        Ok(BridgeWriteOutcome {
            decision_id,
            legacy_outbox_id,
            dovecote,
        })
    }

    /// Imports a bounded complete-history range.  The state row is claimed
    /// with a database-time lease and every cursor update is fenced by the
    /// persisted token, so concurrent callers can safely retry interrupted
    /// batches.
    ///
    /// # Errors
    ///
    /// Returns [`SqliteBridgeError::Claimed`] when another importer owns the
    /// lease, or another typed error when a row cannot be imported.
    #[allow(clippy::too_many_lines)]
    pub async fn import_legacy_history(
        &self,
        bridge: &DovecoteAuditBridge,
        options: &BridgeImportOptions,
    ) -> Result<BridgeImportReport, SqliteBridgeError> {
        let dovecote = dovecote_sqlx_sqlite::SqliteDovecote::new(self.pool.clone());
        let mut transaction = dovecote
            .begin_write()
            .await
            .map_err(SqliteBridgeError::DovecoteBegin)?;
        let token = claim_import_state(&mut transaction, bridge, options).await?;
        let (high_water, cursor, outbox_high_water, outbox_cursor) =
            state_position(&mut transaction).await?;
        let legacy_now =
            sqlx::query_scalar::<_, String>("select strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
                .fetch_one(&mut *transaction)
                .await
                .map_err(SqliteBridgeError::Sqlx)
                .and_then(|value| parse_sqlite_timestamp(&value))?;
        let decision_scan_ready = outbox_cursor >= outbox_high_water;
        let decision_rows = if decision_scan_ready {
            sqlx::query(
            "select d.id as decision_id, d.entry from gatekeep_audit_decisions d where d.id > ? and d.id <= ? and not exists (select 1 from gatekeep_audit_outbox o where o.decision_id = d.id) order by d.id limit ?",
            )
            .bind(cursor)
            .bind(high_water)
            .bind(i64::from(options.batch_size()))
            .fetch_all(&mut *transaction)
            .await?
        } else {
            Vec::new()
        };
        let outbox_rows = sqlx::query(
            "select o.id as outbox_id, o.event_type, o.payload, o.claimed_by, o.claimed_until, o.delivered_at from gatekeep_audit_outbox o where o.id > ? and o.id <= ? order by o.id limit ?",
        )
        .bind(outbox_cursor)
        .bind(outbox_high_water)
        .bind(i64::from(options.batch_size()))
        .fetch_all(&mut *transaction)
        .await?;

        let mut report = BridgeImportReport::empty(
            high_water,
            cursor,
            outbox_high_water,
            outbox_cursor,
            decision_rows.is_empty() && outbox_rows.is_empty(),
        );
        let decision_rows_len = decision_rows.len();
        let outbox_rows_len = outbox_rows.len();
        let batch_size = usize::try_from(options.batch_size()).unwrap_or(usize::MAX);
        let mut decision_cursor = cursor;
        let mut outbox_cursor = outbox_cursor;
        for row in decision_rows {
            let decision_id: i64 = row.try_get("decision_id")?;
            let entry: String = row.try_get("entry")?;
            let value: serde_json::Value = serde_json::from_str(&entry)?;
            let payload = encode_reconstructed_audit_v1(&value)?;
            let publication = match persisted_audit_mapping(&mut transaction, decision_id).await? {
                Some(publication) => publication,
                None => bridge.reconstructed_audit_publication(
                    decision_id,
                    GATEKEEP_AUDIT_EVENT_TYPE,
                    payload,
                )?,
            };
            let event = bridge.event_from_reconstructed_audit(&publication)?;
            let outcome = dovecote_sqlx_sqlite::import_for_migration(
                &mut transaction,
                event,
                ImportedDeliveryState::pending(),
            )
            .await
            .map_err(SqliteBridgeError::DovecoteImport)?;
            insert_audit_mapping(
                &mut transaction,
                &publication,
                import_row_id(&outcome)
                    .ok_or(SqliteBridgeError::UnsupportedOutcome)?
                    .get(),
            )
            .await?;
            let (imported, already, delivered, _) = count_import(&outcome, false);
            report.imported += u64::from(imported);
            report.already_imported += u64::from(already);
            report.delivered += u64::from(delivered);
            advance_import_state(&mut transaction, &token, decision_id).await?;
            report.cursor = decision_id;
            decision_cursor = decision_id;
        }

        for row in outbox_rows {
            let outbox_id: i64 = row.try_get("outbox_id")?;
            let event_type: String = row.try_get("event_type")?;
            let payload: String = row.try_get("payload")?;
            let claimed_by: Option<String> = row.try_get("claimed_by")?;
            let claimed_until_raw: Option<String> = row.try_get("claimed_until")?;
            let claimed_until = claimed_until_raw
                .as_deref()
                .map(parse_sqlite_timestamp)
                .transpose()?;
            if claimed_until.is_some_and(|until| until > legacy_now)
                || (claimed_by.is_some() && claimed_until.is_none())
            {
                return Err(SqliteBridgeError::LegacyClaimed(outbox_id));
            }

            if let Some(until) = claimed_until
                && until <= legacy_now
            {
                fence_expired_legacy_claim(
                    &mut transaction,
                    outbox_id,
                    claimed_until_raw.as_deref(),
                    claimed_by.as_deref(),
                )
                .await?;
            }

            let delivered_at: Option<String> = row.try_get("delivered_at")?;
            let publication = match persisted_bridge_mapping(&mut transaction, outbox_id).await? {
                Some(publication) => publication,
                None => bridge.publication_with_provenance(
                    outbox_id,
                    &event_type,
                    payload.into_bytes(),
                    BRIDGE_PAYLOAD_PROVENANCE_LEGACY_TEXT,
                )?,
            };
            let event = bridge.event_from_publication(&publication)?;
            let state = match delivered_at {
                Some(value) => ImportedDeliveryState::delivered(parse_sqlite_timestamp(&value)?)
                    .map_err(SqliteBridgeError::State)?,
                None => ImportedDeliveryState::pending(),
            };
            let delivered = state.delivered_at().is_some();
            let outcome =
                dovecote_sqlx_sqlite::import_for_migration(&mut transaction, event, state)
                    .await
                    .map_err(SqliteBridgeError::DovecoteImport)?;
            insert_bridge_mapping(
                &mut transaction,
                &publication,
                import_row_id(&outcome)
                    .ok_or(SqliteBridgeError::UnsupportedOutcome)?
                    .get(),
            )
            .await?;
            let (imported, already, delivered, _) = count_import(&outcome, delivered);
            report.imported += u64::from(imported);
            report.already_imported += u64::from(already);
            report.delivered += u64::from(delivered);
            advance_outbox_state(&mut transaction, &token, outbox_id).await?;
            outbox_cursor = outbox_id;
        }

        if outbox_rows_len < batch_size {
            advance_outbox_state(&mut transaction, &token, outbox_high_water).await?;
            outbox_cursor = outbox_high_water;
        }

        let remaining = batch_size.saturating_sub(outbox_rows_len);
        if !decision_scan_ready && outbox_cursor >= outbox_high_water && remaining == 0 {
            if remaining == 0 {
                let decision_only: i64 = sqlx::query_scalar(
                    "select count(*) from gatekeep_audit_decisions d where d.id > ? and d.id <= ? and not exists (select 1 from gatekeep_audit_outbox o where o.decision_id = d.id)",
                )
                .bind(decision_cursor)
                .bind(high_water)
                .fetch_one(&mut *transaction)
                .await?;
                if decision_only == 0 {
                    advance_import_state(&mut transaction, &token, high_water).await?;
                    report.cursor = high_water;
                    decision_cursor = high_water;
                }
            }
        } else if !decision_scan_ready && outbox_cursor >= outbox_high_water {
            let decision_rows = sqlx::query(
                "select d.id as decision_id, d.entry from gatekeep_audit_decisions d where d.id > ? and d.id <= ? and not exists (select 1 from gatekeep_audit_outbox o where o.decision_id = d.id) order by d.id limit ?",
            )
            .bind(decision_cursor)
            .bind(high_water)
            .bind(i64::try_from(remaining).unwrap_or(i64::MAX))
            .fetch_all(&mut *transaction)
            .await?;
            let decision_rows_len = decision_rows.len();
            for row in decision_rows {
                let decision_id: i64 = row.try_get("decision_id")?;
                let entry: String = row.try_get("entry")?;
                let value: serde_json::Value = serde_json::from_str(&entry)?;
                let payload = encode_reconstructed_audit_v1(&value)?;
                let publication =
                    match persisted_audit_mapping(&mut transaction, decision_id).await? {
                        Some(publication) => publication,
                        None => bridge.reconstructed_audit_publication(
                            decision_id,
                            GATEKEEP_AUDIT_EVENT_TYPE,
                            payload,
                        )?,
                    };
                let event = bridge.event_from_reconstructed_audit(&publication)?;
                let outcome = dovecote_sqlx_sqlite::import_for_migration(
                    &mut transaction,
                    event,
                    ImportedDeliveryState::pending(),
                )
                .await
                .map_err(SqliteBridgeError::DovecoteImport)?;
                insert_audit_mapping(
                    &mut transaction,
                    &publication,
                    import_row_id(&outcome)
                        .ok_or(SqliteBridgeError::UnsupportedOutcome)?
                        .get(),
                )
                .await?;
                let (imported, already, delivered, _) = count_import(&outcome, false);
                report.imported += u64::from(imported);
                report.already_imported += u64::from(already);
                report.delivered += u64::from(delivered);
                advance_import_state(&mut transaction, &token, decision_id).await?;
                report.cursor = decision_id;
                decision_cursor = decision_id;
            }

            if decision_rows_len < remaining {
                advance_import_state(&mut transaction, &token, high_water).await?;
                report.cursor = high_water;
                decision_cursor = high_water;
            }
        }

        if decision_scan_ready && decision_rows_len < batch_size {
            advance_import_state(&mut transaction, &token, high_water).await?;
            report.cursor = high_water;
            decision_cursor = high_water;
        }
        report.complete = decision_cursor >= high_water && outbox_cursor >= outbox_high_water;
        report.outbox_cursor = outbox_cursor;
        release_import_state(&mut transaction, &token).await?;
        transaction.commit().await?;
        Ok(report)
    }

    /// Returns the persisted identity and exact payload bytes for a legacy
    /// publisher.  The mapping is authoritative and is not recomputed from
    /// the caller's current bridge configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SqliteBridgeError::MappingNotFound`] when no bridge mapping
    /// exists, or another typed error when persisted data is invalid.
    pub async fn legacy_outbox_publication(
        &self,
        legacy_outbox_id: i64,
    ) -> Result<super::bridge::BridgePublication, SqliteBridgeError> {
        let row = sqlx::query(
            "select source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
        )
        .bind(legacy_outbox_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SqliteBridgeError::MappingNotFound(legacy_outbox_id))?;
        let source: String = row.try_get("source")?;
        let event_id: String = row.try_get("event_id")?;
        let event_type: String = row.try_get("event_type")?;
        let payload: Vec<u8> = row.try_get("payload")?;
        let payload_provenance: String = row.try_get("payload_provenance")?;
        let payload_codec: String = row.try_get("payload_codec")?;
        let payload_digest: Vec<u8> = row.try_get("payload_digest")?;
        super::bridge::BridgePublication::from_persisted(
            legacy_outbox_id,
            super::bridge::PersistedBridgePublication {
                source,
                event_id,
                event_type,
                payload_provenance,
                payload_codec,
                payload_digest,
                payload,
            },
        )
        .map_err(SqliteBridgeError::Event)
    }

    /// Claims one bridge-mapped legacy row for the legacy publisher.
    ///
    /// The claim is made with `SQLite`'s immediate write transaction and stores
    /// a fresh opaque generation in the bridge mapping. The generation is
    /// replaced on every successful acquisition, including a reclaim by the
    /// same worker with the same expiry. Callers must pass the returned token
    /// to [`Self::acknowledge_legacy_outbox_with_dovecote`].
    ///
    /// # Errors
    ///
    /// Returns [`SqliteBridgeError::LegacyClaimUnavailable`] when the row is
    /// already delivered or has an active legacy claim.
    pub async fn claim_legacy_outbox_with_dovecote(
        &self,
        legacy_outbox_id: i64,
        worker: &str,
        lease: Duration,
    ) -> Result<LegacyOutboxClaim, SqliteBridgeError> {
        let dovecote = dovecote_sqlx_sqlite::SqliteDovecote::new(self.pool.clone());
        let mut tx = dovecote
            .begin_write()
            .await
            .map_err(SqliteBridgeError::DovecoteBegin)?;
        let _ = mapping_row_id(&mut tx, legacy_outbox_id).await?;
        let lease_millis =
            i64::try_from(lease.as_millis()).map_err(|_| SqliteBridgeError::StateTimestamp {
                detail: "legacy claim lease exceeds SQLite integer range".to_owned(),
            })?;
        if lease_millis <= 0 {
            return Err(SqliteBridgeError::StateTimestamp {
                detail: "legacy claim lease must be positive".to_owned(),
            });
        }

        let now = sqlite_epoch_millis(&mut tx).await?;
        let until_millis =
            now.checked_add(lease_millis)
                .ok_or_else(|| SqliteBridgeError::StateTimestamp {
                    detail: "legacy claim expiry exceeds SQLite integer range".to_owned(),
                })?;
        let until =
            time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(until_millis) * 1_000_000)
                .map_err(|error| SqliteBridgeError::StateTimestamp {
                    detail: error.to_string(),
                })?
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| SqliteBridgeError::StateTimestamp {
                    detail: error.to_string(),
                })?;
        let changed = sqlx::query(
            "update gatekeep_audit_outbox set claimed_by = ?, claimed_until = ? where id = ? and delivered_at is null and (claimed_until is null or julianday(claimed_until) <= julianday('now'))",
        )
        .bind(worker)
        .bind(&until)
        .bind(legacy_outbox_id)
        .execute(&mut *tx)
        .await?;
        if changed.rows_affected() != 1 {
            return Err(SqliteBridgeError::LegacyClaimUnavailable(legacy_outbox_id));
        }

        let token = new_claim_token(worker);
        let mapped = sqlx::query(
            "update gatekeep_dovecote_bridge_outbox set legacy_claim_token = ? where legacy_outbox_id = ?",
        )
        .bind(&token)
        .bind(legacy_outbox_id)
        .execute(&mut *tx)
        .await?;
        if mapped.rows_affected() != 1 {
            return Err(SqliteBridgeError::MappingNotFound(legacy_outbox_id));
        }

        tx.commit().await?;
        Ok(LegacyOutboxClaim::new(legacy_outbox_id, token))
    }

    /// Acknowledges a claimed legacy row and finalizes its mapped Dovecote
    /// delivery in the same immediate transaction.
    ///
    /// The caller must be the current legacy publisher owner and provide the
    /// opaque generation returned by
    /// [`Self::claim_legacy_outbox_with_dovecote`]. An already-delivered row
    /// is accepted only when its delivery time and generation match.
    ///
    /// # Errors
    ///
    /// Returns [`SqliteBridgeError::AckNotOwned`] when the legacy claim is not
    /// owned by `worker`, or another typed error when either side cannot be
    /// finalized atomically.
    pub async fn acknowledge_legacy_outbox_with_dovecote(
        &self,
        legacy_outbox_id: i64,
        worker: &str,
        claim_token: &str,
        delivered_at: time::OffsetDateTime,
    ) -> Result<(), SqliteBridgeError> {
        let dovecote = dovecote_sqlx_sqlite::SqliteDovecote::new(self.pool.clone());
        let mut tx = dovecote
            .begin_write()
            .await
            .map_err(SqliteBridgeError::DovecoteBegin)?;
        let dovecote_row_id = mapping_row_id(&mut tx, legacy_outbox_id).await?;
        acknowledge_legacy_claim(&mut tx, legacy_outbox_id, worker, claim_token, delivered_at)
            .await?;
        dovecote_sqlx_sqlite::finalize_pending_delivery_for_migration(
            &mut tx,
            dovecote_row_id,
            delivered_at,
        )
        .await
        .map_err(SqliteBridgeError::DovecoteFinalize)?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(feature = "dovecote-sqlite")]
async fn acknowledge_legacy_claim(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    legacy_outbox_id: i64,
    worker: &str,
    claim_token: &str,
    delivered_at: time::OffsetDateTime,
) -> Result<(), SqliteBridgeError> {
    let row = sqlx::query(
        "select l.claimed_by, l.claimed_until, l.delivered_at, b.legacy_claim_token from gatekeep_audit_outbox l join gatekeep_dovecote_bridge_outbox b on b.legacy_outbox_id = l.id where l.id = ?",
    )
    .bind(legacy_outbox_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(SqliteBridgeError::MappingNotFound(legacy_outbox_id))?;
    let claimed_by: Option<String> = row.try_get("claimed_by")?;
    let persisted_until: Option<String> = row.try_get("claimed_until")?;
    let existing_delivered: Option<String> = row.try_get("delivered_at")?;
    let persisted_token: Option<String> = row.try_get("legacy_claim_token")?;
    let delivered_text = delivered_at
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| SqliteBridgeError::StateTimestamp {
            detail: error.to_string(),
        })?;
    if let Some(existing) = existing_delivered {
        return if existing == delivered_text && persisted_token.as_deref() == Some(claim_token) {
            Ok(())
        } else if existing == delivered_text {
            Err(SqliteBridgeError::AckNotOwned(legacy_outbox_id))
        } else {
            Err(SqliteBridgeError::AckConflict(legacy_outbox_id))
        };
    }

    let now = sqlx::query_scalar::<_, String>("select strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
        .fetch_one(&mut **tx)
        .await
        .and_then(|value| {
            parse_sqlite_timestamp(&value).map_err(|error| sqlx::Error::Protocol(error.to_string()))
        })
        .map_err(SqliteBridgeError::Sqlx)?;
    let until = persisted_until
        .as_deref()
        .map(parse_sqlite_timestamp)
        .transpose()?;
    if persisted_token.as_deref() != Some(claim_token)
        || claimed_by.as_deref() != Some(worker)
        || until.is_none_or(|value| value <= now)
    {
        return Err(SqliteBridgeError::AckNotOwned(legacy_outbox_id));
    }

    let changed = sqlx::query(
        "update gatekeep_audit_outbox set delivered_at = ?, claimed_by = null, claimed_until = null where id = ? and claimed_by = ? and claimed_until = ? and julianday(claimed_until) > julianday('now') and delivered_at is null",
    )
    .bind(&delivered_text)
    .bind(legacy_outbox_id)
    .bind(worker)
    .bind(persisted_until.as_deref())
    .execute(&mut **tx)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(SqliteBridgeError::AckNotOwned(legacy_outbox_id));
    }

    Ok(())
}

#[cfg(feature = "dovecote-sqlite")]
async fn fence_expired_legacy_claim(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    id: i64,
    until: Option<&str>,
    claimed_by: Option<&str>,
) -> Result<(), SqliteBridgeError> {
    let fenced = sqlx::query(
        "update gatekeep_audit_outbox set claimed_by = null, claimed_until = null where id = ? and claimed_until = ? and claimed_by is ?",
    )
    .bind(id)
    .bind(until)
    .bind(claimed_by)
    .execute(&mut **tx)
    .await?;
    if fenced.rows_affected() != 1 {
        return Err(SqliteBridgeError::LegacyClaimed(id));
    }
    Ok(())
}

#[cfg(feature = "dovecote-sqlite")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
/// Errors returned by `SQLite` dual-write and history-import operations.
pub enum SqliteBridgeError {
    /// `SQLx` returned an error.
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    /// Legacy audit payload could not be encoded or decoded.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Bridge event identity or payload validation failed.
    #[error(transparent)]
    Event(#[from] BridgeEventError),
    /// Persisted source or stream differs from the configured bridge.
    #[error("bridge state source or stream conflicts with its existing configuration")]
    StateConflict,
    /// Another importer currently owns the bridge lease.
    #[error("bridge state is claimed by another importer")]
    Claimed,
    /// The current importer no longer owns the state-row lease.
    #[error("bridge claim token was lost")]
    LostClaim,
    /// No persisted publisher identity exists for the requested outbox row.
    #[error("bridge identity mapping does not exist for legacy outbox row {0}")]
    MappingNotFound(i64),
    /// The existing mapping disagrees with the event being imported or written.
    #[error("bridge identity mapping conflicts with persisted content")]
    MappingConflict,
    /// The legacy publisher does not own an unexpired claim for the row.
    #[error("legacy outbox row {0} is not conditionally owned by the publisher")]
    AckNotOwned(i64),
    /// The row cannot be acquired because it is delivered or actively claimed.
    #[error("legacy outbox row {0} cannot be acquired by the bridge")]
    LegacyClaimUnavailable(i64),
    /// The row was already acknowledged with a different delivery time.
    #[error("legacy outbox row {0} was already acknowledged with a different delivery time")]
    AckConflict(i64),
    /// A legacy publisher currently owns the row being imported.
    #[error("legacy outbox row {0} has an active claim")]
    LegacyClaimed(i64),
    /// The configured Dovecote adapter returned an unknown outcome.
    #[error("Dovecote returned an unsupported import outcome")]
    UnsupportedOutcome,
    /// The legacy audit write failed.
    #[error(transparent)]
    Audit(#[from] SqlxAuditError),
    /// A persisted `SQLite` timestamp could not be interpreted.
    #[error("invalid bridge state timestamp: {detail}")]
    StateTimestamp {
        /// Parsing or range error detail.
        detail: String,
    },
    /// Dovecote rejected the imported delivery state.
    #[error("invalid imported delivery state: {0}")]
    State(#[source] dovecote::ValidationError),
    /// Dovecote rejected a dual-write enqueue.
    #[error("Dovecote enqueue failed: {0}")]
    Dovecote(#[source] dovecote_sqlx_sqlite::EnqueueError),
    /// Dovecote rejected a history import.
    #[error("Dovecote import failed: {0}")]
    DovecoteImport(#[source] dovecote_sqlx_sqlite::ImportError),
    /// Dovecote pending delivery finalization failed.
    #[error("Dovecote delivery finalization failed: {0}")]
    DovecoteFinalize(#[source] dovecote_sqlx_sqlite::FinalizeError),
    /// The `SQLite` adapter could not acquire a write transaction.
    #[error("Dovecote write transaction failed: {0}")]
    DovecoteBegin(#[source] dovecote_sqlx_sqlite::EnqueueError),
}

async fn insert_children(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    decision_id: i64,
    entry: &AuditEntry,
) -> Result<(), SqlxAuditError> {
    for (position, obligation) in entry.obligations.iter().enumerate() {
        sqlx::query(
            "insert into gatekeep_audit_obligations (decision_id, position, obligation_id) values (?, ?, ?)",
        )
        .bind(decision_id)
        .bind(position_i32(position))
        .bind(obligation.as_str())
        .execute(&mut **tx)
        .await?;
    }

    for (position, (fact, presence)) in entry.consulted.iter().enumerate() {
        sqlx::query(
            "insert into gatekeep_audit_consulted_facts (decision_id, position, fact_id, presence) values (?, ?, ?, ?)",
        )
        .bind(decision_id)
        .bind(position_i32(position))
        .bind(fact.as_str())
        .bind(presence_label(*presence))
        .execute(&mut **tx)
        .await?;
    }

    for (slot, subject) in &entry.subjects {
        sqlx::query(
            "insert into gatekeep_audit_request_subjects (decision_id, slot, subject_kind, subject_id) values (?, ?, ?, ?)",
        )
        .bind(decision_id)
        .bind(slot.as_str())
        .bind(subject.kind())
        .bind(subject.id())
        .execute(&mut **tx)
        .await?;
    }

    if let Some(reason) = &entry.denial_reason {
        for (key, value) in &reason.params {
            sqlx::query(
                "insert into gatekeep_audit_reason_params (decision_id, key, value) values (?, ?, ?)",
            )
            .bind(decision_id)
            .bind(key.as_str())
            .bind(reason_value_json(value)?)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn insert_outbox(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    decision_id: i64,
    entry: &AuditEntry,
) -> Result<(), SqlxAuditError> {
    sqlx::query("insert into gatekeep_audit_outbox (decision_id, payload) values (?, ?)")
        .bind(decision_id)
        .bind(serde_json::to_string(entry)?)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(feature = "dovecote-sqlite")]
async fn insert_outbox_with_id(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    decision_id: i64,
    payload: &str,
) -> Result<i64, SqliteBridgeError> {
    sqlx::query("insert into gatekeep_audit_outbox (decision_id, payload) values (?, ?)")
        .bind(decision_id)
        .bind(payload)
        .execute(&mut **tx)
        .await?;
    Ok(sqlx::query_scalar::<_, i64>("select last_insert_rowid()")
        .fetch_one(&mut **tx)
        .await?)
}

#[cfg(feature = "dovecote-sqlite")]
async fn ensure_bridge_configuration(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    bridge: &DovecoteAuditBridge,
) -> Result<(), SqliteBridgeError> {
    sqlx::query(
        "insert into gatekeep_dovecote_bridge_state (id, source, stream, cursor) values (1, ?, ?, 0) on conflict (id) do nothing",
    )
    .bind(bridge.source().as_str())
    .bind(bridge.stream().as_str())
    .execute(&mut **tx)
    .await?;
    let (source, stream): (String, String) =
        sqlx::query_as("select source, stream from gatekeep_dovecote_bridge_state where id = 1")
            .fetch_one(&mut **tx)
            .await?;
    if source != bridge.source().as_str() || stream != bridge.stream().as_str() {
        return Err(SqliteBridgeError::StateConflict);
    }
    Ok(())
}

#[cfg(feature = "dovecote-sqlite")]
async fn insert_bridge_mapping(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    publication: &super::bridge::BridgePublication,
    dovecote_row_id: i64,
) -> Result<(), SqliteBridgeError> {
    sqlx::query(
        "insert into gatekeep_dovecote_bridge_outbox (legacy_outbox_id, source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest, dovecote_row_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict (legacy_outbox_id) do nothing",
    )
    .bind(publication.legacy_outbox_id())
    .bind(publication.source())
    .bind(publication.event_id())
    .bind(publication.event_type())
    .bind(publication.payload())
    .bind(publication.payload_provenance())
    .bind(publication.payload_codec())
    .bind(publication.payload_digest())
    .bind(dovecote_row_id)
    .execute(&mut **tx)
    .await?;
    let row = sqlx::query(
        "select source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest, dovecote_row_id from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
    )
    .bind(publication.legacy_outbox_id())
    .fetch_one(&mut **tx)
    .await?;
    let source: String = row.try_get("source")?;
    let event_id: String = row.try_get("event_id")?;
    let event_type: String = row.try_get("event_type")?;
    let payload: Vec<u8> = row.try_get("payload")?;
    let payload_provenance: String = row.try_get("payload_provenance")?;
    let payload_codec: String = row.try_get("payload_codec")?;
    let payload_digest: Vec<u8> = row.try_get("payload_digest")?;
    let existing_row_id: i64 = row.try_get("dovecote_row_id")?;
    if source != publication.source()
        || event_id != publication.event_id()
        || event_type != publication.event_type()
        || payload != publication.payload()
        || payload_provenance != publication.payload_provenance()
        || payload_codec != publication.payload_codec()
        || payload_digest != publication.payload_digest()
        || existing_row_id != dovecote_row_id
    {
        return Err(SqliteBridgeError::MappingConflict);
    }
    Ok(())
}

#[cfg(feature = "dovecote-sqlite")]
async fn persisted_bridge_mapping(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    legacy_outbox_id: i64,
) -> Result<Option<super::bridge::BridgePublication>, SqliteBridgeError> {
    let row = sqlx::query(
        "select source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
    )
    .bind(legacy_outbox_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    let source: String = row.try_get("source")?;
    let event_id: String = row.try_get("event_id")?;
    let event_type: String = row.try_get("event_type")?;
    let payload: Vec<u8> = row.try_get("payload")?;
    let payload_provenance: String = row.try_get("payload_provenance")?;
    let payload_codec: String = row.try_get("payload_codec")?;
    let payload_digest: Vec<u8> = row.try_get("payload_digest")?;
    super::bridge::BridgePublication::from_persisted(
        legacy_outbox_id,
        super::bridge::PersistedBridgePublication {
            source,
            event_id,
            event_type,
            payload_provenance,
            payload_codec,
            payload_digest,
            payload,
        },
    )
    .map(Some)
    .map_err(SqliteBridgeError::Event)
}

#[cfg(feature = "dovecote-sqlite")]
async fn insert_audit_mapping(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    publication: &LegacyAuditPublication,
    dovecote_row_id: i64,
) -> Result<(), SqliteBridgeError> {
    sqlx::query(
        "insert into gatekeep_dovecote_bridge_audit (decision_id, source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest, dovecote_row_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict (decision_id) do nothing",
    )
    .bind(publication.decision_id)
    .bind(&publication.source)
    .bind(&publication.event_id)
    .bind(&publication.event_type)
    .bind(&publication.payload)
    .bind(&publication.payload_provenance)
    .bind(&publication.payload_codec)
    .bind(publication.payload_digest.as_slice())
    .bind(dovecote_row_id)
    .execute(&mut **tx)
    .await?;
    let row = sqlx::query(
        "select source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest, dovecote_row_id from gatekeep_dovecote_bridge_audit where decision_id = ?",
    )
    .bind(publication.decision_id)
    .fetch_one(&mut **tx)
    .await?;
    let source: String = row.try_get("source")?;
    let event_id: String = row.try_get("event_id")?;
    let event_type: String = row.try_get("event_type")?;
    let payload: Vec<u8> = row.try_get("payload")?;
    let payload_provenance: String = row.try_get("payload_provenance")?;
    let payload_codec: String = row.try_get("payload_codec")?;
    let payload_digest: Vec<u8> = row.try_get("payload_digest")?;
    let existing_row_id: i64 = row.try_get("dovecote_row_id")?;
    if source != publication.source
        || event_id != publication.event_id
        || event_type != publication.event_type
        || payload != publication.payload
        || payload_provenance != publication.payload_provenance
        || payload_codec != publication.payload_codec
        || payload_digest != publication.payload_digest
        || existing_row_id != dovecote_row_id
    {
        return Err(SqliteBridgeError::MappingConflict);
    }
    Ok(())
}

#[cfg(feature = "dovecote-sqlite")]
async fn persisted_audit_mapping(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    decision_id: i64,
) -> Result<Option<LegacyAuditPublication>, SqliteBridgeError> {
    let row = sqlx::query(
        "select source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest from gatekeep_dovecote_bridge_audit where decision_id = ?",
    )
    .bind(decision_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    let source: String = row.try_get("source")?;
    let event_id: String = row.try_get("event_id")?;
    let event_type: String = row.try_get("event_type")?;
    let payload: Vec<u8> = row.try_get("payload")?;
    let payload_provenance: String = row.try_get("payload_provenance")?;
    let payload_codec: String = row.try_get("payload_codec")?;
    let payload_digest: Vec<u8> = row.try_get("payload_digest")?;
    LegacyAuditPublication::from_persisted(
        decision_id,
        super::bridge::PersistedBridgePublication {
            source,
            event_id,
            event_type,
            payload_provenance,
            payload_codec,
            payload_digest,
            payload,
        },
    )
    .map(Some)
    .map_err(SqliteBridgeError::Event)
}

#[cfg(feature = "dovecote-sqlite")]
async fn mapping_row_id(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    legacy_outbox_id: i64,
) -> Result<dovecote::RowId, SqliteBridgeError> {
    let value: i64 = sqlx::query_scalar(
        "select dovecote_row_id from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
    )
    .bind(legacy_outbox_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(SqliteBridgeError::MappingNotFound(legacy_outbox_id))?;
    dovecote::RowId::new(value).map_err(|_| SqliteBridgeError::MappingConflict)
}

#[cfg(feature = "dovecote-sqlite")]
async fn claim_import_state(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    bridge: &DovecoteAuditBridge,
    options: &BridgeImportOptions,
) -> Result<String, SqliteBridgeError> {
    let existing = sqlx::query(
        "select source, stream, high_water, cursor, claimed_by, claim_token, claim_until from gatekeep_dovecote_bridge_state where id = 1",
    )
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = &existing {
        let source: String = row.try_get("source")?;
        let stream: String = row.try_get("stream")?;
        if source != bridge.source().as_str() || stream != bridge.stream().as_str() {
            return Err(SqliteBridgeError::StateConflict);
        }

        let claim_until: Option<i64> = row.try_get("claim_until")?;
        let now = sqlite_epoch_millis(tx).await?;
        if claim_until.is_some_and(|until| until > now) {
            return Err(SqliteBridgeError::Claimed);
        }
    } else {
        sqlx::query(
            "insert into gatekeep_dovecote_bridge_state (id, source, stream, cursor) values (1, ?, ?, 0)",
        )
        .bind(bridge.source().as_str())
        .bind(bridge.stream().as_str())
        .execute(&mut **tx)
        .await?;
    }

    let token = new_claim_token(options.worker());
    let lease_millis = i64::try_from(options.lease().as_millis()).map_err(|_| {
        SqliteBridgeError::StateTimestamp {
            detail: "bridge lease exceeds SQLite integer range".to_owned(),
        }
    })?;
    sqlx::query(
        "update gatekeep_dovecote_bridge_state set claimed_by = ?, claim_token = ?, claim_until = ? + ? where id = 1",
    )
    .bind(options.worker())
    .bind(&token)
    .bind(sqlite_epoch_millis(tx).await?)
    .bind(lease_millis)
    .execute(&mut **tx)
    .await?;
    Ok(token)
}

#[cfg(feature = "dovecote-sqlite")]
async fn state_position(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
) -> Result<(i64, i64, i64, i64), SqliteBridgeError> {
    let row = sqlx::query(
        "select high_water, cursor, outbox_high_water, outbox_cursor, (select coalesce(max(id), 0) from gatekeep_audit_decisions) as latest_id, (select coalesce(max(id), 0) from gatekeep_audit_outbox) as latest_outbox_id from gatekeep_dovecote_bridge_state where id = 1",
    )
    .fetch_one(&mut **tx)
    .await?;
    let stored_high_water: Option<i64> = row.try_get(0)?;
    let cursor: i64 = row.try_get(1)?;
    let stored_outbox_high_water: Option<i64> = row.try_get(2)?;
    let outbox_cursor: i64 = row.try_get(3)?;
    let latest_id: i64 = row.try_get("latest_id")?;
    let latest_outbox_id: i64 = row.try_get("latest_outbox_id")?;
    let high_water = if stored_high_water.is_none_or(|value| cursor >= value) {
        latest_id.max(cursor)
    } else {
        stored_high_water.unwrap_or(0)
    };

    let outbox_high_water = if stored_outbox_high_water.is_none_or(|value| outbox_cursor >= value) {
        latest_outbox_id.max(outbox_cursor)
    } else {
        stored_outbox_high_water.unwrap_or(0)
    };
    if stored_high_water != Some(high_water) {
        sqlx::query("update gatekeep_dovecote_bridge_state set high_water = ? where id = 1")
            .bind(high_water)
            .execute(&mut **tx)
            .await?;
    }

    if stored_outbox_high_water != Some(outbox_high_water) {
        sqlx::query("update gatekeep_dovecote_bridge_state set outbox_high_water = ? where id = 1")
            .bind(outbox_high_water)
            .execute(&mut **tx)
            .await?;
    }
    Ok((high_water, cursor, outbox_high_water, outbox_cursor))
}

#[cfg(feature = "dovecote-sqlite")]
async fn advance_import_state(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    token: &str,
    cursor: i64,
) -> Result<(), SqliteBridgeError> {
    let result = sqlx::query(
        "update gatekeep_dovecote_bridge_state set cursor = ? where id = 1 and claim_token = ?",
    )
    .bind(cursor)
    .bind(token)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(SqliteBridgeError::LostClaim);
    }
    Ok(())
}

#[cfg(feature = "dovecote-sqlite")]
async fn advance_outbox_state(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    token: &str,
    cursor: i64,
) -> Result<(), SqliteBridgeError> {
    let result = sqlx::query(
        "update gatekeep_dovecote_bridge_state set outbox_cursor = ? where id = 1 and claim_token = ?",
    )
    .bind(cursor)
    .bind(token)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(SqliteBridgeError::LostClaim);
    }
    Ok(())
}

#[cfg(feature = "dovecote-sqlite")]
async fn release_import_state(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    token: &str,
) -> Result<(), SqliteBridgeError> {
    let result = sqlx::query(
        "update gatekeep_dovecote_bridge_state set claimed_by = null, claim_token = null, claim_until = null where id = 1 and claim_token = ?",
    )
    .bind(token)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(SqliteBridgeError::LostClaim);
    }
    Ok(())
}

#[cfg(feature = "dovecote-sqlite")]
async fn sqlite_epoch_millis(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
) -> Result<i64, SqliteBridgeError> {
    Ok(
        sqlx::query_scalar::<_, i64>("select cast(unixepoch('now') * 1000 as integer)")
            .fetch_one(&mut **tx)
            .await?,
    )
}

#[cfg(feature = "dovecote-sqlite")]
fn parse_sqlite_timestamp(value: &str) -> Result<time::OffsetDateTime, SqliteBridgeError> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).map_err(
        |error| SqliteBridgeError::StateTimestamp {
            detail: error.to_string(),
        },
    )
}

fn reason_value_json(value: &ReasonValue) -> Result<String, SqlxAuditError> {
    serde_json::to_string(value).map_err(SqlxAuditError::from)
}
