use async_trait::async_trait;
use gatekeep::AuditEntry;
#[cfg(feature = "dovecote-mysql")]
use sqlx::Row;
use sqlx::Transaction;
#[cfg(feature = "dovecote-mysql")]
use std::time::Duration;

#[cfg(feature = "dovecote-mysql")]
use super::bridge::{
    BRIDGE_PAYLOAD_PROVENANCE_LEGACY_JSON_VALUE, BridgeEventError, BridgeImportOptions,
    BridgeImportReport, BridgeWriteOutcome, DovecoteAuditBridge, GATEKEEP_AUDIT_EVENT_TYPE,
    LegacyAuditPublication, LegacyOutboxClaim, count_import, encode_audit_entry_v1,
    encode_reconstructed_audit_v1, import_row_id, new_claim_token, outcome_row_id,
};
use super::support::{
    deny_shape_label, effect_label, position_i32, presence_label, records_from_json_rows,
};
use super::{DecisionAuditRecord, SqlxAuditError, SqlxAuditStore, SqlxDecisionAuditRepository};
#[cfg(feature = "dovecote-mysql")]
use dovecote::ImportedDeliveryState;

/// MySQL-backed decision audit repository.
pub type MySqlDecisionAuditRepository = SqlxDecisionAuditRepository<crate::MySqlBackend>;

impl MySqlDecisionAuditRepository {
    /// Creates a repository from a `MySQL` pool.
    #[must_use]
    pub const fn new(pool: sqlx::MySqlPool) -> Self {
        Self::from_pool(pool)
    }
}

#[cfg(feature = "dovecote-mysql")]
impl MySqlDecisionAuditRepository {
    /// Records the legacy normalized audit data and a pending Dovecote event
    /// in one concrete MySQL/MariaDB transaction.
    ///
    /// # Errors
    ///
    /// Returns [`MySqlBridgeError`] when the legacy write, bridge mapping, or
    /// Dovecote enqueue cannot be completed atomically.
    pub async fn record_decision_audit_with_dovecote(
        &self,
        entry: &AuditEntry,
        bridge: &DovecoteAuditBridge,
    ) -> Result<BridgeWriteOutcome, MySqlBridgeError> {
        let payload = encode_audit_entry_v1(entry)?;
        let mut tx = self.pool.begin().await?;
        ensure_bridge_configuration(&mut tx, bridge).await?;
        let denial_reason_json = entry
            .denial_reason
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let result = sqlx::query(
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
        .bind(serde_json::to_value(&entry.trace)?)
        .bind(serde_json::to_value(&entry.decisive)?)
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
        .bind(serde_json::from_slice::<serde_json::Value>(&payload)?)
        .execute(&mut *tx)
        .await?;
        let decision_id = i64::try_from(result.last_insert_id())
            .map_err(|_| MySqlBridgeError::IdOverflow(result.last_insert_id()))?;
        insert_children(&mut tx, decision_id, entry)
            .await
            .map_err(MySqlBridgeError::Audit)?;
        let legacy_outbox_id = insert_outbox_with_id(&mut tx, decision_id, &payload).await?;
        let event = bridge.event(legacy_outbox_id, GATEKEEP_AUDIT_EVENT_TYPE, payload.clone())?;
        let dovecote = dovecote_sqlx_mysql::enqueue(&mut tx, event)
            .await
            .map_err(MySqlBridgeError::Dovecote)?;
        insert_bridge_mapping(
            &mut tx,
            &bridge.publication(legacy_outbox_id, GATEKEEP_AUDIT_EVENT_TYPE, payload)?,
            outcome_row_id(&dovecote)
                .ok_or(MySqlBridgeError::UnsupportedOutcome)?
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

    /// Imports one bounded high-water batch under a fenced database-time
    /// bridge claim.  Rerunning a committed range delegates identity and
    /// delivery conflict handling to Dovecote's typed importer.
    ///
    /// # Errors
    ///
    /// Returns [`MySqlBridgeError::Claimed`] when another importer owns the
    /// lease, or another typed error when a row cannot be imported.
    #[allow(clippy::too_many_lines)]
    pub async fn import_legacy_history(
        &self,
        bridge: &DovecoteAuditBridge,
        options: &BridgeImportOptions,
    ) -> Result<BridgeImportReport, MySqlBridgeError> {
        let mut transaction = self.pool.begin().await?;
        let token = claim_import_state(&mut transaction, bridge, options).await?;
        let (high_water, cursor, outbox_high_water, outbox_cursor) =
            state_position(&mut transaction).await?;
        let legacy_now: time::OffsetDateTime = sqlx::query_scalar("select current_timestamp(6)")
            .fetch_one(&mut *transaction)
            .await?;
        let decision_scan_ready = outbox_cursor >= outbox_high_water;
        let decision_rows = if decision_scan_ready {
            sqlx::query(
                r"select d.id as decision_id, d.entry
               from gatekeep_audit_decisions d
               where d.id > ? and d.id <= ?
                 and not exists (
                   select 1 from gatekeep_audit_outbox o where o.decision_id = d.id
                 )
               order by d.id
               limit ?
               for update",
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
            r"select o.id as outbox_id, o.event_type, o.payload,
                      o.claimed_by, o.claimed_until, o.delivered_at
               from gatekeep_audit_outbox o
               where o.id > ? and o.id <= ?
               order by o.id
               limit ?
               for update",
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
            let entry: serde_json::Value = row.try_get("entry")?;
            let payload = encode_reconstructed_audit_v1(&entry)?;
            let publication = match persisted_audit_mapping(&mut transaction, decision_id).await? {
                Some(publication) => publication,
                None => bridge.reconstructed_audit_publication(
                    decision_id,
                    GATEKEEP_AUDIT_EVENT_TYPE,
                    payload,
                )?,
            };
            let event = bridge.event_from_reconstructed_audit(&publication)?;
            let outcome = dovecote_sqlx_mysql::import_for_migration(
                &mut transaction,
                event,
                ImportedDeliveryState::pending(),
            )
            .await
            .map_err(MySqlBridgeError::DovecoteImport)?;
            insert_audit_mapping(
                &mut transaction,
                &publication,
                import_row_id(&outcome)
                    .ok_or(MySqlBridgeError::UnsupportedOutcome)?
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
            let value: serde_json::Value = row.try_get("payload")?;
            let payload = encode_reconstructed_audit_v1(&value)?;
            let claimed_by: Option<String> = row.try_get("claimed_by")?;
            let claimed_until: Option<time::OffsetDateTime> = row.try_get("claimed_until")?;
            if claimed_until.is_some_and(|until| until > legacy_now)
                || (claimed_by.is_some() && claimed_until.is_none())
            {
                return Err(MySqlBridgeError::LegacyClaimed(outbox_id));
            }

            if let Some(until) = claimed_until
                && until <= legacy_now
            {
                fence_expired_legacy_claim(
                    &mut transaction,
                    outbox_id,
                    until,
                    claimed_by.as_deref(),
                )
                .await?;
            }

            let delivered_at: Option<time::OffsetDateTime> = row.try_get("delivered_at")?;
            let publication = match persisted_bridge_mapping(&mut transaction, outbox_id).await? {
                Some(publication) => publication,
                None => bridge.publication_with_provenance(
                    outbox_id,
                    &event_type,
                    payload,
                    BRIDGE_PAYLOAD_PROVENANCE_LEGACY_JSON_VALUE,
                )?,
            };
            let event = bridge.event_from_publication(&publication)?;
            let state = match delivered_at {
                Some(value) => {
                    ImportedDeliveryState::delivered(value).map_err(MySqlBridgeError::State)?
                }
                None => ImportedDeliveryState::pending(),
            };
            let delivered = state.delivered_at().is_some();
            let outcome = dovecote_sqlx_mysql::import_for_migration(&mut transaction, event, state)
                .await
                .map_err(MySqlBridgeError::DovecoteImport)?;
            insert_bridge_mapping(
                &mut transaction,
                &publication,
                import_row_id(&outcome)
                    .ok_or(MySqlBridgeError::UnsupportedOutcome)?
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
                r"select d.id as decision_id, d.entry
                   from gatekeep_audit_decisions d
                   where d.id > ? and d.id <= ?
                     and not exists (
                       select 1 from gatekeep_audit_outbox o where o.decision_id = d.id
                     )
                   order by d.id
                   limit ?
                   for update",
            )
            .bind(decision_cursor)
            .bind(high_water)
            .bind(i64::try_from(remaining).unwrap_or(i64::MAX))
            .fetch_all(&mut *transaction)
            .await?;
            let decision_rows_len = decision_rows.len();
            for row in decision_rows {
                let decision_id: i64 = row.try_get("decision_id")?;
                let entry: serde_json::Value = row.try_get("entry")?;
                let payload = encode_reconstructed_audit_v1(&entry)?;
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
                let outcome = dovecote_sqlx_mysql::import_for_migration(
                    &mut transaction,
                    event,
                    ImportedDeliveryState::pending(),
                )
                .await
                .map_err(MySqlBridgeError::DovecoteImport)?;
                insert_audit_mapping(
                    &mut transaction,
                    &publication,
                    import_row_id(&outcome)
                        .ok_or(MySqlBridgeError::UnsupportedOutcome)?
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

    /// Reads the persisted bridge mapping used by a legacy publisher.
    ///
    /// # Errors
    ///
    /// Returns [`MySqlBridgeError::MappingNotFound`] when no bridge mapping
    /// exists, or another typed error when persisted data is invalid.
    pub async fn legacy_outbox_publication(
        &self,
        legacy_outbox_id: i64,
    ) -> Result<super::bridge::BridgePublication, MySqlBridgeError> {
        let row = sqlx::query(
            "select source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
        )
        .bind(legacy_outbox_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MySqlBridgeError::MappingNotFound(legacy_outbox_id))?;
        let source = String::from_utf8(row.try_get::<Vec<u8>, _>("source")?)?;
        let event_id = String::from_utf8(row.try_get::<Vec<u8>, _>("event_id")?)?;
        let event_type = String::from_utf8(row.try_get::<Vec<u8>, _>("event_type")?)?;
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
        .map_err(MySqlBridgeError::Event)
    }

    /// Claims one bridge-mapped legacy row for the legacy publisher.
    ///
    /// The claim stores a fresh opaque generation in the bridge mapping. The
    /// generation is replaced on every successful acquisition, including a
    /// reclaim by the same worker with the same expiry. Callers must pass the
    /// returned token to [`Self::acknowledge_legacy_outbox_with_dovecote`].
    ///
    /// # Errors
    ///
    /// Returns [`MySqlBridgeError::LegacyClaimUnavailable`] when the row is
    /// already delivered or has an active legacy claim.
    pub async fn claim_legacy_outbox_with_dovecote(
        &self,
        legacy_outbox_id: i64,
        worker: &str,
        lease: Duration,
    ) -> Result<LegacyOutboxClaim, MySqlBridgeError> {
        let mut tx = self.pool.begin().await?;
        let _ = mapping_row_id(&mut tx, legacy_outbox_id).await?;
        let lease =
            time::Duration::try_from(lease).map_err(|error| MySqlBridgeError::StateTimestamp {
                detail: error.to_string(),
            })?;
        if lease.is_zero() || lease.is_negative() {
            return Err(MySqlBridgeError::StateTimestamp {
                detail: "legacy claim lease must be positive".to_owned(),
            });
        }

        let now: time::OffsetDateTime = sqlx::query_scalar("select current_timestamp(6)")
            .fetch_one(&mut *tx)
            .await?;
        let until = now
            .checked_add(lease)
            .ok_or_else(|| MySqlBridgeError::StateTimestamp {
                detail: "legacy claim expiry exceeds MySQL timestamp range".to_owned(),
            })?;
        let changed = sqlx::query(
            "update gatekeep_audit_outbox set claimed_by = ?, claimed_until = ? where id = ? and delivered_at is null and (claimed_until is null or claimed_until <= ?)",
        )
        .bind(worker)
        .bind(until)
        .bind(legacy_outbox_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if changed.rows_affected() != 1 {
            return Err(MySqlBridgeError::LegacyClaimUnavailable(legacy_outbox_id));
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
            return Err(MySqlBridgeError::MappingNotFound(legacy_outbox_id));
        }

        tx.commit().await?;
        Ok(LegacyOutboxClaim::new(legacy_outbox_id, token))
    }

    /// Acknowledges a claimed legacy row and finalizes its mapped Dovecote
    /// delivery atomically.
    ///
    /// # Errors
    ///
    /// Returns a typed bridge or Dovecote error if the claim is not owned by
    /// `worker`, the persisted mapping conflicts, or either transaction fails.
    pub async fn acknowledge_legacy_outbox_with_dovecote(
        &self,
        legacy_outbox_id: i64,
        worker: &str,
        claim_token: &str,
        delivered_at: time::OffsetDateTime,
    ) -> Result<(), MySqlBridgeError> {
        let mut tx = self.pool.begin().await?;
        let dovecote_row_id = mapping_row_id(&mut tx, legacy_outbox_id).await?;
        acknowledge_legacy_claim(&mut tx, legacy_outbox_id, worker, claim_token, delivered_at)
            .await?;
        dovecote_sqlx_mysql::finalize_pending_delivery_for_migration(
            &mut tx,
            dovecote_row_id,
            delivered_at,
        )
        .await
        .map_err(MySqlBridgeError::DovecoteFinalize)?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(feature = "dovecote-mysql")]
async fn acknowledge_legacy_claim(
    tx: &mut Transaction<'_, sqlx::MySql>,
    legacy_outbox_id: i64,
    worker: &str,
    claim_token: &str,
    delivered_at: time::OffsetDateTime,
) -> Result<(), MySqlBridgeError> {
    let row = sqlx::query(
        "select l.claimed_by, l.claimed_until, l.delivered_at, b.legacy_claim_token from gatekeep_audit_outbox l join gatekeep_dovecote_bridge_outbox b on b.legacy_outbox_id = l.id where l.id = ? for update",
    )
    .bind(legacy_outbox_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(MySqlBridgeError::MappingNotFound(legacy_outbox_id))?;
    let claimed_by: Option<String> = row.try_get("claimed_by")?;
    let persisted_until: Option<time::OffsetDateTime> = row.try_get("claimed_until")?;
    let existing_delivered: Option<time::OffsetDateTime> = row.try_get("delivered_at")?;
    let persisted_token: Option<String> = row.try_get("legacy_claim_token")?;
    if let Some(existing) = existing_delivered {
        return if existing == delivered_at && persisted_token.as_deref() == Some(claim_token) {
            Ok(())
        } else if existing == delivered_at {
            Err(MySqlBridgeError::AckNotOwned(legacy_outbox_id))
        } else {
            Err(MySqlBridgeError::AckConflict(legacy_outbox_id))
        };
    }

    let until = persisted_until.ok_or(MySqlBridgeError::AckNotOwned(legacy_outbox_id))?;
    if persisted_token.as_deref() != Some(claim_token) || claimed_by.as_deref() != Some(worker) {
        return Err(MySqlBridgeError::AckNotOwned(legacy_outbox_id));
    }

    let changed = sqlx::query(
        "update gatekeep_audit_outbox set delivered_at = ?, claimed_by = null, claimed_until = null where id = ? and claimed_by = ? and claimed_until = ? and claimed_until > current_timestamp(6) and delivered_at is null",
    )
    .bind(delivered_at)
    .bind(legacy_outbox_id)
    .bind(worker)
    .bind(until)
    .execute(&mut **tx)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(MySqlBridgeError::AckNotOwned(legacy_outbox_id));
    }

    Ok(())
}

#[cfg(feature = "dovecote-mysql")]
async fn fence_expired_legacy_claim(
    tx: &mut Transaction<'_, sqlx::MySql>,
    id: i64,
    until: time::OffsetDateTime,
    claimed_by: Option<&str>,
) -> Result<(), MySqlBridgeError> {
    let fenced = sqlx::query(
        "update gatekeep_audit_outbox set claimed_by = null, claimed_until = null where id = ? and claimed_until = ? and claimed_by <=> ?",
    )
    .bind(id)
    .bind(until)
    .bind(claimed_by)
    .execute(&mut **tx)
    .await?;
    if fenced.rows_affected() != 1 {
        return Err(MySqlBridgeError::LegacyClaimed(id));
    }
    Ok(())
}

#[cfg(feature = "dovecote-mysql")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
/// Errors returned by `MySQL` dual-write and history-import operations.
pub enum MySqlBridgeError {
    /// `SQLx` returned an error.
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    /// Legacy audit payload could not be encoded or decoded.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Bridge event identity or payload validation failed.
    #[error(transparent)]
    Event(#[from] BridgeEventError),
    /// A database row ID did not fit the portable i64 representation.
    #[error("legacy decision/outbox row ID does not fit i64: {0}")]
    IdOverflow(u64),
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
    /// A legacy publisher currently owns the row being imported.
    #[error("legacy outbox row {0} has an active claim")]
    LegacyClaimed(i64),
    /// The legacy publisher does not own an unexpired claim for the row.
    #[error("legacy outbox row {0} is not conditionally owned by the publisher")]
    AckNotOwned(i64),
    /// The row cannot be acquired because it is delivered or actively claimed.
    #[error("legacy outbox row {0} cannot be acquired by the bridge")]
    LegacyClaimUnavailable(i64),
    /// The row was already acknowledged with a different delivery time.
    #[error("legacy outbox row {0} was already acknowledged with a different delivery time")]
    AckConflict(i64),
    /// A claim lease or expiry could not be represented safely.
    #[error("invalid bridge claim timestamp: {detail}")]
    StateTimestamp {
        /// Explanation of the invalid timestamp or duration.
        detail: String,
    },
    /// A persisted identity field is not valid UTF-8.
    #[error("persisted bridge identity is not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    /// The configured Dovecote adapter returned an unknown outcome.
    #[error("Dovecote returned an unsupported import outcome")]
    UnsupportedOutcome,
    /// The legacy audit write failed.
    #[error(transparent)]
    Audit(#[from] SqlxAuditError),
    /// Dovecote rejected the imported delivery state.
    #[error("invalid imported delivery state: {0}")]
    State(#[source] dovecote::ValidationError),
    /// Dovecote rejected a dual-write enqueue.
    #[error("Dovecote enqueue failed: {0}")]
    Dovecote(#[source] dovecote_sqlx_mysql::EnqueueError),
    /// Dovecote rejected a history import.
    #[error("Dovecote import failed: {0}")]
    DovecoteImport(#[source] dovecote_sqlx_mysql::ImportError),
    /// Dovecote pending delivery finalization failed.
    #[error("Dovecote delivery finalization failed: {0}")]
    DovecoteFinalize(#[source] dovecote_sqlx_mysql::FinalizeError),
}

#[async_trait]
impl SqlxAuditStore<crate::MySqlBackend> for MySqlDecisionAuditRepository {
    async fn record_decision_audit(&self, entry: &AuditEntry) -> Result<i64, SqlxAuditError> {
        let mut tx = self.pool.begin().await?;
        let denial_reason_json = entry
            .denial_reason
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let result = sqlx::query(
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
        .bind(serde_json::to_value(&entry.trace)?)
        .bind(serde_json::to_value(&entry.decisive)?)
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
        .bind(serde_json::to_value(entry)?)
        .execute(&mut *tx)
        .await?;
        let id =
            i64::try_from(result.last_insert_id()).map_err(|_| SqlxAuditError::IdOverflow {
                id: result.last_insert_id(),
            })?;
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
        records_from_json_rows(rows)
    }
}

async fn insert_children(
    tx: &mut Transaction<'_, sqlx::MySql>,
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
                "insert into gatekeep_audit_reason_params (decision_id, `key`, value) values (?, ?, ?)",
            )
            .bind(decision_id)
            .bind(key.as_str())
            .bind(serde_json::to_value(value)?)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn insert_outbox(
    tx: &mut Transaction<'_, sqlx::MySql>,
    decision_id: i64,
    entry: &AuditEntry,
) -> Result<(), SqlxAuditError> {
    sqlx::query("insert into gatekeep_audit_outbox (decision_id, payload) values (?, ?)")
        .bind(decision_id)
        .bind(serde_json::to_value(entry)?)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(feature = "dovecote-mysql")]
async fn ensure_bridge_configuration(
    tx: &mut Transaction<'_, sqlx::MySql>,
    bridge: &DovecoteAuditBridge,
) -> Result<(), MySqlBridgeError> {
    sqlx::query(
        "insert into gatekeep_dovecote_bridge_state (id, source, stream, `cursor`) values (1, ?, ?, 0) on duplicate key update id = id",
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
        return Err(MySqlBridgeError::StateConflict);
    }
    Ok(())
}

#[cfg(feature = "dovecote-mysql")]
async fn insert_outbox_with_id(
    tx: &mut Transaction<'_, sqlx::MySql>,
    decision_id: i64,
    payload: &[u8],
) -> Result<i64, MySqlBridgeError> {
    let result =
        sqlx::query("insert into gatekeep_audit_outbox (decision_id, payload) values (?, ?)")
            .bind(decision_id)
            .bind(serde_json::from_slice::<serde_json::Value>(payload)?)
            .execute(&mut **tx)
            .await?;
    i64::try_from(result.last_insert_id())
        .map_err(|_| MySqlBridgeError::IdOverflow(result.last_insert_id()))
}

#[cfg(feature = "dovecote-mysql")]
async fn insert_bridge_mapping(
    tx: &mut Transaction<'_, sqlx::MySql>,
    publication: &super::bridge::BridgePublication,
    dovecote_row_id: i64,
) -> Result<(), MySqlBridgeError> {
    sqlx::query(
        "insert into gatekeep_dovecote_bridge_outbox (legacy_outbox_id, source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest, dovecote_row_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?) on duplicate key update legacy_outbox_id = legacy_outbox_id",
    )
    .bind(publication.legacy_outbox_id())
    .bind(publication.source().as_bytes())
    .bind(publication.event_id().as_bytes())
    .bind(publication.event_type().as_bytes())
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
    let source = String::from_utf8(row.try_get::<Vec<u8>, _>("source")?)?;
    let event_id = String::from_utf8(row.try_get::<Vec<u8>, _>("event_id")?)?;
    let event_type = String::from_utf8(row.try_get::<Vec<u8>, _>("event_type")?)?;
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
        return Err(MySqlBridgeError::MappingConflict);
    }
    Ok(())
}

#[cfg(feature = "dovecote-mysql")]
async fn persisted_bridge_mapping(
    tx: &mut Transaction<'_, sqlx::MySql>,
    legacy_outbox_id: i64,
) -> Result<Option<super::bridge::BridgePublication>, MySqlBridgeError> {
    let row = sqlx::query(
        "select source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
    )
    .bind(legacy_outbox_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    let source = String::from_utf8(row.try_get::<Vec<u8>, _>("source")?)?;
    let event_id = String::from_utf8(row.try_get::<Vec<u8>, _>("event_id")?)?;
    let event_type = String::from_utf8(row.try_get::<Vec<u8>, _>("event_type")?)?;
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
    .map_err(MySqlBridgeError::Event)
}

#[cfg(feature = "dovecote-mysql")]
async fn insert_audit_mapping(
    tx: &mut Transaction<'_, sqlx::MySql>,
    publication: &LegacyAuditPublication,
    dovecote_row_id: i64,
) -> Result<(), MySqlBridgeError> {
    sqlx::query(
        "insert into gatekeep_dovecote_bridge_audit (decision_id, source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest, dovecote_row_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?) on duplicate key update decision_id = decision_id",
    )
    .bind(publication.decision_id)
    .bind(publication.source.as_bytes())
    .bind(publication.event_id.as_bytes())
    .bind(publication.event_type.as_bytes())
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
    let source = String::from_utf8(row.try_get::<Vec<u8>, _>("source")?)?;
    let event_id = String::from_utf8(row.try_get::<Vec<u8>, _>("event_id")?)?;
    let event_type = String::from_utf8(row.try_get::<Vec<u8>, _>("event_type")?)?;
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
        return Err(MySqlBridgeError::MappingConflict);
    }
    Ok(())
}

#[cfg(feature = "dovecote-mysql")]
async fn persisted_audit_mapping(
    tx: &mut Transaction<'_, sqlx::MySql>,
    decision_id: i64,
) -> Result<Option<LegacyAuditPublication>, MySqlBridgeError> {
    let row = sqlx::query(
        "select source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest from gatekeep_dovecote_bridge_audit where decision_id = ?",
    )
    .bind(decision_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    let source = String::from_utf8(row.try_get::<Vec<u8>, _>("source")?)?;
    let event_id = String::from_utf8(row.try_get::<Vec<u8>, _>("event_id")?)?;
    let event_type = String::from_utf8(row.try_get::<Vec<u8>, _>("event_type")?)?;
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
    .map_err(MySqlBridgeError::Event)
}

#[cfg(feature = "dovecote-mysql")]
async fn mapping_row_id(
    tx: &mut Transaction<'_, sqlx::MySql>,
    legacy_outbox_id: i64,
) -> Result<dovecote::RowId, MySqlBridgeError> {
    let value: i64 = sqlx::query_scalar(
        "select dovecote_row_id from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
    )
    .bind(legacy_outbox_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(MySqlBridgeError::MappingNotFound(legacy_outbox_id))?;
    dovecote::RowId::new(value).map_err(|_| MySqlBridgeError::MappingConflict)
}

#[cfg(feature = "dovecote-mysql")]
async fn claim_import_state(
    tx: &mut Transaction<'_, sqlx::MySql>,
    bridge: &DovecoteAuditBridge,
    options: &BridgeImportOptions,
) -> Result<String, MySqlBridgeError> {
    sqlx::query(
        "insert into gatekeep_dovecote_bridge_state (id, source, stream, `cursor`) values (1, ?, ?, 0) on duplicate key update id = id",
    )
    .bind(bridge.source().as_str())
    .bind(bridge.stream().as_str())
    .execute(&mut **tx)
    .await?;
    let configured: (String, String) =
        sqlx::query_as("select source, stream from gatekeep_dovecote_bridge_state where id = 1")
            .fetch_one(&mut **tx)
            .await?;
    if configured.0 != bridge.source().as_str() || configured.1 != bridge.stream().as_str() {
        return Err(MySqlBridgeError::StateConflict);
    }

    let token = new_claim_token(options.worker());
    let lease_millis =
        i64::try_from(options.lease().as_millis()).map_err(|_| MySqlBridgeError::StateConflict)?;
    let claimed = sqlx::query(
        "update gatekeep_dovecote_bridge_state set claimed_by = ?, claim_token = ?, claim_until = (unix_timestamp(current_timestamp(6)) * 1000 + ?) where id = 1 and (claim_until is null or claim_until <= unix_timestamp(current_timestamp(6)) * 1000)",
    )
    .bind(options.worker())
    .bind(&token)
    .bind(lease_millis)
    .execute(&mut **tx)
    .await?;
    if claimed.rows_affected() != 1 {
        return Err(MySqlBridgeError::Claimed);
    }
    Ok(token)
}

#[cfg(feature = "dovecote-mysql")]
async fn state_position(
    tx: &mut Transaction<'_, sqlx::MySql>,
) -> Result<(i64, i64, i64, i64), MySqlBridgeError> {
    let row = sqlx::query("select high_water, `cursor`, outbox_high_water, outbox_cursor, (select max(id) from gatekeep_audit_decisions) as latest_id, (select max(id) from gatekeep_audit_outbox) as latest_outbox_id from gatekeep_dovecote_bridge_state where id = 1")
        .fetch_one(&mut **tx)
        .await?;
    let high_water: Option<i64> = row.try_get("high_water")?;
    let cursor: i64 = row.try_get("cursor")?;
    let outbox_high_water: Option<i64> = row.try_get("outbox_high_water")?;
    let outbox_cursor: i64 = row.try_get("outbox_cursor")?;
    let latest_id: Option<i64> = row.try_get("latest_id")?;
    let latest_outbox_id: Option<i64> = row.try_get("latest_outbox_id")?;
    let latest_id = latest_id.unwrap_or(0);
    let latest_outbox_id = latest_outbox_id.unwrap_or(0);
    let high_water = if high_water.is_none_or(|value| cursor >= value) {
        latest_id.max(cursor)
    } else {
        high_water.unwrap_or(0)
    };

    let outbox_high_water = if outbox_high_water.is_none_or(|value| outbox_cursor >= value) {
        latest_outbox_id.max(outbox_cursor)
    } else {
        outbox_high_water.unwrap_or(0)
    };
    if row.try_get::<Option<i64>, _>("high_water")? != Some(high_water) {
        sqlx::query("update gatekeep_dovecote_bridge_state set high_water = ? where id = 1")
            .bind(high_water)
            .execute(&mut **tx)
            .await?;
    }

    if row.try_get::<Option<i64>, _>("outbox_high_water")? != Some(outbox_high_water) {
        sqlx::query("update gatekeep_dovecote_bridge_state set outbox_high_water = ? where id = 1")
            .bind(outbox_high_water)
            .execute(&mut **tx)
            .await?;
    }
    Ok((high_water, cursor, outbox_high_water, outbox_cursor))
}

#[cfg(feature = "dovecote-mysql")]
async fn advance_import_state(
    tx: &mut Transaction<'_, sqlx::MySql>,
    token: &str,
    cursor: i64,
) -> Result<(), MySqlBridgeError> {
    let changed = sqlx::query(
        "update gatekeep_dovecote_bridge_state set `cursor` = ? where id = 1 and claim_token = ?",
    )
    .bind(cursor)
    .bind(token)
    .execute(&mut **tx)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(MySqlBridgeError::LostClaim);
    }
    Ok(())
}

#[cfg(feature = "dovecote-mysql")]
async fn advance_outbox_state(
    tx: &mut Transaction<'_, sqlx::MySql>,
    token: &str,
    cursor: i64,
) -> Result<(), MySqlBridgeError> {
    let changed = sqlx::query(
        "update gatekeep_dovecote_bridge_state set outbox_cursor = ? where id = 1 and claim_token = ?",
    )
    .bind(cursor)
    .bind(token)
    .execute(&mut **tx)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(MySqlBridgeError::LostClaim);
    }
    Ok(())
}

#[cfg(feature = "dovecote-mysql")]
async fn release_import_state(
    tx: &mut Transaction<'_, sqlx::MySql>,
    token: &str,
) -> Result<(), MySqlBridgeError> {
    let changed = sqlx::query(
        "update gatekeep_dovecote_bridge_state set claimed_by = null, claim_token = null, claim_until = null where id = 1 and claim_token = ?",
    )
    .bind(token)
    .execute(&mut **tx)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(MySqlBridgeError::LostClaim);
    }
    Ok(())
}
