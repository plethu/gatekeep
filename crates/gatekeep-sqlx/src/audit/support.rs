use gatekeep::AuditEntry;
use sqlx::Row;

use super::{DecisionAuditRecord, SqlxAuditError};

#[cfg(any(feature = "postgres", feature = "mysql"))]
pub(super) fn records_from_json_rows<R>(
    rows: Vec<R>,
) -> Result<Vec<DecisionAuditRecord>, SqlxAuditError>
where
    R: Row,
    for<'r> &'r str: sqlx::ColumnIndex<R>,
    for<'r> i64: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    for<'r> serde_json::Value: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    rows.into_iter()
        .map(|row| {
            let id: i64 = row.try_get("id")?;
            let entry = serde_json::from_value::<AuditEntry>(row.try_get("entry")?)?;
            Ok(DecisionAuditRecord { id, entry })
        })
        .collect()
}

#[cfg(feature = "sqlite")]
pub(super) fn records_from_text_rows<R>(
    rows: Vec<R>,
) -> Result<Vec<DecisionAuditRecord>, SqlxAuditError>
where
    R: Row,
    for<'r> &'r str: sqlx::ColumnIndex<R>,
    for<'r> i64: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    for<'r> String: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    rows.into_iter()
        .map(|row| {
            let id: i64 = row.try_get("id")?;
            let entry_json: String = row.try_get("entry")?;
            let entry = serde_json::from_str(&entry_json)?;
            Ok(DecisionAuditRecord { id, entry })
        })
        .collect()
}

pub(super) const fn effect_label(entry: &AuditEntry) -> &'static str {
    match entry.effect {
        gatekeep::EffectKind::Permit => "permit",
        gatekeep::EffectKind::Deny => "deny",
    }
}

pub(super) const fn deny_shape_label(shape: gatekeep::DenyShape) -> &'static str {
    match shape {
        gatekeep::DenyShape::Forbidden => "forbidden",
        gatekeep::DenyShape::Hidden => "hidden",
    }
}

pub(super) fn position_i32(position: usize) -> i32 {
    i32::try_from(position).unwrap_or(i32::MAX)
}

pub(super) const fn presence_label(presence: gatekeep::Presence) -> &'static str {
    match presence {
        gatekeep::Presence::Present => "present",
        gatekeep::Presence::Absent => "absent",
        gatekeep::Presence::Unknown => "unknown",
    }
}
