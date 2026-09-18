use crate::{Emergency, Enabled, Owner, Released, Shared};
use async_trait::async_trait;
use gatekeep::{
    BatchFactResolver, Clock, Context, FactId, FactResolution, FactResolver, KnownFacts,
    PartialFacts, QueryFactResolver, ResolveError,
};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};
use std::{
    collections::BTreeMap,
    slice,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// One provider batch uses one metadata query, regardless of the number of records.
#[derive(Clone)]
pub struct RecordResolver {
    pool: SqlitePool,
    queries: Arc<AtomicUsize>,
}

type PermissionRow = (String, String, String, bool, bool, bool, bool, Option<i64>);
type PermissionKey = (String, String, String);

impl RecordResolver {
    /// Uses the application's database pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            queries: Arc::new(AtomicUsize::new(0)),
        }
    }
    /// Counts metadata SQL calls, independently of audit and disclosure reads.
    #[must_use]
    pub fn query_count(&self) -> usize {
        self.queries.load(Ordering::Relaxed)
    }

    async fn load(
        &self,
        contexts: &[Context],
    ) -> Result<BTreeMap<PermissionKey, PermissionRow>, sqlx::Error> {
        let mut query = QueryBuilder::<Sqlite>::new(
            "SELECT tenant, person, record, enabled, owner, shared, released, emergency_until FROM record_access WHERE ",
        );
        let mut clauses = query.separated(" OR ");
        for context in contexts {
            let record = record_id(context);
            clauses
                .push("(tenant = ")
                .push_bind_unseparated(context.tenant().as_str())
                .push_unseparated(" AND person = ")
                .push_bind_unseparated(context.principal().id())
                .push_unseparated(" AND record = ")
                .push_bind_unseparated(record)
                .push_unseparated(")");
        }

        self.queries.fetch_add(1, Ordering::Relaxed);
        let rows = query
            .build_query_as::<PermissionRow>()
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| ((row.0.clone(), row.1.clone(), row.2.clone()), row))
            .collect())
    }
}

fn record_id(context: &Context) -> &str {
    if context.principal().kind() != "person" {
        return "";
    }
    context
        .subjects()
        .iter()
        .find(|(slot, subject)| slot.as_str() == "record" && subject.kind() == "record")
        .map_or("", |(_, subject)| subject.id())
}

/// Resolves permission metadata while the caller holds the `SQLite` write fence.
///
/// # Errors
/// Returns source or freshness errors.
pub async fn resolve_in_transaction(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    context: &Context,
    clock: &dyn Clock,
) -> Result<FactResolution<KnownFacts>, ResolveError<sqlx::Error>> {
    let row = sqlx::query_as::<_, PermissionRow>("SELECT tenant, person, record, enabled, owner, shared, released, emergency_until FROM record_access WHERE tenant = ? AND person = ? AND record = ?")
        .bind(context.tenant().as_str()).bind(context.principal().id()).bind(record_id(context))
        .fetch_optional(&mut **transaction).await?;
    resolution(row.as_ref(), clock.now_utc())
}

fn resolution(
    row: Option<&PermissionRow>,
    now: time::OffsetDateTime,
) -> Result<FactResolution<KnownFacts>, ResolveError<sqlx::Error>> {
    let expiry = row
        .and_then(|row| row.7)
        .filter(|expiry| *expiry > now.unix_timestamp())
        .map(time::OffsetDateTime::from_unix_timestamp)
        .transpose()
        .map_err(|error| ResolveError::Backend(sqlx::Error::Decode(Box::new(error))))?;
    let source = gatekeep::BindingProvenance::new("sqlite.record-access")
        .map_err(|error| ResolveError::Backend(sqlx::Error::Decode(Box::new(error))))?;
    FactResolution::new(
        facts(row, now.unix_timestamp()),
        Some(gatekeep::FactResolutionMetadata::new(source, None, expiry)),
        now,
    )
    .map_err(ResolveError::Resolution)
}

fn facts(row: Option<&PermissionRow>, now: i64) -> KnownFacts {
    KnownFacts::new()
        .with_bool::<Enabled>(row.is_some_and(|row| row.3))
        .with_bool::<Owner>(row.is_some_and(|row| row.4))
        .with_bool::<Shared>(row.is_some_and(|row| row.5))
        .with_bool::<Released>(row.is_some_and(|row| row.6))
        .with_bool::<Emergency>(row.and_then(|row| row.7).is_some_and(|expiry| now < expiry))
}

#[async_trait]
impl FactResolver for RecordResolver {
    type Error = sqlx::Error;
    async fn resolve_for_decision(
        &self,
        required: &[FactId],
        context: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<KnownFacts>, ResolveError<Self::Error>> {
        self.resolve_batch(required, slice::from_ref(context), clock)
            .await?
            .pop()
            .ok_or_else(|| ResolveError::Backend(sqlx::Error::RowNotFound))?
    }
}

#[async_trait]
impl QueryFactResolver for RecordResolver {
    async fn resolve_for_query(
        &self,
        required: &[FactId],
        _context: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<PartialFacts>, ResolveError<Self::Error>> {
        let facts = PartialFacts::from_entries(
            required
                .iter()
                .cloned()
                .map(|fact| (fact, gatekeep::Presence::Unknown)),
        );
        FactResolution::new(facts, None, clock.now_utc()).map_err(ResolveError::Resolution)
    }
}

#[async_trait]
impl BatchFactResolver for RecordResolver {
    async fn resolve_batch(
        &self,
        _required: &[FactId],
        contexts: &[Context],
        clock: &dyn Clock,
    ) -> Result<
        Vec<Result<FactResolution<KnownFacts>, ResolveError<Self::Error>>>,
        ResolveError<Self::Error>,
    > {
        if contexts.is_empty() {
            return Ok(Vec::new());
        }

        let rows = self.load(contexts).await?;
        let now = clock.now_utc();
        Ok(contexts
            .iter()
            .map(|context| {
                let record = record_id(context);
                let row = rows.get(&(
                    context.tenant().as_str().to_owned(),
                    context.principal().id().to_owned(),
                    record.to_owned(),
                ));
                resolution(row, now)
            })
            .collect())
    }
}
