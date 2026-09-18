use crate::{Access, App, ExampleError, ListView, View, context};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use dovecote::{ContentType, EventData, EventId, EventSource, EventType, NewEvent, StreamName};
use gatekeep::{
    Clock, Context, DecisionAuditId, DecisionAuditOccurrence, FactId, PartialFacts, Presence,
    SystemClock, partial_evaluate,
};
use gatekeep_sqlx::{
    SqlOutcome, SqliteBackend, SqlxFactPredicates, SqlxFragment, SqlxLowerer, TenantColumn,
};
use sqlx::{QueryBuilder, Sqlite};
use std::sync::Arc;

impl SqlOutcome for Access {
    fn to_sql_ordinal(&self) -> i64 {
        match self {
            Self::Released => 0,
            Self::Shared => 1,
            Self::Full => 2,
        }
    }
}
struct Predicates {
    now: i64,
}
impl SqlxFactPredicates<SqliteBackend> for Predicates {
    fn predicate(&self, fact: &FactId, _: &Context) -> Option<SqlxFragment<SqliteBackend>> {
        let sql = match fact.as_str() {
            "record.owner" => "access.owner",
            "record.shared" => "access.shared",
            "record.released" => "access.released",
            "person.enabled" => "access.enabled",
            "record.emergency" => {
                let mut predicate = SqlxFragment::trusted("access.emergency_until > ");
                predicate.push_fragment(SqlxFragment::bind(self.now));
                return Some(predicate);
            }
            _ => return None,
        };
        Some(SqlxFragment::trusted(sql))
    }
}

impl App {
    pub(crate) async fn list(
        State(app): State<Arc<Self>>,
        Path(person): Path<String>,
    ) -> Result<Json<ListView>, StatusCode> {
        list_records(&app, &person)
            .await
            .map(Json)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

async fn list_records(app: &App, person: &str) -> Result<ListView, ExampleError> {
    let context = context("demo", person, "list")?;
    let store = dovecote_sqlx_sqlite::SqliteDovecote::new(app.pool.clone());
    let mut transaction = store.begin_write().await?;
    let now = SystemClock.now_utc();
    context.validate_at(now)?;
    let lowerer = SqlxLowerer::new(
        Predicates {
            now: now.unix_timestamp(),
        },
        TenantColumn::new("records", "tenant")?,
    );
    let partial = PartialFacts::from_entries(
        app.policy
            .required_facts()
            .iter()
            .cloned()
            .map(|fact| (fact, Presence::Unknown)),
    );
    let plan = lowerer.lower_result(&partial_evaluate(app.policy.policy(), &partial), &context)?;
    let mut count = QueryBuilder::<Sqlite>::new("SELECT count(*)");
    append_source(&mut count, person, &plan.filter);
    let total = count
        .build_query_scalar::<i64>()
        .fetch_one(&mut *transaction)
        .await?;
    let mut query = QueryBuilder::<Sqlite>::new(
        "SELECT id, access_grade, summary, CASE WHEN access_grade >= 1 THEN shared_notes END, CASE WHEN access_grade >= 2 THEN private_notes END FROM (SELECT records.*, ",
    );
    plan.grade.push_to(&mut query);
    query.push(" AS access_grade");
    append_source(&mut query, person, &plan.filter);
    query.push(") authorized ORDER BY id LIMIT 20 OFFSET 0");
    let rows = query
        .build_query_as::<(String, i64, String, Option<String>, Option<String>)>()
        .fetch_all(&mut *transaction)
        .await?;
    let records = rows
        .into_iter()
        .map(|row| {
            let access = match row.1 {
                0 => Access::Released,
                1 => Access::Shared,
                2 => Access::Full,
                _ => return Err("unrecognized access grade"),
            };
            Ok(View {
                id: row.0,
                access,
                summary: row.2,
                shared_notes: row.3,
                private_notes: row.4,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Application-owned disclosure event: real rows/grades, never fabricated
    // point-evaluation traces. It records assembly, not receipt by a client.
    let occurrence = DecisionAuditOccurrence::new(DecisionAuditId::generate(), now)?;
    let payload = serde_json::json!({"schema_version": 1, "policy": app.policy.anchor(), "principal": context.principal(), "rows": records.iter().map(|record| (&record.id, record.access)).collect::<Vec<_>>()});
    let event = NewEvent::builder(
        StreamName::new("record-disclosures")?,
        EventId::new(occurrence.decision_audit_id().as_str())?,
        EventSource::new("https://record-demo.example/audit")?,
        EventType::new("record_demo.list_assembled")?,
    )
    .time(occurrence.occurred_at())
    .datacontenttype(ContentType::new("application/json")?)
    .data(EventData::json(serde_json::to_vec(&payload)?)?)
    .build()?;
    store
        .for_tenant(dovecote::TenantId::new(context.tenant().as_str())?)
        .enqueue(&mut transaction, event)
        .await?;
    transaction.commit().await?;
    Ok(ListView { total, records })
}

fn append_source(
    query: &mut QueryBuilder<Sqlite>,
    person: &str,
    filter: &SqlxFragment<SqliteBackend>,
) {
    query.push(" FROM records LEFT JOIN record_access access ON access.tenant = records.tenant AND access.record = records.id AND access.person = ");
    query.push_bind(person.to_owned());
    query.push(" WHERE ");
    filter.push_to(query);
}
