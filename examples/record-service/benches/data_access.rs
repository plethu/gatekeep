//! Database calls and SQL construction are measured separately from evaluation.
use gatekeep::{
    BatchFactResolver, Context, FactId, FactResolver, PartialFacts, PolicyId, PreparedPolicy,
    SystemClock, partial_evaluate,
};
use gatekeep_example_record_service::{
    ExampleError, RecordResolver, context, database, read_policy,
};
use gatekeep_sqlx::{SqliteBackend, SqlxFactPredicates, SqlxFragment, SqlxLowerer, TenantColumn};
use std::{hint::black_box, time::Instant};

struct Predicates;
impl SqlxFactPredicates<SqliteBackend> for Predicates {
    fn predicate(&self, _: &FactId, _: &Context) -> Option<SqlxFragment<SqliteBackend>> {
        Some(SqlxFragment::trusted("records.flag"))
    }
}

#[tokio::main]
async fn main() -> Result<(), ExampleError> {
    let resolver = RecordResolver::new(database().await?);
    let policy = PreparedPolicy::new(PolicyId::new("read")?, read_policy()?)?;
    let contexts = [
        context("demo", "owner", "one")?,
        context("demo", "parent", "one")?,
        context("demo", "admin", "one")?,
    ];
    let started = Instant::now();
    for _ in 0..100 {
        for context in &contexts {
            black_box(
                resolver
                    .resolve_for_decision(policy.required_facts(), context, &SystemClock)
                    .await?,
            );
        }
    }
    println!(
        "single source resolution: {:?}, {} database calls",
        started.elapsed(),
        resolver.query_count()
    );
    let calls = resolver.query_count();
    let started = Instant::now();
    for _ in 0..100 {
        let results = resolver
            .resolve_batch(policy.required_facts(), &contexts, &SystemClock)
            .await?;
        for result in results {
            black_box(result?);
        }
    }
    println!(
        "batch source resolution: {:?}, {} database calls",
        started.elapsed(),
        resolver.query_count() - calls
    );
    let facts = PartialFacts::from_entries(
        policy
            .required_facts()
            .iter()
            .cloned()
            .map(|fact| (fact, gatekeep::Presence::Unknown)),
    );
    let residual = partial_evaluate(policy.policy(), &facts);
    let lowerer = SqlxLowerer::new(Predicates, TenantColumn::new("records", "tenant")?);
    let started = Instant::now();
    for _ in 0..10_000 {
        black_box(lowerer.lower_result(&residual, &contexts[0])?);
    }
    println!(
        "SQL construction: {:?} / 10000 iterations (no queries)",
        started.elapsed()
    );
    Ok(())
}
