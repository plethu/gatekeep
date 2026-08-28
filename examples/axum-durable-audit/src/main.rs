//! Runnable, compile-checked setup for Axum authorization with durable audit.

use std::{convert::Infallible, env};

use async_trait::async_trait;
use gatekeep::{
    BindingProvenance, Clock, Context, FactId, FactResolution, FactResolutionMetadata,
    FactResolver, KnownFacts, PartialFacts, ResolveError,
};
use gatekeep_axum::Gatekeeper;
use gatekeep_sqlx::PgDovecoteAudit;
use sqlx::PgPool;

type DurableGatekeeper = Gatekeeper<ApplicationFactResolver, PgDovecoteAudit>;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let database_url = env::var("DATABASE_URL")?;
        let pool = PgPool::connect(&database_url).await?;
        let _gatekeeper = build_gatekeeper(pool).await?;
        Ok(())
    })
}

async fn build_gatekeeper(
    pool: PgPool,
) -> Result<DurableGatekeeper, Box<dyn std::error::Error + Send + Sync>> {
    let audit = PgDovecoteAudit::new(pool, "https://auth.example.test/gatekeep")?;
    audit.check_schema().await?;
    Ok(Gatekeeper::new(ApplicationFactResolver, audit))
}

/// Application-owned fact lookup used by this setup example.
#[derive(Clone, Copy)]
struct ApplicationFactResolver;

#[async_trait]
impl FactResolver for ApplicationFactResolver {
    type Error = Infallible;

    async fn resolve_for_decision(
        &self,
        _required: &[FactId],
        _cx: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<KnownFacts>, ResolveError<Self::Error>> {
        let metadata = BindingProvenance::new("example.application-facts")
            .ok()
            .map(|source| FactResolutionMetadata::new(source, None, None));
        FactResolution::new(KnownFacts::new(), metadata, clock.now_utc())
            .map_err(ResolveError::Resolution)
    }

    async fn resolve_for_query(
        &self,
        _required: &[FactId],
        _cx: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<PartialFacts>, ResolveError<Self::Error>> {
        FactResolution::new(PartialFacts::new(), None, clock.now_utc())
            .map_err(ResolveError::Resolution)
    }
}
