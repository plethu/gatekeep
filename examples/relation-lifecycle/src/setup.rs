//! Additive fixture setup; no existing rows or schemas are deleted.
use dovecote_sqlx_postgres::PostgresDovecote;
use gatekeep_sqlx::PgDovecoteAudit;
use keepsake::{ExpiryPolicy, RelationDefinition, RelationKey, TenantId};
use keepsake_sqlx::KeepsakeRepository;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    Result,
    store::{BLOCK, Consumer, RESTRICTION},
};

pub async fn consumer(url: &str) -> Result<Consumer> {
    let pool = PgPool::connect(url).await?;
    let relations =
        KeepsakeRepository::new(pool.clone(), "https://example.invalid/keepsake-consumer")?;
    relations.migrate().await?;
    let installed: bool =
        sqlx::query_scalar("SELECT to_regclass('public.dovecote_schema') IS NOT NULL")
            .fetch_one(&pool)
            .await?;
    if !installed {
        sqlx::raw_sql(
            dovecote_sqlx_postgres::MIGRATIONS
                .first()
                .ok_or("Dovecote fixture migration is missing")?
                .sql(),
        )
        .execute(&pool)
        .await?;
    }

    relations.check_schema().await?;
    let audit = PgDovecoteAudit::new(pool.clone(), "https://example.invalid/gatekeep-consumer")?;
    audit.check_schema().await?;
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS application_authorities (tenant_id text NOT NULL, principal text NOT NULL, enabled boolean NOT NULL, PRIMARY KEY(tenant_id,principal));
         CREATE TABLE IF NOT EXISTS application_actions (tenant_id text NOT NULL, command_id text NOT NULL, command bytea NOT NULL, assignment_id uuid NOT NULL, PRIMARY KEY(tenant_id,command_id));
         CREATE TABLE IF NOT EXISTS application_sessions (tenant_id text NOT NULL, session_id text NOT NULL, PRIMARY KEY(tenant_id,session_id));",
    ).execute(&pool).await?;
    let tenant = TenantId::new(format!("synthetic-{}", Uuid::new_v4()))?;
    for principal in ["operator", "alice"] {
        sqlx::query("INSERT INTO application_authorities VALUES ($1,$2,true)")
            .bind(tenant.as_str())
            .bind(principal)
            .execute(&pool)
            .await?;
    }

    let scoped = relations.for_tenant(tenant.clone());
    for (id, name) in [(BLOCK, "block"), (RESTRICTION, "restriction")] {
        scoped
            .upsert_relation(
                &RelationDefinition::enabled(
                    tenant.clone(),
                    id,
                    RelationKey::new("synthetic", name)?,
                    ExpiryPolicy::ManualOnly,
                )?,
                time::OffsetDateTime::UNIX_EPOCH,
            )
            .await?;
    }

    Ok(Consumer {
        outbox: PostgresDovecote::new(pool.clone()),
        pool,
        relations,
        audit,
        tenant,
    })
}
