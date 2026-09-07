//! Caller-owned transactions. Every error requires the caller to roll back.
use dovecote::{EventId, EventSource, EventType, NewEvent, StreamName};
use dovecote_sqlx_postgres::PostgresDovecote;
use gatekeep::policy::permit;
use gatekeep::{FactId, KnownFacts, Presence};
use gatekeep_keepsake::KeepsakeRelationTarget;
use gatekeep_sqlx::PgDovecoteAudit;
use keepsake::{ApplyKeepsake, ObservationTime, SubjectRef, TenantId};
use keepsake_sqlx::KeepsakeRepository;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    Result,
    policy::{self, DecisionContext},
};

pub const BLOCK: Uuid = Uuid::from_u128(1);
pub const RESTRICTION: Uuid = Uuid::from_u128(2);

pub struct Consumer {
    pub pool: PgPool,
    pub relations: KeepsakeRepository,
    pub audit: PgDovecoteAudit,
    pub outbox: PostgresDovecote,
    pub tenant: TenantId,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied(Uuid),
    Replayed(Uuid),
    Denied,
}

/// Injective, direction-preserving encoding for this fixture's account IDs.
/// A production identity mapper owns its durable mapping and byte limits.
pub fn pair(first: &str, second: &str) -> Result<SubjectRef> {
    Ok(SubjectRef::new(
        "directed-account-pair",
        format!("{}:{first}{second}", first.len()),
    )?)
}

impl Consumer {
    pub async fn authenticate(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        principal: &str,
    ) -> Result<bool> {
        // The executable uses a synthetic pre-authenticated account identity.
        // Current authority is locked BEFORE any old operation receipt is read.
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM application_authorities WHERE tenant_id=$1 AND principal=$2 FOR SHARE",
        ).bind(self.tenant.as_str()).bind(principal).fetch_optional(&mut **tx).await?.unwrap_or(false))
    }

    pub async fn apply(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        command: &ApplyKeepsake,
    ) -> Result<Outcome> {
        if !self.authenticate(tx, "operator").await? {
            return Ok(Outcome::Denied);
        }

        let scoped = self.relations.for_tenant(self.tenant.clone());
        // Lock relation state before app business rows, on retries as on new commands.
        let observation = scoped
            .observe_in_transaction(tx, &command.subject, command.relation_id)
            .await?;
        let policy = permit(());
        let facts = KnownFacts::new();
        let decision = gatekeep::evaluate(&policy, &facts);
        let id = command.audit_id.as_uuid().to_string();
        let bytes = serde_json::to_vec(command)?;
        let old: Option<(Vec<u8>, Uuid)> = sqlx::query_as(
            "SELECT command, assignment_id FROM application_actions WHERE tenant_id=$1 AND command_id=$2 FOR UPDATE",
        ).bind(self.tenant.as_str()).bind(&id).fetch_optional(&mut **tx).await?;
        if let Some((previous, assignment)) = old {
            if previous != bytes {
                return Err("conflicting application command reuse".into());
            }

            return Ok(Outcome::Replayed(assignment));
        }

        let applied = scoped
            .apply_if_current_in_transaction(tx, &observation, command)
            .await?;
        sqlx::query("INSERT INTO application_actions (tenant_id, command_id, command, assignment_id) VALUES ($1,$2,$3,$4)")
            .bind(self.tenant.as_str()).bind(&id).bind(bytes).bind(applied.keepsake.id()).execute(&mut **tx).await?;
        let context = DecisionContext {
            tenant: self.tenant.as_str(),
            principal: "operator",
            target: "alice",
            id: &id,
            at: command.at,
        };
        self.audit
            .record_decision_audit_in_transaction(
                tx,
                &policy::audit(&context, &policy, facts, &decision)?,
            )
            .await?;
        let event = NewEvent::builder(
            StreamName::new("application-notifications")?,
            EventId::new(id)?,
            EventSource::new("https://example.invalid/relation-consumer")?,
            EventType::new("application.relation-action-recorded")?,
        )
        .time(command.at)
        .build()?;
        self.outbox
            .for_tenant(dovecote::TenantId::new(self.tenant.as_str())?)
            .enqueue(tx, event)
            .await?;
        Ok(Outcome::Applied(applied.keepsake.id()))
    }

    pub async fn admit(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: &str,
        at: ObservationTime,
        audit_denial: bool,
    ) -> Result<bool> {
        if !self.authenticate(tx, "alice").await? {
            return Ok(false);
        }

        let facts = self.admission_facts(tx, at).await?;
        let policy = policy::admission_policy()?;
        let decision = gatekeep::evaluate(&policy, &facts);
        if decision.is_permit() || audit_denial {
            let context = DecisionContext {
                tenant: self.tenant.as_str(),
                principal: "alice",
                target: "bob",
                id,
                at: at.instant()?,
            };
            let entry = policy::audit(&context, &policy, facts, &decision)?;
            self.audit
                .record_decision_audit_in_transaction(tx, &entry)
                .await?;
        }

        if decision.is_permit() {
            sqlx::query("INSERT INTO application_sessions (tenant_id, session_id) VALUES ($1,$2) ON CONFLICT DO NOTHING")
                .bind(self.tenant.as_str()).bind(id).execute(&mut **tx).await?;
        }

        Ok(decision.is_permit())
    }

    async fn admission_facts(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        at: ObservationTime,
    ) -> Result<KnownFacts> {
        let targets = [
            ("blocks-forward", pair("alice", "bob")?, BLOCK),
            ("blocks-reverse", pair("bob", "alice")?, BLOCK),
            (
                "restricted",
                SubjectRef::new("account", "alice")?,
                RESTRICTION,
            ),
        ];
        let scoped = self.relations.for_tenant(self.tenant.clone());
        let mut facts = Vec::<(FactId, Presence)>::new();
        for (name, subject, relation_id) in targets {
            let target = KeepsakeRelationTarget {
                tenant_id: self.tenant.clone(),
                fact: FactId::new(name)?,
                subject,
                relation_id,
                subject_slot: None,
            };
            let observation = scoped
                .observe_in_transaction(tx, &target.subject, relation_id)
                .await?;
            let presence = target.effective_presence(at, &observation.snapshot()?, None)?;
            facts.push((target.fact, presence));
        }

        Ok(KnownFacts::from_entries(facts)?)
    }

    pub async fn count(&self, table: &str) -> Result<i64> {
        // Only fixed fixture table names are accepted; no request enters SQL text.
        let query = match table {
            "events" => "SELECT count(*) FROM dovecote_events WHERE tenant_id=$1",
            "actions" => "SELECT count(*) FROM application_actions WHERE tenant_id=$1",
            "sessions" => "SELECT count(*) FROM application_sessions WHERE tenant_id=$1",
            "relations" => "SELECT count(*) FROM keepsakes WHERE tenant_id=$1",
            _ => return Err("unknown fixture table".into()),
        };
        Ok(sqlx::query_scalar(query)
            .bind(self.tenant.as_str())
            .fetch_one(&self.pool)
            .await?)
    }
}
