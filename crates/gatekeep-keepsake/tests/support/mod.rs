//! Test support for keepsake resolver integration tests.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use std::collections::BTreeMap;

use gatekeep::{
    Context, Fact, FactId, GatekeepError, Locale, StaticFactId, SubjectRef, SubjectSlot, TenantId,
};
use gatekeep_keepsake::KeepsakeResolver;
use keepsake::{
    ActiveRelation, ActiveRelationSource, ExpiryPolicy, InMemoryActiveRelations, RelationId,
    RelationKey, SubjectRef as KeepsakeSubjectRef, relation_spec,
};
use thiserror::Error;

pub type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

pub struct PaidPlan;

impl Fact for PaidPlan {
    const ID: StaticFactId = StaticFactId::new("paid_plan");
}

pub struct ResourceMember;

impl Fact for ResourceMember {
    const ID: StaticFactId = StaticFactId::new("resource_member");
}

relation_spec! {
    pub struct PaidPlanRelation {
        id: 0x1111_1111_1111_1111_1111_1111_1111_1111;
        key: ("entitlement", "paid-plan");
        expiry(_at) => ExpiryPolicy::ManualOnly;
    }
}

relation_spec! {
    pub struct ResourceMemberRelation {
        id: 0x2222_2222_2222_2222_2222_2222_2222_2222;
        key: ("membership", "resource-member");
        expiry(_at) => ExpiryPolicy::ManualOnly;
    }
}

relation_spec! {
    pub struct UnboundRelation {
        id: 0x3333_3333_3333_3333_3333_3333_3333_3333;
        key: ("entitlement", "unbound");
        expiry(_at) => ExpiryPolicy::ManualOnly;
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StoreError {
    #[error("store failed")]
    Failed,

    #[error("source call recorder lock poisoned")]
    Poisoned,
}

#[derive(Clone, Debug, Default)]
pub struct FakeSource {
    inner: InMemoryActiveRelations,
    fail: bool,
    calls: Arc<AtomicUsize>,
    requested_relation_ids: Arc<Mutex<Vec<Vec<RelationId>>>>,
}

impl FakeSource {
    pub fn failing() -> Self {
        Self {
            fail: true,
            ..Self::default()
        }
    }

    pub fn with_active_for_paid_plan(self, subject: KeepsakeSubjectRef) -> TestResult<Self> {
        self.inner.insert_active_for_spec::<PaidPlanRelation>(
            0xaaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa,
            subject,
            fixed_time()?,
        )?;
        Ok(self)
    }

    pub fn with_active_for_resource_member(self, subject: KeepsakeSubjectRef) -> TestResult<Self> {
        self.inner
            .insert_active_for_spec::<ResourceMemberRelation>(
                0xbbbb_bbbb_bbbb_bbbb_bbbb_bbbb_bbbb_bbbb,
                subject,
                fixed_time()?,
            )?;
        Ok(self)
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn requested_relation_ids(&self) -> Result<Vec<Vec<RelationId>>, StoreError> {
        self.requested_relation_ids
            .lock()
            .map(|requests| requests.clone())
            .map_err(|_| StoreError::Poisoned)
    }
}

impl ActiveRelationSource for FakeSource {
    type Error = StoreError;

    async fn active_relations_for_subject(
        &self,
        subject: &KeepsakeSubjectRef,
    ) -> Result<Vec<ActiveRelation>, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(StoreError::Failed);
        }
        self.inner
            .active_relations_for_subject(subject)
            .await
            .map_err(|_| StoreError::Failed)
    }

    async fn active_relations_for_subject_by_ids(
        &self,
        subject: &KeepsakeSubjectRef,
        relation_ids: &[RelationId],
    ) -> Result<Vec<ActiveRelation>, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(StoreError::Failed);
        }
        self.requested_relation_ids
            .lock()
            .map_err(|_| StoreError::Poisoned)?
            .push(relation_ids.to_vec());
        self.inner
            .active_relations_for_subject_by_ids(subject, relation_ids)
            .await
            .map_err(|_| StoreError::Failed)
    }

    async fn active_relations_for_subject_by_keys(
        &self,
        subject: &KeepsakeSubjectRef,
        keys: &[RelationKey],
    ) -> Result<Vec<ActiveRelation>, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(StoreError::Failed);
        }
        self.inner
            .active_relations_for_subject_by_keys(subject, keys)
            .await
            .map_err(|_| StoreError::Failed)
    }
}

pub fn resolver_for(principal: &SubjectRef) -> TestResult<KeepsakeResolver<FakeSource>> {
    resolver_for_tenant("tenant_1", principal)
}

pub fn resolver_for_tenant(
    tenant: &str,
    principal: &SubjectRef,
) -> TestResult<KeepsakeResolver<FakeSource>> {
    let subject = tenant_subject(tenant, principal)?;
    resolver_with_subject(subject)
}

pub fn principal_resolver_for(principal: &SubjectRef) -> TestResult<KeepsakeResolver<FakeSource>> {
    let subject = KeepsakeSubjectRef::new(principal.kind(), principal.id())?;
    resolver_with_subject(subject)
}

fn resolver_with_subject(subject: KeepsakeSubjectRef) -> TestResult<KeepsakeResolver<FakeSource>> {
    Ok(KeepsakeResolver::new(
        FakeSource::default().with_active_for_paid_plan(subject)?,
    ))
}

pub fn context(tenant: &str, principal: SubjectRef) -> Result<Context, GatekeepError> {
    Ok(Context {
        tenant: TenantId::new(tenant)?,
        principal,
        subjects: BTreeMap::new(),
        locale: Locale::new("en-US")?,
        request_id: None,
    })
}

pub fn context_with_subjects(
    tenant: &str,
    principal: SubjectRef,
    subjects: BTreeMap<SubjectSlot, SubjectRef>,
) -> Result<Context, GatekeepError> {
    Ok(Context {
        tenant: TenantId::new(tenant)?,
        principal,
        subjects,
        locale: Locale::new("en-US")?,
        request_id: None,
    })
}

pub fn subject(kind: &str, id: &str) -> Result<SubjectRef, GatekeepError> {
    SubjectRef::new(kind, id)
}

pub fn fact_id(value: &str) -> Result<FactId, GatekeepError> {
    FactId::new(value)
}

pub fn tenant_subject(
    tenant: &str,
    principal: &SubjectRef,
) -> Result<KeepsakeSubjectRef, keepsake::KeepsakeError> {
    KeepsakeSubjectRef::new(
        format!(
            "tenant:{}:{}principal:{}:{}",
            tenant.len(),
            tenant,
            principal.kind().len(),
            principal.kind()
        ),
        principal.id(),
    )
}

fn fixed_time() -> TestResult<keepsake::__private::DateTime<keepsake::__private::Utc>> {
    Ok(
        keepsake::__private::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")?
            .with_timezone(&keepsake::__private::Utc),
    )
}
