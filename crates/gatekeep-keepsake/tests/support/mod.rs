//! Test support for keepsake resolver integration tests.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use gatekeep::{Context, Fact, FactId, GatekeepError, Locale, StaticFactId, SubjectRef, TenantId};
use gatekeep_keepsake::{ActiveRelationSource, KeepsakeResolver};
use keepsake::{
    ExpiryPolicy, Keepsake, RelationDefinition, SubjectRef as KeepsakeSubjectRef, relation_spec,
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
}

#[derive(Clone, Debug, Default)]
pub struct FakeSource {
    active: HashMap<KeepsakeSubjectRef, Vec<Keepsake>>,
    fail: bool,
    calls: Arc<AtomicUsize>,
}

impl FakeSource {
    pub fn failing() -> Self {
        Self {
            fail: true,
            ..Self::default()
        }
    }

    fn with_active(mut self, subject: KeepsakeSubjectRef, keepsake: Keepsake) -> Self {
        self.active.entry(subject).or_default().push(keepsake);
        self
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ActiveRelationSource for FakeSource {
    type Error = StoreError;

    async fn active_for_subject(
        &self,
        subject: &KeepsakeSubjectRef,
    ) -> Result<Vec<Keepsake>, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(StoreError::Failed);
        }
        Ok(self.active.get(subject).cloned().unwrap_or_default())
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
    let relation = RelationDefinition::from_spec::<PaidPlanRelation>(fixed_time()?)?;
    let keepsake = Keepsake::applied(
        keepsake::__private::Uuid::from_u128(0xaaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa),
        subject.clone(),
        &relation,
        fixed_time()?,
        BTreeMap::new(),
    )?;
    Ok(KeepsakeResolver::new(
        FakeSource::default().with_active(subject, keepsake),
    ))
}

pub fn context(tenant: &str, principal: SubjectRef) -> Result<Context, GatekeepError> {
    Ok(Context {
        tenant: TenantId::new(tenant)?,
        principal,
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

fn tenant_subject(
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
