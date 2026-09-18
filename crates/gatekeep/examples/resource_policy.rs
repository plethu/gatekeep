//! A typed ownership gate using ordinary Rust checks, without a custom lattice.
use std::{convert::Infallible, error::Error};

use async_trait::async_trait;
use gatekeep::{
    Authorizer, Clock, Context, Fact, FactResolution, KnownFacts, Locale, PreparedPolicy,
    ResolveError, ResourcePolicy, StaticFactId, SubjectRef, TenantId, TrustedServiceBinding,
    condition, policy,
};

struct Owner;
impl Fact for Owner {
    const ID: StaticFactId = StaticFactId::new("record.owner");
}

struct Record {
    owner: SubjectRef,
    tenant: TenantId,
}

enum Action {
    Read,
}

struct RecordPolicy {
    read: PreparedPolicy<()>,
}

#[async_trait]
impl ResourcePolicy for RecordPolicy {
    type Principal = SubjectRef;
    type Resource = Record;
    type Action = Action;
    type Outcome = ();
    type Error = Infallible;

    fn policy(&self, action: &Action) -> &PreparedPolicy<()> {
        match action {
            Action::Read => &self.read,
        }
    }

    async fn resolve(
        &self,
        _action: &Action,
        principal: &SubjectRef,
        record: &Record,
        context: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<KnownFacts>, ResolveError<Infallible>> {
        let owns_record = principal == context.principal()
            && record.tenant == *context.tenant()
            && record.owner == *principal;
        FactResolution::new(
            KnownFacts::new().with_bool::<Owner>(owns_record),
            None,
            clock.now_utc(),
        )
        .map_err(ResolveError::Resolution)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let policies = RecordPolicy {
        read: PreparedPolicy::new(
            gatekeep::PolicyId::new("record.read")?,
            policy::grant_clause((), condition::has::<Owner>())
                .try_labeled("owner")?
                .hidden()
                .into_policy(),
        )?,
    };
    let principal = SubjectRef::new("person", "alex")?;
    let tenant = TenantId::new("demo")?;
    // This fixture is a trusted local service, not browser authentication.
    let context = Context::from_trusted_service(
        TrustedServiceBinding::new(tenant.clone(), "local-example")?,
        principal.clone(),
        Locale::new("en")?,
    )?;
    let record = Record {
        owner: principal.clone(),
        tenant,
    };
    // Explicitly unaudited for this first-use example. Audited apps supply a sink.
    let authorizer = Authorizer::unaudited(policies);
    let result = authorizer
        .authorize_resource(&Action::Read, &principal, &record, &context)
        .await?;
    assert!(result.decision.is_permit());
    println!("Owner may read: {}", result.decision.is_permit());
    Ok(())
}
