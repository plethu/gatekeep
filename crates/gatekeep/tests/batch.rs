//! Batch completeness, per-item evidence and receipt-time freshness.
use async_trait::async_trait;
use gatekeep::{
    AuditEntry, AuditSink, Authorizer, BatchError, BatchFactResolver, BindingProvenance, Clock,
    Context, FactId, FactResolution, FactResolutionMetadata, FactResolver, KnownFacts, Locale,
    PartialFacts, PolicyId, PreparedPolicy, ResolveError, SubjectRef, TenantId,
    TrustedServiceBinding, policy,
};
use std::{
    convert::Infallible,
    error::Error,
    future::pending,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use time::{Duration, OffsetDateTime};
use tokio::{sync::Notify, task::yield_now};

#[derive(Clone, Copy)]
enum Mode {
    Complete,
    Short,
    ItemFailure,
}
#[derive(Clone)]
struct Resolver {
    calls: Arc<AtomicUsize>,
    mode: Mode,
}

#[async_trait]
impl FactResolver for Resolver {
    type Error = Infallible;
    async fn resolve_for_decision(
        &self,
        _: &[FactId],
        _: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<KnownFacts>, ResolveError<Infallible>> {
        let metadata = BindingProvenance::new("test").ok().map(|source| {
            FactResolutionMetadata::new(
                source,
                None,
                clock.now_utc().checked_add(Duration::seconds(1)),
            )
        });
        FactResolution::new(KnownFacts::new(), metadata, clock.now_utc())
            .map_err(ResolveError::Resolution)
    }
    async fn resolve_for_query(
        &self,
        _: &[FactId],
        _: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<PartialFacts>, ResolveError<Infallible>> {
        FactResolution::new(PartialFacts::new(), None, clock.now_utc())
            .map_err(ResolveError::Resolution)
    }
}
#[async_trait]
impl BatchFactResolver for Resolver {
    async fn resolve_batch(
        &self,
        required: &[FactId],
        contexts: &[Context],
        clock: &dyn Clock,
    ) -> Result<
        Vec<Result<FactResolution<KnownFacts>, ResolveError<Infallible>>>,
        ResolveError<Infallible>,
    > {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut results = Vec::new();
        for context in contexts {
            results.push(self.resolve_for_decision(required, context, clock).await);
        }

        match self.mode {
            Mode::Complete => {}
            Mode::Short => {
                results.pop();
            }
            Mode::ItemFailure => {
                if let Some(first) = results.first_mut() {
                    *first = Err(ResolveError::Timeout);
                }
            }
        }

        Ok(results)
    }
}

struct Audit {
    writes: Arc<AtomicUsize>,
    advance: bool,
}
#[async_trait]
impl AuditSink for Audit {
    type Error = Infallible;
    async fn record(&self, _: &AuditEntry) -> Result<(), Infallible> {
        self.writes
            .fetch_add(usize::from(self.advance), Ordering::Relaxed);
        Ok(())
    }
}

fn context() -> Result<Context, Box<dyn Error>> {
    Ok(Context::from_trusted_service(
        TrustedServiceBinding::new(TenantId::new("one")?, "test")?,
        SubjectRef::new("person", "alex")?,
        Locale::new("en")?,
    )?)
}
fn limit() -> Result<NonZeroUsize, Box<dyn Error>> {
    Ok(NonZeroUsize::new(2).ok_or("invalid limit")?)
}

#[tokio::test]
async fn malformed_cardinality_and_limits_precede_audit() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let authorizer = Authorizer::unaudited(Resolver {
        calls: Arc::clone(&calls),
        mode: Mode::Short,
    });
    let prepared = PreparedPolicy::new(PolicyId::new("read")?, policy::permit(()))?;
    let contexts = [context()?, context()?, context()?];
    assert!(matches!(
        authorizer
            .authorize_batch(&prepared, &contexts, limit()?)
            .await,
        Err(BatchError::Limit)
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        authorizer
            .authorize_batch(&prepared, &contexts[..2], limit()?)
            .await,
        Err(BatchError::Cardinality {
            expected: 2,
            actual: 1
        })
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn strict_failure_retains_successful_item_evidence() -> Result<(), Box<dyn Error>> {
    let authorizer = Authorizer::unaudited(Resolver {
        calls: Arc::default(),
        mode: Mode::ItemFailure,
    });
    let policy = PreparedPolicy::new(PolicyId::new("read")?, policy::permit(()))?;
    let batch = authorizer
        .authorize_batch(&policy, &[context()?, context()?], limit()?)
        .await?;
    let Err(retained) = batch.into_strict() else {
        return Err("strict batch unexpectedly succeeded".into());
    };
    assert_eq!(retained.results.len(), 2);
    assert!(retained.results.first().is_some_and(Result::is_err));
    assert!(retained.results.last().is_some_and(|result| {
        result
            .as_ref()
            .is_ok_and(|decision| decision.decision.is_permit())
    }));
    Ok(())
}

#[tokio::test]
async fn later_items_revalidate_after_earlier_audit_waits() -> Result<(), Box<dyn Error>> {
    let writes = Arc::new(AtomicUsize::new(0));
    let elapsed = Arc::clone(&writes);
    let clock = move || {
        OffsetDateTime::UNIX_EPOCH
            + if elapsed.load(Ordering::Relaxed) == 0 {
                Duration::ZERO
            } else {
                Duration::seconds(2)
            }
    };
    let authorizer = Authorizer::new(
        Resolver {
            calls: Arc::default(),
            mode: Mode::Complete,
        },
        Audit {
            writes: Arc::clone(&writes),
            advance: true,
        },
    )
    .with_clock(clock);
    let policy = PreparedPolicy::new(PolicyId::new("read")?, policy::permit(()))?;
    let batch = authorizer
        .authorize_batch(&policy, &[context()?, context()?], limit()?)
        .await?;
    assert!(batch.results.first().is_some_and(Result::is_ok));
    assert!(matches!(
        batch.results.last(),
        Some(Err(gatekeep::AuthorizationError::Resolve(
            ResolveError::Resolution(gatekeep::FactResolutionError::Expired { .. })
        )))
    ));
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    Ok(())
}

struct BlockingAudit {
    entered: Arc<Notify>,
    calls: Arc<AtomicUsize>,
}
#[async_trait]
impl AuditSink for BlockingAudit {
    type Error = Infallible;
    async fn record(&self, _: &AuditEntry) -> Result<(), Self::Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.entered.notify_one();
        pending().await
    }
}

#[tokio::test]
async fn cancelling_batch_does_not_start_later_audit_writes() -> Result<(), Box<dyn Error>> {
    let entered = Arc::new(Notify::new());
    let writes = Arc::new(AtomicUsize::new(0));
    let authorizer = Authorizer::new(
        Resolver {
            calls: Arc::new(AtomicUsize::new(0)),
            mode: Mode::Complete,
        },
        BlockingAudit {
            entered: Arc::clone(&entered),
            calls: Arc::clone(&writes),
        },
    );
    let prepared = PreparedPolicy::new(PolicyId::new("read")?, policy::permit(()))?;
    let contexts = [context()?, context()?];
    let mut future = Box::pin(authorizer.authorize_batch(&prepared, &contexts, limit()?));
    tokio::select! {
        () = entered.notified() => {},
        _ = &mut future => return Err("batch returned before required persistence".into()),
    }
    drop(future);
    yield_now().await;
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    Ok(())
}
