//! Runnable axum example for authorized-list lowering with in-process facts.

use async_trait::async_trait;
use gatekeep::{
    Context, FactId, FactResolver, GatekeepError, KnownFacts, PartialFacts, ResolveError,
};
use gatekeep_example_authorized_list_support::{CaseOwner, SharedCase, Staff, router};

fn main() -> Result<(), RunError> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
        let address = listener.local_addr()?;
        eprintln!("listening on http://{address}");
        axum::serve(listener, router(resolver_with_staff())?).await?;
        Ok(())
    })
}

#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Router(#[from] gatekeep_example_authorized_list_support::BuildError),
}

fn resolver_with_staff() -> StaticResolver {
    StaticResolver {
        decision_facts: KnownFacts::new().with_present::<Staff>(),
        query_facts: query_facts(),
    }
}

#[cfg(test)]
fn resolver_without_staff() -> StaticResolver {
    StaticResolver {
        decision_facts: KnownFacts::new().with_absent::<Staff>(),
        query_facts: query_facts(),
    }
}

fn query_facts() -> PartialFacts {
    PartialFacts::new()
        .with_present::<Staff>()
        .with_unknown::<SharedCase>()
        .with_unknown::<CaseOwner>()
}

#[derive(Clone, Debug)]
struct StaticResolver {
    decision_facts: KnownFacts,
    query_facts: PartialFacts,
}

#[async_trait]
impl FactResolver for StaticResolver {
    type Error = GatekeepError;

    async fn resolve_for_decision(
        &self,
        required: &[FactId],
        _cx: &Context,
    ) -> Result<KnownFacts, ResolveError<Self::Error>> {
        KnownFacts::from_entries(
            required
                .iter()
                .map(|fact| (fact.clone(), self.decision_facts.presence(fact))),
        )
        .map_err(ResolveError::Backend)
    }

    async fn resolve_for_query(
        &self,
        required: &[FactId],
        _cx: &Context,
    ) -> Result<PartialFacts, ResolveError<Self::Error>> {
        Ok(PartialFacts::from_entries(required.iter().map(|fact| {
            (fact.clone(), self.query_facts.presence(fact))
        })))
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use gatekeep_axum::test_support::{ExpectedDenial, assert_denial_response};
    use gatekeep_example_authorized_list_support::{
        AuthorizedList, EXPECTED_LIST_BINDS, EXPECTED_LIST_SQL,
    };
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn list_route_returns_lowered_authorized_query() -> Result<(), TestError> {
        let response = match router(resolver_with_staff())?
            .oneshot(Request::builder().uri("/cases").body(Body::empty())?)
            .await
        {
            Ok(response) => response,
            Err(error) => match error {},
        };

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body: AuthorizedList = serde_json::from_slice(&bytes)?;
        assert_eq!(body.bind_count, EXPECTED_LIST_BINDS);
        assert_eq!(body.sql, EXPECTED_LIST_SQL);
        Ok(())
    }

    #[tokio::test]
    async fn detail_route_uses_localized_denial_response() -> Result<(), TestError> {
        let response = match router(resolver_without_staff())?
            .oneshot(
                Request::builder()
                    .uri("/staff/cases/case_1")
                    .body(Body::empty())?,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => match error {},
        };

        assert_denial_response(
            response,
            ExpectedDenial::forbidden()
                .with_message("You cannot read this case.")
                .with_reason("case-read-denied"),
        )
        .await?;
        Ok(())
    }

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Axum(#[from] axum::Error),
        #[error(transparent)]
        Build(#[from] gatekeep_example_authorized_list_support::BuildError),
        #[error(transparent)]
        Http(#[from] axum::http::Error),
        #[error(transparent)]
        Json(#[from] serde_json::Error),
        #[error(transparent)]
        Denial(#[from] gatekeep_axum::test_support::DenialAssertError),
    }
}
