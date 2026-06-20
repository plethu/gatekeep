//! Runnable axum example for authorized-list lowering with keepsake facts.

use chrono::{DateTime, Utc};
use gatekeep_example_authorized_list_support::{
    CaseOwner, SharedCase, Staff, request_context, router,
};
use gatekeep_keepsake::{KeepsakeResolver, tenant_scoped_subject};
use keepsake::{
    ExpiryPolicy, InMemoryActiveRelations, InMemoryActiveRelationsError, KeepsakeError,
    relation_spec,
};

type Resolver = KeepsakeResolver<InMemoryActiveRelations>;

fn main() -> Result<(), BuildError> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await?;
        let address = listener.local_addr()?;
        eprintln!("listening on http://{address}");
        axum::serve(listener, router(resolver_with_staff()?)?).await?;
        Ok(())
    })
}

fn resolver_with_staff() -> Result<Resolver, BuildError> {
    let context = request_context()?;
    let source = InMemoryActiveRelations::empty();
    source.insert_active_for_spec::<StaffRelation>(
        0xaaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa,
        tenant_scoped_subject(&context)?,
        fixed_time()?,
    )?;
    Ok(resolver_from_source(source)?)
}

#[cfg(test)]
fn resolver_without_staff() -> Result<Resolver, gatekeep_keepsake::FactBindingError> {
    resolver_from_source(InMemoryActiveRelations::empty())
}

fn resolver_from_source(
    source: InMemoryActiveRelations,
) -> Result<Resolver, gatekeep_keepsake::FactBindingError> {
    KeepsakeResolver::new(source)
        .with_resolved_relation::<Staff, StaffRelation>()?
        .with_deferred_relation::<SharedCase, SharedCaseRelation>()?
        .with_deferred_relation::<CaseOwner, CaseOwnerRelation>()
}

fn fixed_time() -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

relation_spec! {
    struct StaffRelation {
        id: 0x1111_1111_1111_1111_1111_1111_1111_1111;
        key: ("role", "staff");
        expiry(_at) => ExpiryPolicy::ManualOnly;
    }
}

relation_spec! {
    struct SharedCaseRelation {
        id: 0x2222_2222_2222_2222_2222_2222_2222_2222;
        key: ("case", "shared");
        expiry(_at) => ExpiryPolicy::ManualOnly;
    }
}

relation_spec! {
    struct CaseOwnerRelation {
        id: 0x3333_3333_3333_3333_3333_3333_3333_3333;
        key: ("case", "owner");
        expiry(_at) => ExpiryPolicy::ManualOnly;
    }
}

#[derive(Debug, thiserror::Error)]
enum BuildError {
    #[error(transparent)]
    Binding(#[from] gatekeep_keepsake::FactBindingError),
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    #[error(transparent)]
    Gatekeep(#[from] gatekeep::GatekeepError),
    #[error(transparent)]
    InMemory(#[from] InMemoryActiveRelationsError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Keepsake(#[from] KeepsakeError),
    #[error(transparent)]
    Router(#[from] gatekeep_example_authorized_list_support::BuildError),
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
        let response = match router(resolver_with_staff()?)?
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
        let response = match router(resolver_without_staff()?)?
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
        Binding(#[from] gatekeep_keepsake::FactBindingError),
        #[error(transparent)]
        Build(#[from] BuildError),
        #[error(transparent)]
        Http(#[from] axum::http::Error),
        #[error(transparent)]
        Json(#[from] serde_json::Error),
        #[error(transparent)]
        Denial(#[from] gatekeep_axum::test_support::DenialAssertError),
        #[error(transparent)]
        Router(#[from] gatekeep_example_authorized_list_support::BuildError),
    }
}
