# Overview

Gatekeep is an authorization library for Rust services that keep policy logic in
the application. A policy is a typed Rust value. Evaluation is deterministic and
returns a decision with the facts and clause that led to the result.

Use Gatekeep when the same authorization rule has to work in three places:

- a request path that answers permit or deny
- a list endpoint that filters rows before they leave the database
- an audit record that explains the decision later

## Core Model

Gatekeep separates authorization into a few small pieces.

| Concept | Example | Source |
| --- | --- | --- |
| Subject | `user:42`, `account:acct_123` | Request context |
| Fact | `case_owner`, `has_entitlement` | Application resolver |
| Policy | "owners may read the full case" | Rust code |
| Outcome | `ReadAccess::Full` | Application type |
| Decision | permit with outcome, or deny | Gatekeep evaluation |
| Audit entry | request id, effect, trace, reason | Adapter or application |

The application resolves facts from its own state. Gatekeep evaluates the policy
against the facts it receives. That boundary keeps network calls, database
reads, authentication, tenancy, and product state in application code.

## Decision Flow

Most integrations follow this order:

1. Build a request `Context` with a principal, request id, tenant, and optional
   named subjects.
2. Resolve the facts needed by the policy.
3. Evaluate the policy with `KnownFacts`.
4. Return the permit outcome or map the denial reason to the response.
5. Record an audit entry before the request boundary returns.

List endpoints use the same policy differently. Mark request-known facts as
present or absent, leave row-level facts unknown, and lower the residual policy
with `gatekeep-sqlx`.

## Where It Fits

Gatekeep is a good fit for services where Rust engineers own the authorization
model and want compile-time policy structure, typed outcomes, and query lowering
from the same rule.

Use a central policy service when policy authors work outside the service team
or when many runtimes must share one external DSL. Use Gatekeep when local Rust
policy values, normal tests, and direct integration with application types give
the clearer contract.
