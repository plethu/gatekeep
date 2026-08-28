# Facts And Context

Facts describe authorization inputs. Context describes the request that needs a
decision. Gatekeep keeps both explicit so request authorization, SQL lowering,
and audit records can use the same names.

## Fact Types

A fact type provides a stable id:

```rust
use gatekeep::{Fact, StaticFactId};

struct CaseOwner;

impl Fact for CaseOwner {
    const ID: StaticFactId = StaticFactId::new("case_owner");
}
```

Use stable ids as part of the public contract for policies, audit records, SQL
lowering, and localized denial messages. Rename Rust types freely. Rename fact
ids as a data migration.

## Known And Partial Facts

`KnownFacts` is for direct evaluation. Each consulted fact is present or absent.

`PartialFacts` is for query lowering. A request path may know the principal is
active, while a list query has to leave row-level facts unknown until SQL runs
against each row.

That split lets one policy serve both request checks and list filters.

Fact resolvers receive a shared application-owned `Clock` and return one
`FactResolution` envelope containing the facts, the metadata, and the source's
`observed_at` for that same observation. The
envelope rejects an impossible freshness window (`fresh_until` before
`observed_at`) and Gatekeep rejects an observation from after the decision
receipt or an expired result at the decision boundary. The application should
use the supplied clock for the observation; Gatekeep uses that same clock for
the receipt and allows no implicit clock-skew grace period.
The Axum boundary keeps a separate receipt/decision time for binding and
freshness checks, computes a deterministic digest of the complete fact set,
and does not retain resolver state between calls. Missing source metadata
therefore still produces bounded fact-set evidence.

## Request Context

`Context` carries request envelope data such as:

- request id
- principal subject
- a tenant id and its validated binding
- optional named subjects
- policy anchor

Construct contexts with `Context::from_application_verified` (or
`Context::new_at` when the expected tenant is held separately). An
`ApplicationVerifiedTenantBinding` carries application-supplied structured
evidence: an issuer/provider reference, optional key id, authentication time,
validity window, and a fixed-size claims/binding digest. It never stores raw
claims or tokens. The validity lifetime is an application policy; Gatekeep
checks the window but does not verify JWTs, OIDC claims, or directory records.
A stale, not-yet-valid, or future-dated authentication binding is rejected
before fact resolution; Gatekeep applies no clock-skew grace period. Use
`TrustedServiceBinding` and `Context::from_trusted_service` for explicitly
trusted internal services; this is a separate authority path, not an end-user
verification claim.

Named subjects let adapters resolve facts about something other than the
principal. For example, a policy may check an entitlement attached to a
repository, package, account, or source identity named in the request.

## Keepsake Targets

`gatekeep-keepsake` maps facts to active Keepsake relations. The resolver uses
the principal by default and can target named `SubjectSlot` values from
`Context::subjects`.

Use named subjects when a fact belongs to another entity. A missing subject slot
returns `ResolveError::MissingSubject`, which keeps request-shape problems
separate from absent authorization facts.
