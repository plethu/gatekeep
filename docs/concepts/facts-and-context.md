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

## Request Context

`Context` carries request envelope data such as:

- request id
- principal subject
- tenant id
- optional named subjects
- policy anchor

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
