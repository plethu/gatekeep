# Threat model

This is an engineering aid for Gatekeep 5, not a security audit or a
regulatory-compliance claim.

## Assets

- Tenant ownership of request contexts, query rows, Keepsake relations, and
  durable audit events.
- Policy decisions, traces, denial reasons, resolver evidence, and retry
  identities.
- Application credentials, database connections, migration authority, and
  protected resource data.

## Trust boundaries

The identity provider authenticates credentials. The application verifies the
assertion and binds the principal to a tenant before constructing a
`Context`. Gatekeep validates the typed binding and checks its freshness at
the authorization boundary. Fact resolvers, SQLx adapters, Keepsake, and
Dovecote are separate persistence or integration boundaries. Database RLS is
optional defense in depth, not a premise of the core library.

Gatekeep does not verify OIDC/JWT signatures, discover tenant membership,
choose the tenant, own application tables, configure RLS, encrypt payloads,
manage KMS keys, or execute obligations.

## Threats and controls

### Cross-tenant reads or writes

An attacker or application bug may reuse a subject, UUID, or query fragment
under another tenant. `Context` requires a matching binding; binding freshness
is checked before fact resolution; SQLx emits typed tenant predicates for both
filter and grade; Keepsake relation providers receive an explicit tenant; and
durable audit events are enqueued through Dovecote's tenant-scoped handle.
The remaining risk is raw SQL, an incorrectly configured provider, an admin
handle, or a cache/export that drops scope. Review those paths separately and
use database RLS where appropriate.

### Forged or stale tenant evidence

Gatekeep cannot authenticate an arbitrary application-supplied assertion. The
application must validate issuer, signature, audience, lifetime, and
principal/tenant membership. Application-verified bindings carry a validity
window and bounded evidence digest; an expired or not-yet-valid binding is
rejected before a resolver runs. A digest is evidence for reconstruction, not
proof that Gatekeep performed authentication.

### Resolver freshness and provenance gaps

Fact resolvers return one atomic envelope containing the resolved set, source
metadata, revision, freshness, and source `observed_at`. The envelope rejects
an impossible freshness window, while Gatekeep keeps a separate receipt/
decision time, rejects observations from after that boundary, and fails closed
if `fresh_until` has expired. No clock-skew grace period is implicit. It always
records a digest of the complete set and does not invent per-fact provenance.
Checked authorization requires an explicit observation, including false, for
every required fact. Selected per-fact evidence is bounded and checked against
the resolved set and receipt time. Applications remain responsible for the
truth of those observations and for choosing source revisions and freshness
windows.

### Replay, duplicate audit, and obligation confusion

Decision audit identities make an identical operation retryable and
deduplicable within its tenant. They are not bearer tokens, authentication
evidence, or a substitute for request replay controls. Dovecote delivery is
at-least-once; consumers must preserve tenant routing and deduplicate the
`(tenant_id, source, event_id)` identity, and must not treat an emitted
obligation as proof of external execution.

### Migration and supply-chain failure

Historical imports must preserve tenant ownership; no tenant may be guessed
as a migration default. Deploy audit schema-2 readers before enabling Gatekeep
5 writers. The project gate
runs cargo-deny advisory checks backed by RustSec's advisory database, along
with dependency source, license, and ban policy checks. These are review
signals, not a substitute for dependency review, lockfile inspection, backup
scope, or deployment testing.

## Operational checklist

Before production use, verify identity-provider configuration, binding and
freshness tests, explicit SQL predicates, Keepsake tenant arguments, RLS and
pool hygiene, migration mappings, backup/restore scope, Dovecote consumer
deduplication, secret handling, and the dependency-advisory result for the
exact lockfile and feature set.
