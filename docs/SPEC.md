# gatekeep — specification

`gatekeep` is a code-first authorization engine for Rust: policies are defined
as composable Rust values, evaluated by a pure deterministic core, and every
decision carries the reasons that produced it.

It is the sibling of [`keepsake`](../../keepsake-rs): keepsake *keeps* relation
lifecycle state (entitlements, holds, sanctions, risk flags, gates); gatekeep
*decides* what those facts permit. The two compose — keepsake relations are a
natural fact source for gatekeep policies — but they are independent crates.
keepsake deliberately excludes authorization from its charter, so this is a
separate project rather than a keepsake module.

This document is the design contract. It is implementation guidance first and a
dependency second, following keepsake's discipline. No code is shipped with this
spec.

## 1. Why this exists

The Rust authz ecosystem is **DSL-first**. The pure engines that exist are not
code-first, and the code-first options are not authorization engines:

| Crate | Policy definition | Pure core | Reason-carrying decision | Code-first |
| --- | --- | --- | --- | --- |
| Cedar (AWS) | external `.cedar` DSL + JSON entities | yes | partial (external validator) | no |
| Casbin-rs | `.conf` model + `.csv` data | yes (`Arc<RwLock>`) | no (bool) | no |
| Oso / Polar | external DSL via FFI | no | yes | no (deprecated) |
| biscuit-auth | Datalog in tokens | yes | partial | no (capability tokens) |
| SpiceDB / OpenFGA clients | remote service schema | no (network) | yes (server) | no |
| portcullis | CEL constraint strings | partial | yes | no (agent-containment domain) |
| axum-login | Rust traits | yes | no (bool) | closest, but authn-only |

The exact combination — **composable Rust combinators + a pure synchronous core
+ a structured reason-carrying decision + audit/observability as defaults** —
has no occupant.

### Why the ecosystem chose DSLs

The DSL bias is a deployment-model artifact, not technical superiority. A policy
language buys: (1) policy change without a redeploy, (2) authorship by
non-engineers with separation of duties, (3) analyzability — a restricted,
total language admits "is policy A strictly more permissive than B?" proofs that
Turing-complete Rust cannot, (4) polyglot one-source-of-truth across many
services, (5) a centralized audit point, (6) an evaluator that cannot panic,
block, or do IO.

Every one of those is an enterprise/polyglot concern. For a single-language,
in-process authorization boundary authored by the team that owns the
application, the benefits are ~zero and the costs are all present: a second
language, serializing the domain into "entities/attributes," typos failing at
runtime instead of compile time, worse testing and debugging, and obscuring
indirection. That gap is gatekeep's niche.

The one lesson gatekeep *takes* from the DSL world is analyzability: **reify the
policy as inspectable data even though it is authored in Rust** (see §4). That
captures most of the DSL's value with none of the second-language cost.

Reification also unlocks a capability the boolean check-engines structurally
lack: **partial evaluation** of a policy over principal-level facts, producing a
residual that lowers into a query filter — turning per-row permission checks into
a single authorized list query (§5.3). ASP.NET handlers, Symfony voters, and
Laravel gates are all closures that can only answer "can this principal act on
*this* resource?"; gatekeep can also answer "*which* resources?".

## 2. Scope

### In scope

- A pure, synchronous decision kernel over a frozen fact set.
- A two-layer reified algebra authored as Rust values: a Boolean `Condition`
  layer (`condition::{always, never, has, not, all, any}`) and a graded
  `Policy<O>` layer (`policy::{permit, deny, grant, all, any, or_else}`).
- A decision type generic over the outcome `O` (a bounded lattice), carrying a
  self-describing reason trace and obligations.
- Partial evaluation of a policy over a partial fact set, producing a residual
  for authorized list queries (§5.3).
- Structured, i18n-ready denial reasons: stable codes localized at the edge,
  with deny-shape gating disclosure (§5.4).
- Adapter boundaries for async fact resolution, observability, audit, query
  lowering, and reason localization, each with no-op/identity defaults.

### Out of scope (non-goals)

- No embedded policy DSL or policy-as-data language in the core. (A future
  `gatekeep-cel` style adapter is *possible* because policies are reified data,
  but it is not part of v1 and the core must not depend on it.)
- No authentication, session, token, or credential handling — that is the
  application's or an authn crate's job.
- No persistence of policies or facts in the core; adapters own all IO.
- No network policy service, no distributed evaluation.
- No central DI container, service locator, or mutable global policy registry.
  Policies are values.

## 3. Architecture and boundaries

Four ownership boundaries, mirroring keepsake's `core + adapter` split.

```
+- gatekeep (crate) -- pure, synchronous, no IO -------------------+
|  model:    Condition, Policy<O>, FactId, KnownFacts, PartialFacts|
|            Decision<O>                                           |
|            Lattice (bound on O), Effect<O>, Trace                 |
|  algebra:  condition::{always, never, has, not, all, any}         |
|            policy::{permit, deny, grant, all, any, or_else}       |
|  evaluate: fn(&Policy<O>, &KnownFacts) -> Decision<O>   (pure)   |
|  partial:  fn(&Policy<O>, &PartialFacts) -> Residual<O>           |
|            #[must_use], deterministic, reproducible              |
|  observe:  PolicyObserver, AuditSink   (Noop* defaults)          |
+------------------------------------------------------------------+
        ^ fact bundles (frozen, typed, named) | Decision<O> (typed trace)
        |                                      v
+- FactResolver (trait) -- async, owns all IO --------------------+
|  walks Policy<O> -> set of required FactId                       |
|  fetches them in stable order -> freezes a fact bundle           |
+------------------------------------------------------------------+
        ^                       ^                        ^
+- gatekeep-keepsake -+  +- gatekeep-sqlx / app -+  +- in-memory (tests) -+
| Entitlement / Hold  |  | RBAC edge roles, org   |  | literal KnownFacts  |
| from KeepsakeStore  |  | membership, tenancy    |  | for pure unit tests |
+---------------------+  +------------------------+  +---------------------+
```

The load-bearing rule is **gather-then-decide**:

- Fact resolution is async and lives entirely in adapters.
- Evaluation is synchronous, pure, and reproducible from `(Policy, KnownFacts)`
  alone — no clock, no IO, no `Context`, no hidden state. Re-running the
  evaluator on the same inputs always yields the same `Decision` and the same
  typed trace.

This single seam is what delivers determinism, testability, and an audit trace
that can be replayed.

### 3.1 Context, tenancy, and isolation

The kernel is pure over `(Policy, KnownFacts)` and **never reads a `Context`** —
that is what makes a decision replayable from its inputs alone. Request-scoped
data lives in an orchestration `Context` threaded only to the adapters
(`FactResolver`, `QueryLowering`, `AuditSink`, the denial presenter), never into
`evaluate`:

```rust
pub struct Context {
    pub tenant: TenantId,
    pub principal: SubjectRef,      // core-owned kind+id (defined below)
    pub locale: Locale,             // for denial localization (§5.4)
    pub request_id: Option<RequestId>,
    pub extensions: Extensions,     // typed, app-supplied side data
}

pub struct TenantId(String);        // #[serde(transparent)] (§4.5)
pub struct RequestId(String);       // #[serde(transparent)] (§4.5)

/// Subject identity owned by gatekeep core. Independent of keepsake — core never
/// depends on it; the gatekeep-keepsake adapter maps between this and keepsake's
/// SubjectRef.
pub struct SubjectRef { kind: String, id: String }

/// Type-keyed container for app request data the adapters may read.
pub struct Extensions(/* HashMap<TypeId, Box<dyn Any + Send + Sync>> */);
```

This is *not* offloading tenant isolation onto the integrator — it gives it two
explicit, first-class integration points:

1. **Tenant-scoped resolution.** The `FactResolver` receives the `Context` and
   fetches only the tenant's facts. A principal in tenant A can never resolve a
   fact about tenant B's resources, so cross-tenant access cannot even be
   *expressed* as a fact, let alone permitted. Isolation is a property of
   resolution, not a check you can forget to write.
2. **Tenant-keyed policy composition.** Jurisdictions with divergent rules are
   tenant-selected policies composed from shared combinators — the algebra is
   built for exactly this:

   ```rust
   fn case_read_policy(j: Jurisdiction) -> Policy<ReadTier> {
       let base = baseline_case_read();            // shared core
       match j {                                   // exhaustive, no wildcard (§6.4)
           Jurisdiction::Eu => policy::all([base, gdpr_overlay()]),
           Jurisdiction::Us => policy::all([base, hipaa_overlay()]),
           Jurisdiction::Au => policy::or_else(base, au_special_access()),
       }
   }
   ```

   Per-jurisdiction divergence is `policy::all` / `policy::or_else` composition
   over a shared base, not forks of an engine. Determinism is untouched: once the
   tenant has selected its policy and the resolver has frozen its facts,
   evaluation is pure.

The `AuditSink` records the `tenant` and `principal` from the `Context` so
isolation is auditable, but those identifiers never enter the kernel or the
reproducible `(Policy, KnownFacts)` pair. `TenantId` / `RequestId` follow the
§4.5 identity discipline; `SubjectRef` is core-owned (above), independent of
keepsake; `Locale` is a BCP-47 newtype (§5.4).

## 4. The policy is reified data, never closures

Combinators build serializable ASTs, not `Box<dyn Fn>`. This is the central
constraint: a closure-based engine can never serialize, diff, analyze, or render
a policy; a reified one gets all of that while remaining pure Rust at the call
site.

The algebra is **two layers**, which keeps grade composition clean — grades are
introduced only by the graded layer (`policy::grant` / `policy::permit`), so the
Boolean layer never has to reconcile graded against ungraded nodes.

### 4.1 `Condition` — the Boolean layer

```rust
/// A pure predicate over the resolved fact set. Evaluates to satisfied/unsatisfied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    /// Unconditionally satisfied.
    Always,
    /// Unconditionally unsatisfied.
    Never,
    /// True when a named fact is present in the resolved fact set.
    Has(FactId),
    Not(Box<Condition>),
    All(Vec<Condition>),
    Any(Vec<Condition>),
}
```

`condition::all([condition::has::<A>(), condition::not(condition::has::<B>())])`
is a `Condition`. It carries no outcome; it is the guard layer. Empty public
condition combinators fail closed to `Never`; reducers emit `Always` / `Never`
explicitly when they need Boolean identities.

### 4.2 `Policy<O>` — the graded layer

```rust
/// An outcome-producing policy. Outcomes (grades) are introduced by grants or
/// explicit constants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy<O> {
    /// Unconditionally permit with outcome `O`.
    Permit(O),
    /// Unconditionally deny; used directly and for empty combinators.
    Deny,
    /// Permit with outcome `O` when the condition holds; otherwise deny.
    Grant {
        outcome: O,
        condition: Condition,
        /// Author-assigned, deploy-stable name; the audit-trace and reason key.
        label: Option<ClauseLabel>,
        /// How a denial of *this* grant presents (default `Forbidden`); §5.2.
        deny_shape: DenyShape,
        /// Attached on the decisive arm when this grant decides (§6.3).
        obligations: Vec<ObligationId>,
        /// Optional explicit reason key; defaults to `label` (§5.4).
        reason: Option<ReasonCode>,
    },
    /// Meet: deny if any arm denies; otherwise permit at the meet of arm grades.
    All(Vec<Policy<O>>),
    /// Join: permit if any arm permits, at the join of permitting arm grades.
    Any(Vec<Policy<O>>),
    /// Ordered fallback: if `primary` permits, use it; else evaluate `fallback`.
    OrElse { primary: Box<Policy<O>>, fallback: Box<Policy<O>> },
}
```

`policy::grant(outcome, condition)` (§6.2) fills `deny_shape: Forbidden`, empty
`obligations`, and `reason: None`; the builder sets the rest (`.labeled(..)`,
`.hidden()`, `.with_obligation::<O>()`, `.reason(..)`). `policy::permit(outcome)`
and `policy::deny()` construct metadata-light constants; user-facing denial
reasons come from denied grants, not from a bare `Deny` constant.

Partial evaluation uses a separate `ResidualPolicy<O>` (§5.3) so author-facing
policies do not expose trace-preservation nodes.

### 4.3 Facts and fact identity

`condition::has::<F>()` records `F`'s stable `FactId`, never its `TypeId`
(`TypeId` is unstable across builds and unserializable — useless in an audit
log). Fact identity follows keepsake's `RelationKey` / `StaticRelationKey` /
`RelationSpec` discipline, so call sites are compile-time-checked and free of
raw strings:

```rust
/// Owned, validated identity (non-empty). #[serde(transparent)] over String.
pub struct FactId(String);

/// Compile-time identity for an application-owned fact catalogue.
pub struct StaticFactId(&'static str);
impl StaticFactId { pub const fn new(id: &'static str) -> Self { /* … */ } }

/// Implemented on zero-sized marker types — the typed fact catalogue.
pub trait Fact { const ID: StaticFactId; }
// struct BillingEntitlement;
// impl Fact for BillingEntitlement {
//     const ID: StaticFactId = StaticFactId::new("billing_entitlement");
// }
```

`condition::has::<F>()` reads `F::ID` and stores the owned `FactId` in the AST;
runtime-built policies may insert `FactId`s directly.

**Facts are presence-only.** The raw map records, per `FactId`, whether the fact
is `Present`, `Absent`, or `Unknown`; typed wrappers decide which states are
legal at each phase. `KnownFacts` is the only input accepted by full
`evaluate` and contains only `Present` / `Absent`. `PartialFacts` is the only
input accepted by `partial_evaluate` and may contain `Unknown` for facts
intentionally deferred to query lowering (§5.3). Value comparisons (an ABAC
`department == eng`, a tier ceiling) are reified by the resolver into distinct
facts, keeping the Boolean layer total and the kernel pure over booleans. A fact
MAY carry an opaque, already-serialized `TraceValue` used *only* for the trace
and audit (so a log can show `sensitivity = "full"` rather than a bare flag);
the evaluator never inspects it.

```rust
struct Facts(IndexMap<FactId, (Presence, Option<TraceValue>)>);
pub struct KnownFacts(Facts);   // constructor rejects Unknown
pub struct PartialFacts(Facts); // Unknown allowed only for query-deferred facts
pub type TraceValue = serde_json::Value; // opaque to the kernel; trace/audit only
```

The set is keyed by `FactId`; `Fact` markers give ergonomic typed lookup.
Unknown is not a backend "missing" value. It is a query-mode marker produced by
a resolver when a fact is resource-scoped and must be translated into a row
predicate later.

### 4.4 Canonical policy identity

Because `Policy<O>` is a reified AST, a canonical content hash is cheap. The
canonical form is the policy's **`postcard` serialization** — compact, positional,
no key-ordering ambiguity, chosen over JSON for smaller output and faster hashing
— hashed with **BLAKE3** and rendered lowercase hex:

```rust
pub struct PolicyId(String);    // author-assigned, stable; #[serde(transparent)]
pub struct PolicyHash(String);  // blake3(postcard(policy)) hex; derived, not authored

impl<O: Serialize> Policy<O> { pub fn hash(&self) -> PolicyHash { /* … */ } }
```

Every audit entry is anchored to `{ policy_id, policy_hash }`, recording exactly
which policy version produced a decision. The hash is computed lazily at
audit-record time so evaluation is never taxed. Postcard is positional, so any
structural change (including arm reordering) changes the hash — the intended
behavior. `ClauseLabel`s (§4.2, §4.5) name grants across refactors.

### 4.5 The same discipline for every stable identity

`ClauseLabel` (grant names, §4.2), `ObligationId` (§6.3), `ReasonCode` and
`ParamKey` (§5.4), and `TenantId` / `RequestId` (§3.1) are all author-assigned,
deploy-stable identities and use the identical pattern: an owned, validated,
`#[serde(transparent)]` newtype over `String`; a `Static*` `const`-constructible
form for compile-time catalogues; and — where call sites would otherwise repeat
strings — a marker trait carrying the `Static*` constant (as `Fact` does,
mirroring keepsake's `RelationSpec`). Raw identity strings never appear at call
sites. For example:

```rust
pub struct ClauseLabel(String);   // #[serde(transparent)]; the shared pattern
pub struct StaticClauseLabel(&'static str);
```

### 4.6 Boundary validation and record shapes

Every stable identity and boundary record validates at construction and
deserialization time. The core exposes one small validation error enum rather
than panicking or accepting invalid names:

```rust
pub type GatekeepResult<T> = Result<T, GatekeepError>;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum GatekeepError {
    #[error("{field} must not be empty")]
    EmptyIdentifier { field: &'static str },
    #[error("invalid locale tag: {value}")]
    InvalidLocale { value: String },
    #[error("policy record is invalid: {reason}")]
    InvalidPolicyRecord { reason: &'static str },
}
```

`FactId::new`, `PolicyId::new`, `ClauseLabel::new`, `ReasonCode::new`,
`ParamKey::new`, `ObligationId::new`, `TenantId::new`, `RequestId::new`, and
`Locale::new` reject empty or whitespace-only values. Static catalogue helpers
remain `const fn` for ergonomic declarations, but converting a `Static*` value
into its owned runtime form validates and returns `GatekeepResult`.

If an implementation needs a serde/storage boundary shape that differs from the
typed Rust model, it follows keepsake's 0.2 discipline: define a flat `*Record`
type for the wire/storage shape, implement `TryFrom<Record>` for the typed model,
and make `Deserialize` for the typed model go through that conversion. Invalid
record combinations fail at the model boundary. For gatekeep this primarily
applies to policy, trace, and audit record types; the in-memory `Policy<O>` and
`Trace` remain the typed forms callers use.

## 5. Decision and outcome

`evaluate` never returns `bool`. It returns a structured decision generic over
the outcome `O`, so graded results (tiers), obligations (break-glass), and
deny-shape distinctions are first-class — not flattened away.

```rust
#[must_use]
pub fn evaluate<O: Lattice>(policy: &Policy<O>, facts: &KnownFacts) -> Decision<O>;

pub struct Decision<O> {
    pub effect: Effect<O>,              // Permit(O) | Deny
    pub obligations: Vec<ObligationId>, // from the decisive arm only (§6.3)
    pub trace: DecisionTrace<O>,        // typed, pure; serialize at the audit edge (§5.2)
}

pub enum Effect<O> {
    Permit(O),  // O carries the grade/tier, e.g. ReadTier::Full
    Deny,
}
```

The kernel takes no `Context` (§3.1); it is pure over `(Policy, KnownFacts)`.

**The decision procedure.** `evaluate` walks the policy bottom-up in source
order, producing `(Effect<O>, obligations, DecisiveClause)` and accumulating
`consulted`:

- **`Condition`** returns satisfied/unsatisfied and records each `Has(f)` it
  reads into `consulted` as `(f, Present|Absent)`. `Always` is satisfied and
  `Never` is unsatisfied without consulting facts. `Not` negates; `All` holds
  iff every non-empty arm does (may short-circuit on the first unsatisfied);
  `Any` holds iff some arm does (may short-circuit on the first satisfied).
  Empty condition `All` / `Any` nodes evaluate as `Never`; use `Always`
  explicitly when an unconditional guard is intended.
- **`Policy::Permit(o)`** → `Permit(o)` with no obligations and a constant
  permit decisive clause.
- **`Policy::Deny`** → `Deny` with no specific reason metadata and default
  `Forbidden` shape.
- **`Grant`** → if `condition` holds, `Permit(outcome)` with the grant's
  `obligations` and `DecisiveClause::Permit { granted, satisfied, label }`; else
  `Deny` with
  `DecisiveClause::Deny { denied, unsatisfied, label, reason, shape }`, where
  `denied` is the grant's target outcome and `shape` is `deny_shape`.
  `satisfied` / `unsatisfied` list the `Has` facts that decided the condition
  (for an `All` that failed: every deciding absent fact; for an `Any` that
  failed: all arms' missing facts).
- **`Policy::All`** → fold arm effects by meet (`Permit(a)∧Permit(b)=Permit(a∧b)`;
  any `Deny` ⇒ `Deny`; empty `All` ⇒ `Deny`). Decisive clause: on `Deny`, the
  first denying arm's clause; on `Permit`, the arm holding the meet (lowest
  grade), lowest index on ties.
- **`Policy::Any`** → fold by join. Decisive clause: on `Permit`, the
  **lowest-index** arm permitting at the winning (join) grade; on `Deny` (all
  arms denied, including empty `Any`), the **first** arm's clause or the generic
  `Policy::Deny` clause for an empty node — source-order symmetric with `All`
  and deterministic; richer denial aggregation across arms is a debug-trace
  concern, not the decisive clause's job. Obligations: the **union** across all
  arms permitting at the winning grade (§6.3) — the singular decisive clause
  names one of them, the obligations cover all.
- **`OrElse`** → evaluate `primary`; if it permits, return it unchanged (fallback
  never evaluated); else evaluate and return `fallback`.

`consulted` is the dedup'd union (a fact cannot be both present and absent in one
run) of every `Has` node actually evaluated; short-circuited arms contribute
nothing. Short-circuiting may shrink `consulted` but never changes `Effect` or
`obligations` (§9).

### 5.1 `O` is a bounded lattice

`O` must form a **bounded lattice**: it has a `meet` (greatest lower bound, used
by `policy::all`), a `join` (least upper bound, used by `policy::any`), and
explicit `top` / `bottom` elements. `Effect<O>` then forms a bounded lattice
with `Deny` below every permit grade, while `O::bottom()` is only the least
*permitted* grade.

```rust
pub trait Lattice: Clone + Eq + Debug {
    fn meet(&self, other: &Self) -> Self; // greatest lower bound (most restrictive)
    fn join(&self, other: &Self) -> Self; // least upper bound  (most permissive)
    fn top() -> Self;                     // greatest permitted grade
    fn bottom() -> Self;                  // least permitted grade
}
```

The trait is algebraic only. Pure evaluation needs `Clone + Eq + Debug`; policy
hashing, durable trace conversion, decision serialization, and deserialization
add `Serialize` / `DeserializeOwned` bounds on the methods or record loaders that
perform those operations. For a totally-ordered tier such as `ReadTier`
(`Released < Shared < Full`), `meet` / `join` are `min` / `max`, `top` is `Full`,
and `bottom` is `Released`. For a pure gate, `O = ()` (a one-element lattice).
Graded SQL projection (§5.5) additionally needs `O: Ord` plus a caller-supplied
`O -> i64` ordinal; the kernel itself never requires `Ord`.

### 5.2 The trace is self-describing

Replay comes from re-evaluating `(Policy, KnownFacts)`, which is deterministic,
so the trace need not store inputs. `Context` may appear in audit envelopes and
adapter calls, but it is not read by the kernel and is not part of decision
replay. The trace's job is *explanation*, and the durable audit form must be
interpretable **without the live policy tree** — audit logs outlive deploys, so
positional references into the AST are forbidden (they dangle when a later
deploy changes the tree). Trace meaning comes from stable names only.

Pure evaluation returns a typed `DecisionTrace<O>` so the kernel does not need
serde bounds on `O`. The durable `Trace` is **non-generic**: conversion erases
the decisive outcome to a serialized `TraceValue`, so `Trace`,
`DecisionSummary`, and `AuditEntry` (§7) carry no `O` parameter and the
audit/observer traits stay monomorphic.

```rust
pub struct DecisionTrace<O> {
    /// Facts the evaluator actually read (dedup'd; §5 decision procedure).
    pub consulted: Vec<(FactId, Presence)>,
    /// The clause that fixed the Effect, by stable names and typed values.
    pub decisive: DecisiveClause<O>,
}

pub enum DecisiveClause<O> {
    Permit { granted: O, satisfied: Vec<FactId>, label: Option<ClauseLabel> },
    Deny {
        denied: Option<O>,
        unsatisfied: Vec<FactId>,
        label: Option<ClauseLabel>,
        reason: Option<ReasonCode>,
        shape: DenyShape,
    },
}

pub struct Trace {
    pub consulted: Vec<(FactId, Presence)>,
    pub decisive: TraceClause,
}

pub enum TraceClause {
    Permit { granted: TraceValue, satisfied: Vec<FactId>, label: Option<ClauseLabel> },
    Deny {
        denied: Option<TraceValue>,
        unsatisfied: Vec<FactId>,
        label: Option<ClauseLabel>,
        reason: Option<ReasonCode>,
        shape: DenyShape,
    },
}

/// Three-valued so one set of evaluation rules serves both modes. Full
/// `evaluate` accepts only KnownFacts, so it never reads Unknown. `Unknown`
/// appears only under `partial_evaluate` (§5.3), for resource facts not yet
/// resolved.
pub enum Presence { Present, Absent, Unknown }

#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    #[error("failed to serialize outcome for trace")]
    Outcome(#[from] serde_json::Error),
}

impl<O: Serialize> Decision<O> {
    pub fn to_trace(&self) -> Result<Trace, TraceError> { /* … */ }
    pub fn denial_reason(&self) -> Result<Option<DenialReason>, TraceError> { /* … */ }
}
```

Everything here is deploy-stable: `FactId`s are the stable names from §4.3,
`TraceClause` outcomes are serialized values, and `label` is an author-assigned
grant name that survives refactors. A positional, full-evaluation-tree trace
exists only as an **ephemeral debug mode** interpreted against the *current* AST;
it is never written to the durable audit log.

The deny *shape* is a **policy decision** authored on the deny path — not a
request property and not hardcoded in the engine:

```rust
pub enum DenyShape { Forbidden, Hidden } // Hidden: do not reveal the resource exists
```

A `Grant` carries the shape its denial takes (default `Forbidden`, §4.2);
`evaluate` surfaces the decisive deny's `shape`, `reason`, label, and denied
target outcome on the `DecisiveClause`, so `denial_reason()` (§5.4) needs no
`Context`. send-app's hidden-vs-forbidden distinction is expressed by authoring
`.hidden()` on the relevant grants.

### 5.3 Partial evaluation — authorized queries

Because the policy is reified data and `Has(FactId)` is the only fact reference,
the evaluator can run over a *partial* fact set — principal-level facts marked
`Present`/`Absent`, resource-level facts left `Unknown` — and fold out
everything it can decide, leaving a **residual** that depends only on the unknown
facts. This is the capability the boolean check-engines cannot offer, and it
turns "can this principal read case X?" into "**which** cases can this principal
read?" without an N-row evaluation loop. Ships in v1.

```rust
#[must_use]
pub fn partial_evaluate<O: Lattice>(policy: &Policy<O>, known: &PartialFacts) -> Residual<O>;

pub fn evaluate_residual<O: Lattice>(
    policy: &ResidualPolicy<O>,
    known: &KnownFacts,
) -> Decision<O>;

pub fn complete_residual<O: Lattice>(
    residual: &Residual<O>,
    known: &KnownFacts,
) -> Decision<O>;

pub enum Residual<O> {
    /// The known facts alone settle the decision; no resource lookup needed.
    Resolved(Decision<O>),
    /// Decision still depends on unknown (resource-level) facts. `residual` is
    /// the simplified policy over only those facts; hand it to a QueryLowering
    /// adapter (§5.5) to push down into a backend filter.
    Pending { residual: ResidualPolicy<O>, consulted: Vec<(FactId, Presence)> },
}

pub enum ResidualPolicy<O> {
    Permit(O),
    Deny,
    PermitWithTrace {
        outcome: O,
        obligations: Vec<ObligationId>,
        satisfied: Vec<FactId>,
        label: Option<ClauseLabel>,
    },
    DenyWithTrace {
        denied: Option<O>,
        unsatisfied: Vec<FactId>,
        label: Option<ClauseLabel>,
        reason: Option<ReasonCode>,
        shape: DenyShape,
    },
    Grant {
        outcome: O,
        condition: Condition,
        label: Option<ClauseLabel>,
        deny_shape: DenyShape,
        obligations: Vec<ObligationId>,
        reason: Option<ReasonCode>,
    },
    All(Vec<ResidualPolicy<O>>),
    Any(Vec<ResidualPolicy<O>>),
    OrElse {
        primary: Box<ResidualPolicy<O>>,
        fallback: Box<ResidualPolicy<O>>,
    },
}

pub enum ResidualPolicyNode<'a, O, T> {
    Permit(&'a O),
    Deny,
    PermitWithTrace { /* borrowed trace fields */ },
    DenyWithTrace { /* borrowed trace fields */ },
    Grant { /* borrowed grant fields */ },
    All { policies: &'a [ResidualPolicy<O>], arms: Vec<T> },
    Any { policies: &'a [ResidualPolicy<O>], arms: Vec<T> },
    OrElse {
        primary_policy: &'a ResidualPolicy<O>,
        fallback_policy: &'a ResidualPolicy<O>,
        primary: T,
        fallback: Option<T>,
    },
}

pub enum ResidualPolicyBranch<'a, O> {
    OrElseFallback {
        primary: &'a ResidualPolicy<O>,
        fallback: &'a ResidualPolicy<O>,
    },
}

impl<O> ResidualPolicy<O> {
    pub const fn is_permit_constant(&self) -> bool;
    pub const fn is_deny_constant(&self) -> bool;
    pub const fn is_constant(&self) -> bool;
    pub fn carries_obligation(&self) -> bool;
    pub fn fold<T>(&self, visitor: &mut impl FnMut(ResidualPolicyNode<'_, O, T>) -> T) -> T;
    pub fn try_fold<T, E>(
        &self,
        visitor: &mut impl FnMut(ResidualPolicyNode<'_, O, T>) -> Result<T, E>,
    ) -> Result<T, E>;
    pub fn try_fold_pruned<T, E>(
        &self,
        should_descend: &mut impl FnMut(&ResidualPolicyBranch<'_, O>) -> bool,
        visitor: &mut impl FnMut(ResidualPolicyNode<'_, O, T>) -> Result<T, E>,
    ) -> Result<T, E>;
}
```

Like `evaluate`, `partial_evaluate`, `evaluate_residual`, and
`complete_residual` take no `Context` (§3.1). `ResidualPolicy` mirrors the
executable policy algebra and adds traced constants used only when a resolved
arm must remain inside a pending residual. `evaluate_residual` evaluates that
AST alone; `complete_residual` is the trace-preserving completion path for a
`Residual<O>` because it merges the `Pending.consulted` prefix with facts read
from the residual AST.

Adapters should use the core `ResidualPolicy` introspection helpers instead of
duplicating structural walks. `fold` / `try_fold` visit children before their
parent and preserve source order, so backends can build filters, projections, or
analysis summaries bottom-up. When a parent must decide whether a branch should
be visited at all, such as skipping obligation-carrying `OrElse` fallbacks for
bulk listing, use `try_fold_pruned`; skipped `OrElse` fallbacks arrive at the
visitor as `fallback: None`.

**Reduction rules.** Over three-valued presence, `Has(f)` is ⊤/⊥ for
`Present`/`Absent` and stays the residual `Has(f)` for `Unknown`. Conditions
reduce to `Always`, `Never`, or a residual condition over only unknown facts.
Connectives reduce by their identities and short-circuits, leaving only
undecided sub-policies and explicit constants in the residual:

- **`All` (meet):** if any arm resolves `Deny`, the whole is `Resolved(Deny)`
  (`Deny` annihilates meet). Otherwise the residual is the meet of resolved
  permits, represented by traced permit constants, with the still-pending arms;
  if no arm remains pending it is `Resolved(Permit(meet))`.
- **`Any` (join):** if any arm resolves `Permit(O::top())`, the whole is
  `Resolved(Permit(O::top()))`. Otherwise the residual is the join of the
  resolved-`Permit` grade(s) with the still-pending arms; a resolved permit for
  non-top `o` is **kept** in the residual because a pending arm may join higher.
  If there are pending arms and no resolved permit, the first resolved denial is
  kept as `DenyWithTrace` so an all-deny completion keeps the same first-denial
  reason metadata. If no arm remains pending it is `Resolved` at the join.
- **`Not`:** reduces if its operand resolves; otherwise residual `Not`.
- **`OrElse`:** if `primary` resolves `Permit`, drop `fallback` and return
  `primary`; if `primary` resolves `Deny`, recurse into `fallback`; if `primary`
  is pending, the residual is
  `policy::or_else(primary_residual, fallback_residual)`. The fallback is also
  reduced against the known facts so the residual never re-encodes
  principal-level predicates.

In a `Pending` result, `consulted` holds exactly the facts already resolved while
reducing, with the same dedup as `DecisionTrace.consulted` (§5). Unknown facts
that remain as live `Has` predicates in the residual are *not* counted as
consulted until a later `evaluate` or `lower` reads them; facts stored inside a
traced constant are already-decided trace data, not live predicates.

**Soundness contract (testable):** for every completion `c` assigning
`Present`/`Absent` to the unknown facts,
`let residual = partial_evaluate(policy, known); complete_residual(&residual,
complete(known, c))` and `evaluate(policy, complete(known, c))` have the same
`Effect` and obligations. When a resolved arm remains in a pending residual,
traced constants preserve the decisive clause fields needed by
`denial_reason()` and audit traces: label, reason, shape, denied outcome, and
deciding facts. This equivalence is covered by property and regression tests in
the core suite.

Lowering the residual into a query is an adapter concern, never the kernel's:
core emits the residual `ResidualPolicy<O>`; a `QueryLowering` backend (§5.5)
translates it into a query. Which facts are principal- vs resource-scoped is
declared by the resolver, which marks resource facts `Unknown` when resolving
for a list query.

### 5.4 Denial reasons and i18n

A denial must explain itself to a human without ever placing prose in the core,
the trace, or the audit log. The kernel emits a **stable reason code plus
structured parameters**; localization happens only at the presentation edge.

```rust
pub struct DenialReason {
    pub code: ReasonCode,                        // deploy-stable key (§4.5)
    pub params: BTreeMap<ParamKey, ReasonValue>, // e.g. required_tier, the missing fact
    pub shape: DenyShape,                        // Forbidden | Hidden (§5.2)
}

pub struct ReasonCode(String);   // #[serde(transparent)]; the translation key (§4.5)
pub struct ParamKey(String);     // #[serde(transparent)] (§4.5)
pub enum ReasonValue { Str(String), Int(i64), Fact(FactId), Outcome(TraceValue) }
pub struct Locale(String);       // BCP-47 tag, e.g. "en-US"
```

- **Stable codes, not strings.** `ReasonCode` is author-assigned and
  deploy-stable (the same discipline as `FactId`/`ClauseLabel`) and *is* the
  translation key. Audit entries and analytics store the code and params, never
  localized text, so they stay locale-independent and aggregatable.
- **Shape gates disclosure.** A `Hidden` denial must NOT surface a specific
  reason — that leaks the resource's existence — so its presenter collapses to a
  generic "not found". Only `Forbidden` denials render a specific reason. This is
  a correctness rule enforced by the presenter, not a styling choice.
- **Localization is an adapter, in its own crate.** Core ships codes + params; a
  `ReasonCatalog` (§7) maps `(code, params, locale) -> String`. The recommended
  binding is [Fluent](https://projectfluent.org/) (plural/gender-aware,
  asymmetric translations), shipped as `gatekeep-fluent` (a `FluentCatalog:
  ReasonCatalog` over `.ftl` bundles). Localization is orthogonal to the HTTP
  boundary, so this crate is **web-framework-agnostic**: an axum service, an
  actix-web service, a Leptos SSR app, or a CLI all depend on `gatekeep-fluent`
  directly and reuse the same catalogs. `gatekeep-axum` only wires a catalog it
  is *given* into responses; it does not own Fluent. Swapping to gettext/ICU is a
  different sibling crate, not a core change. A Noop/identity catalog (emits the
  bare code) lives in core for tests.

`Decision<O>` exposes
`fn denial_reason(&self) -> Result<Option<DenialReason>, TraceError>` when
`O: Serialize` — no `Context` needed, since the decisive `Deny` clause carries
everything: the `code` is the grant's explicit `ReasonCode` or, by default, its
`ClauseLabel`; `params` are built from the clause's `unsatisfied` facts (as
`ReasonValue::Fact`) plus the denied grant's target outcome
(`ReasonValue::Outcome`) when present; `shape` is the clause's `DenyShape`.
`Ok(Some(_))` only on a `Deny` effect with a specific reason code or label. A
bare `Policy::Deny` has no specific reason metadata and yields `Ok(None)`.

### 5.5 Lowering a residual to a query

§5.3 produces a `Residual::Pending { residual, .. }`: a `ResidualPolicy<O>` with
live predicates only for `Unknown` resource-level facts, plus explicit constants
and traced constants for already-decided arms. Lowering turns that residual into
a backend query so a list endpoint returns exactly the authorized rows — and,
where the outcome is graded, each row's tier. Lowering lives entirely in the
backend adapter; core only emits the residual.

**Two outputs, not one.** A residual carries both Boolean structure (which rows
are permitted) and graded structure (the `O` each permitted row earns). SQL puts
these in different clauses — `WHERE` vs the `SELECT` list — so lowering yields
both:

```rust
pub trait QueryLowering<O> {
    type Filter;      // boolean fragment for WHERE — rows where the residual permits
    type Projection;  // per-row expression computing the granted O (e.g. a CASE)
    fn lower(&self, residual: &ResidualPolicy<O>, cx: &Context)
        -> Result<Lowered<Self::Filter, Self::Projection>, LowerError>;
}

pub struct Lowered<F, P> { pub filter: F, pub grade: P }

#[derive(Debug, thiserror::Error)]
pub enum LowerError {
    /// A residual fact has no backend predicate mapping. Fail loud — never drop.
    #[error("residual fact cannot be lowered: {0}")]
    Unlowerable(FactId),
    /// A graded projection was requested for a lattice that is not totally
    /// ordered, so meet/join are not LEAST/GREATEST. Filtering still works.
    #[error("graded projection requires a total order")]
    NonTotalGrade,
}
```

**Facts become row predicates — the dual of the resolver.** A `FactResolver`
answers "is fact `f` present for this (principal, resource)?"; lowering answers
"as a predicate over a candidate row, when is `f` present?". The application
supplies that mapping, keyed by the same stable `FactId` (§4.3):

```rust
// backend-specific (gatekeep-sqlx)
pub trait PgFactPredicates {
    fn predicate(&self, fact: &FactId, cx: &Context) -> Option<PgFragment>;
}
```

ABAC facts map to column predicates (`case.sensitivity <= $tier`); ReBAC edge
facts map to correlated `EXISTS` subqueries (`EXISTS (SELECT 1 FROM participants
p WHERE p.case_id = case.id AND p.principal_id = $pid)`). Principal-derived values
fold to bound parameters (`$tier`, `$pid`), since the principal facts were
resolved away in §5.3 — the residual never re-encodes principal predicates.

**How the algebra lowers:**

| residual node | filter (Boolean) | grade projection |
| --- | --- | --- |
| `Has(f)` | `predicate(f) IS TRUE` | — |
| `Always` / `Never` (Condition) | `TRUE` / `FALSE` | — |
| `Not` / `All` / `Any` (Condition) | `NOT` / `AND` / `OR` | — |
| `ResidualPolicy::Permit(o)` / `ResidualPolicy::Deny` | `TRUE` / `FALSE` | constant `o` / — |
| `ResidualPolicy::PermitWithTrace` / `ResidualPolicy::DenyWithTrace` | same as `Permit` / `Deny` | same as `Permit` / — |
| `ResidualPolicy::Grant` | `predicate(cond)` | `WHEN predicate(cond) THEN o` |
| `ResidualPolicy::All` (meet) | `AND` of arm filters | `LEAST` of arm grades |
| `ResidualPolicy::Any` (join) | `OR` of arm filters | `GREATEST` of arm grades |
| `OrElse{primary,fallback}` | override rule below | `CASE WHEN primary_filter THEN primary_grade ELSE fallback_grade END` |

`LEAST` / `GREATEST` model meet / join **only when `O` is totally ordered** — the
common tier case, mapped to an ordinal (`Released=0 < Shared=1 < Full=2`).
`gatekeep-sqlx`'s default `PgLowerer` therefore requires `O: SqlOutcome` for full
filter-plus-grade lowering. Call `lower_filter` when only the authorized-row
filter is needed; it works for any outcome lattice. A custom
`OutcomeProjection` can reject full projection with `NonTotalGrade` when the
caller chooses a runtime projection strategy.

Fact predicates are normalized with `IS TRUE` so SQL `NULL` behaves like an
absent fact. This preserves gatekeep's two-valued condition algebra: `Has(f)` is
true only when the row predicate is true, and `Not(Has(f))` includes false and
null rows.

**Override branches are not bulk-listed.** Per §6.3, break-glass and other
obligation-carrying overrides are `policy::or_else` fallbacks. Lowering one into
a list query would silently grant every matching row under a break-glass
obligation and defeat its per-resource audit. The `gatekeep-sqlx` lowerer
descends only the `primary` of a `policy::or_else` whose fallback carries an
obligation, dropping that fallback from both filter and projection. Bulk access
via an override needs a wider lowering result with an obligation marker column so
every overridden row is auditable; it is not exposed until that API exists. A
`policy::or_else` whose fallback carries no obligation lowers normally with a
`CASE WHEN primary_filter THEN primary_grade ELSE fallback_grade END` projection.

**Soundness contract (testable), mirroring §5.3.** For every candidate row `r`,
the lowered query selects `r` iff `evaluate(policy, complete(known, facts(r)))`
is a `Permit`, and the projected grade equals that `Permit`'s `O`. The
`gatekeep-sqlx` tests cover generated SQL, sampled in-memory agreement, and
Docker-backed Postgres differential execution via `make test-db`. Unlowerable
facts fail closed (`LowerError`); lowering never silently widens the result set.

## 6. The algebra

### 6.1 Condition constructors (Boolean)

```rust
pub mod condition {
    pub fn always() -> Condition;
    pub fn never() -> Condition;
    pub fn has<F: Fact>() -> Condition;
    pub fn not(c: Condition) -> Condition;
    pub fn all(cs: impl IntoIterator<Item = Condition>) -> Condition; // boolean AND
    pub fn any(cs: impl IntoIterator<Item = Condition>) -> Condition; // boolean OR
}
```

Empty `condition::all([])` and `condition::any([])` both return `Never` to fail
closed. Use `condition::always()` explicitly for an unconditional grant guard.

### 6.2 Policy constructors (graded) and grade composition

```rust
pub mod policy {
    pub fn permit<O>(outcome: O) -> Policy<O>;
    pub fn deny<O>() -> Policy<O>;
    pub fn grant<O>(outcome: O, condition: Condition) -> Policy<O>;
    // builder: .labeled("normal_case_access")
    pub fn all<O: Lattice>(ps: impl IntoIterator<Item = Policy<O>>) -> Policy<O>; // meet
    pub fn any<O: Lattice>(ps: impl IntoIterator<Item = Policy<O>>) -> Policy<O>; // join
    pub fn or_else<O>(primary: Policy<O>, fallback: Policy<O>) -> Policy<O>;
}
```

`Effect<O>` composition, with `Deny` as ⊥:

| op | `Permit(a) ∘ Permit(b)` | `Permit(a) ∘ Deny` | `Deny ∘ Deny` |
| --- | --- | --- | --- |
| `policy::any` = join (∨) | `Permit(a ∨ b)` | `Permit(a)` | `Deny` |
| `policy::all` = meet (∧) | `Permit(a ∧ b)` | `Deny` | `Deny` |

`policy::any` (most permissive satisfied grant) and `policy::all` (most
restrictive across independent gating dimensions) both ship in v1. `meet`/`join`
are commutative, associative, and idempotent, so the resulting `Effect` is
independent of arm order; the trace still records source order. Empty
`policy::all([])` / `policy::any([])` evaluate **fail-closed to `Deny`**, not to
the lattice identities (`policy::all([])` would otherwise grant `O::top()`).
This keeps the combinator constructors **infallible** — no `Result` tax at every
call site — while staying safe by default: `policy::any([])` denies already, and
empty `policy::all` is forced to deny too rather than vacuously granting.

`policy::all`-as-meet is the model for multi-dimension tiering: when access tier
is gated by several independent dimensions, the effective tier is the meet (most
restrictive), and any dimension denying denies the whole:

```rust
policy::all([
    policy::grant(role_tier(role),        role_holds()),             // e.g. Full
    policy::grant(sensitivity_ceiling(s), condition::always()),      // e.g. Shared
])  // both satisfied -> Permit(Full ∧ Shared) = Permit(Shared); any deny -> Deny
```

### 6.3 Obligations and the override rule

Obligations are stable identities (§4.5), declared as typed markers so call sites
are not stringly-typed:

```rust
pub struct ObligationId(String);            // #[serde(transparent)]
pub struct StaticObligationId(&'static str); // const fn new
pub trait ObligationSpec { const ID: StaticObligationId; }
// struct BreakGlass;
// impl ObligationSpec for BreakGlass {
//     const ID: StaticObligationId = StaticObligationId::new("break_glass");
// }
```

Obligations attach to the **decisive arm only** and do not accumulate.

- `policy::or_else`: if `primary` permits, its outcome and obligations stand and the
  fallback is never consulted; only if `primary` denies do `fallback`'s outcome
  *and* obligations apply.
- `policy::any`: union the obligations of the arm(s) permitting at the winning
  (join) grade; the singular `DecisiveClause` names the lowest-index such arm
  (§5 decision procedure), while `Decision::obligations` covers all of them.

**Modeling rule:** privileged or extra-scrutiny overrides (break-glass) are
modeled as ordered `policy::or_else` fallbacks, never as `policy::any` arms — so
the obligation attaches only when the override was actually *needed*:

```rust
policy::or_else(
    normal_case_access(),                              // Permit(Shared) -> no obligation
    policy::grant(ReadTier::Full, break_glass_active()) // only if normal denied
        .labeled("break_glass")
        .with_obligation::<BreakGlass>(),              // typed; audit flag attaches
)
```

If normal access permits at Shared, there is no break-glass obligation. Only
when normal denies and break-glass is active do you get `Permit(Full)` plus the
`BreakGlass` obligation. Accumulation would wrongly stamp the scrutiny flag on a
principal who had legitimate normal access.

### 6.4 The three models are one algebra over facts

gatekeep does not have three engines. RBAC / ABAC / ReBAC differ only in *which
facts the resolver fetches*:

- RBAC -> `condition::has::<Role<Admin>>()` (fact: principal roles)
- ABAC -> `condition::has::<AttrEq<Department, Eng>>()` (fact:
  principal/resource attributes)
- ReBAC -> `condition::has::<Related<Caseworker>>()` (fact: an edge, resolved
  from keepsake relations or an application participant repository)

Composition over registry — a policy is just a value, defined as a free function
co-located with its domain.

**Action dispatch is an exhaustive `match`, never a registry — and never a
wildcard.** Selecting the policy for an action is host code:
`fn case_policy(action: CaseAction) -> Policy<ReadTier>` matching each variant.
The match must be exhaustive with **no `_` arm**: adding a new action then fails
to compile until its policy is authored, which is the fail-closed default authz
demands. A wildcard arm silently routes new actions to a default — permissively
granting them, or denying them while hiding that a policy was never written.
Enforce this with the clippy restriction lint `clippy::wildcard_enum_match_arm`
on dispatch modules, and group shared actions explicitly (`Read | Audit => …`)
rather than falling through. (Action and tenant/jurisdiction are dispatch keys
for *selecting and composing* the policy (§3.1); principal-kind preconditions
enter as resolved facts, not kernel inputs.)

## 7. Adapter traits

All adapters are traits with `Noop*` defaults, matching keepsake's
`TransitionObserver` / `MetricsRecorder` / `AuditSink` pattern.

```rust
/// Async, owns IO. Resolves the facts a policy references into a frozen set.
#[async_trait]
pub trait FactResolver: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn resolve_for_decision(&self, required: &[FactId], cx: &Context)
        -> Result<KnownFacts, ResolveError<Self::Error>>;

    async fn resolve_for_query(&self, required: &[FactId], cx: &Context)
        -> Result<PartialFacts, ResolveError<Self::Error>>;
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError<E> {
    #[error("fact backend failed")]
    Backend(#[from] E), // from the data source
    #[error("required fact is missing: {0}")]
    MissingFact(FactId),   // a required fact the source could not produce
    #[error("fact resolution timed out")]
    Timeout,
}

/// Structured, side-channel observation of decisions. Defaults to no-op.
pub trait PolicyObserver: Send + Sync {
    fn observe(&self, decision_summary: &DecisionSummary);
}

/// Append-only audit boundary. Defaults to no-op; an in-memory impl exists for tests.
pub trait AuditSink: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn record(&self, entry: &AuditEntry) -> Result<(), Self::Error>;
}

/// Lowers a partial-evaluation residual into a backend filter + grade
/// projection. Backend-specific; `gatekeep-sqlx` emits a Postgres `WHERE` plus a
/// per-row grade `CASE`. Full lowering rules and soundness contract in §5.5.
pub trait QueryLowering<O> {
    type Filter;
    type Projection;
    fn lower(&self, residual: &ResidualPolicy<O>, cx: &Context)
        -> Result<Lowered<Self::Filter, Self::Projection>, LowerError>;
}

/// Localizes a structured denial reason (§5.4). Defaults to an identity catalog
/// (emits the stable code); a Fluent-backed impl lives in `gatekeep-fluent`.
pub trait ReasonCatalog {
    fn render(&self, reason: &DenialReason, locale: &Locale) -> String;
}
```

`resolve_for_decision` must return every required fact as `Present` or `Absent`;
`Unknown` is a construction error for `KnownFacts`. `resolve_for_query` returns
known principal/session facts and marks resource-scoped facts as `Unknown` so
`partial_evaluate` can leave them in the residual for `QueryLowering`. A backend
that cannot classify or produce a required fact returns `MissingFact`; `Unknown`
is never used as a soft failure.

Adapters define concrete backend error enums with `thiserror` and expose them as
`FactResolver::Error` / `AuditSink::Error`; the core API does not erase backend
failures behind opaque boxed trait objects. The orchestration layer chooses
whether audit failure is fail-open or fail-closed for its product boundary, but a
durable audit write failure is never silently swallowed by the trait.

The observer and audit payloads are **non-generic** (the trace erases `O`, §5.2):

```rust
pub struct PolicyAnchor { pub policy_id: PolicyId, pub policy_hash: PolicyHash }
pub enum EffectKind { Permit, Deny } // grade elided for aggregation

pub struct DecisionSummary {
    pub anchor: PolicyAnchor,
    pub effect: EffectKind,
    pub obligations: Vec<ObligationId>,
    pub consulted: Vec<(FactId, Presence)>,
}

pub struct AuditEntry {
    pub anchor: PolicyAnchor,
    pub trace: Trace,                  // self-describing (§5.2)
    pub effect: EffectKind,
    pub obligations: Vec<ObligationId>,
    /// Populated from the Context (§3.1) only when the sink is configured to
    /// record subjects for isolation auditing; both default to None.
    pub tenant: Option<TenantId>,
    pub principal: Option<SubjectRef>,
}
```

Both anchor to `{ policy_id, policy_hash }` (§4.4) and default to excluding
subject ids (keepsake's observability discipline): `tenant`/`principal` stay
`None` unless the sink opts in, so the default aggregation key is `FactId`, policy
id, effect, and obligations — not opaque application subject ids.

Durable audit storage should be queryable by default. SQL-style adapters store
the anchor, effect, obligations, consulted facts, reason code/params, tenant, and
principal as structured columns or child rows; they do not collapse the whole
entry into one opaque JSON blob. `TraceValue` remains opaque to the kernel, but
adapter storage should keep stable keys indexable so downstream export, search,
and reporting tools can answer policy-version, reason-code, and fact-consulted
questions without parsing arbitrary JSON.

The resolver computes the required facts with the core helper rather than
re-walking the tree itself:

```rust
/// Sorted set of facts a policy references; sorted order gives a stable fetch order.
pub fn required_facts<O>(policy: &Policy<O>) -> BTreeSet<FactId>;
```

It fetches them in that order and freezes either a `KnownFacts` or
`PartialFacts` bundle, depending on the resolver mode. Lazy per-predicate async
resolution inside `evaluate` is explicitly rejected — it would reintroduce
ordering nondeterminism and couple IO to the kernel.

Adapter caching is optional and never changes the kernel contract. The core does
not cache decisions or facts. Adapters MAY cache low-cardinality metadata such as
policy catalogues, fact predicate mappings, reason bundles, or relation
definitions; those caches use concrete/generic types with no-op defaults rather
than `Arc<dyn ...>` surfaces. Caches for request-scoped facts, active subject
lookups, or authorized-list results belong in application wrappers with the full
tenant/principal/resource/query shape in the cache key.

## 8. Crate layout

Mirrors keepsake's `core + adapter` workspace.

- `crates/gatekeep` — pure model, two-layer algebra, evaluator + partial
  evaluator, denial-reason codes, observer/audit/lowering/catalog traits, errors.
  Synchronous. No IO dependencies.
- `crates/gatekeep-keepsake` — fact-source adapter resolving keepsake relation
  ids (entitlements, holds, sanctions, gates) into gatekeep facts via an async
  `ActiveRelationSource`, with a sync `KeepsakeStore` wrapper and optional
  `keepsake-sqlx` implementation. Subject mapping is tenant-aware by default
  and configurable for applications that already encode tenancy in keepsake
  subjects. Query-mode facts are either resolved from the principal or explicitly
  deferred for row-level lowering.
- `crates/gatekeep-fluent` — a `FluentCatalog: ReasonCatalog` (§5.4) over
  project-fluent `.ftl` bundles. Web-framework-agnostic: usable from axum, actix,
  Leptos SSR, or a CLI. Core owns the trait and the stable codes, so a gettext or
  ICU binding is a separate sibling, not a core change.
- `crates/gatekeep-axum` — boundary integration for handlers or middleware:
  caller-owned policy/context selection, resolve→evaluate orchestration, audit
  and observer recording, and `Effect`/deny-shape response mapping (403 vs a
  generic 404 for `Hidden`). It renders forbidden denial reasons through whatever
  `ReasonCatalog` it is handed (typically `gatekeep-fluent`) and never renders a
  hidden denial's specific reason. The denial/reason types live in core, so this
  stays a thin, swappable adapter (a future `gatekeep-actix` reuses everything
  but this crate).
- `crates/gatekeep-sqlx` — Postgres lowering adapter for residual policies:
  resource `FactId`s map to trusted row predicates, and the `QueryLowering`
  backend turns a residual (§5.5) into a `WHERE` fragment plus a grade
  expression for authorized list queries. DB-backed fact resolution follows
  after the lowering API has settled.
- `examples/` — a billing-gate example, the send-app case-access example (§10),
  and an authorized-list example exercising partial evaluation.

Conventions inherited from keepsake: Rust 2024, the strict lint profile that
denies `unwrap` / `expect` / `panic!` / `todo!` / `dbg!`, `thiserror` for typed
errors, `dep.workspace = true` for shared dependencies, MIT OR Apache-2.0.
Policy-dispatch modules additionally enable `clippy::wildcard_enum_match_arm`
(§6.4).

Implementation modules stay focused while preserving public API paths: model and
identity types, evaluation, partial evaluation, query lowering, audit/observer
payloads, localization, and adapter support are private modules re-exported from
the crate root as needed. Large integration tests split by behavior (evaluation,
partial evaluation, lowering, audit, and adapters) instead of becoming one
catch-all test file.

## 9. Determinism requirements

- `evaluate` is `#[must_use]`, takes no clock, no `Context`, and performs no IO;
  any time-dependence enters as a resolved fact.
- `meet` / `join` are commutative, associative, and idempotent, so
  `policy::all` / `policy::any` produce an `Effect` independent of arm order;
  the trace records source order.
- Empty `policy::all` / `policy::any` evaluate fail-closed to `Deny` (never the
  lattice identity `O::top()`); the constructors stay infallible (§6.2).
- Short-circuit evaluation may shorten a `DecisionTrace` but must never change
  the `Effect` or `obligations`. Tests must assert this equivalence.
- The durable trace is self-describing (stable names only); positional,
  AST-relative traces exist only in the ephemeral debug mode.
- `Condition`, `Policy<O>`, `Decision<O>`, and `Trace` are serializable when the
  relevant `O` operations require `Serialize` / `DeserializeOwned`; pure
  evaluation itself has no serde bound. A decision is reproducible from
  `(Policy, KnownFacts)`.
- Partial evaluation is a conservative authorization reduction: for every
  completion of the unknown facts, evaluating the residual and original policy
  produces the same effect and obligations (§5.3). This equivalence is a
  property test.
- Lowering is sound: the lowered query selects a row iff in-memory evaluation
  permits it, with equal grade (§5.5); verified by differential test. Unlowerable
  facts fail closed.
- Boundary validation is tested directly: empty identifiers, invalid locales,
  invalid flat records, malformed policy/audit records, invalid scan limits, and
  bad lowering inputs all return typed errors rather than panicking or falling
  through to surprising backend behavior.

## 10. Acceptance test — send-app case access

The design is validated against the existing `app-auth` `policy` module, whose
real requirements are richer than allow/deny. gatekeep is only proven if it
expresses these without escaping back to bespoke code:

- A graded outcome: `O = ReadTier` (`Released < Shared < Full`), a bounded
  lattice via its total order.
- Role/action requirements equivalent to the existing `requirement(role, action)`
  decision table.
- Edge-role facts (live case participant roles) resolved by an adapter.
- Tenant isolation and principal-kind handled by tenant-keyed policy selection
  and tenant-scoped fact resolution (§3.1), not by kernel branching on `Context`.
- A break-glass fallback that grants `ReadTier::Full` with a `BreakGlass`
  obligation when the primary policy denies a read — modeled as a `policy::or_else`
  fallback per §6.3.
- The deny-shape distinction (`Hidden` vs `Forbidden`) authored on grants via
  `.hidden()` and surfaced on the decisive clause (§5.2), not hardcoded.
- **Multi-dimension tiering** (upcoming send-app feature): effective tier as the
  meet of independent gating dimensions via `policy::all` (§6.2). Shipping
  `meet` in v1 is what motivates spinning gatekeep out now.
- **Authorized list queries**: "which cases can this principal read?" via partial
  evaluation over principal-level facts (§5.3), with the resource-level residual
  lowered to SQL — not an N-row evaluation loop.
- **Localized denials**: a `Forbidden` read denial renders a specific localized
  reason from a stable code; a `Hidden` denial collapses to a generic message
  (§5.4).

The acceptance criterion: the `app-auth` `check_case_access` behavior — including
break-glass, tiering, multi-dimension meet, and hidden-vs-forbidden — is
reproduced by a gatekeep `Policy<ReadTier>` plus a `FactResolver`, with the pure
decision core fully unit testable against literal `KnownFacts` and no database.

## 11. Resolved design decisions

The questions previously open here are resolved in the body of this spec:

- **Grade composition** — `O` is a bounded lattice; `policy::any` = join,
  `policy::all` = meet, both shipping in v1, with `Deny` as ⊥ (§5.1, §6.2).
- **Obligation flow** — decisive-arm only, no accumulation; overrides are
  modeled as `policy::or_else` fallbacks (§6.3).
- **Trace shape** — self-describing via stable `FactId`s, outcome values, and
  author-assigned `ClauseLabel`s, anchored to a canonical policy hash; positional
  traces are debug-only (§4.4, §5.2).
- **Authorized queries** — partial evaluation over principal-level facts yields a
  residual; lowering (§5.5) splits it into a Boolean filter (any `O`) and a grade
  projection (totally-ordered `O`), with obligation-carrying override branches
  excluded from bulk by default. Ships in v1 (§5.3, §5.5).
- **Action dispatch** — exhaustive, wildcard-free `match`, fail-closed at compile
  time; no action registry (§6.4).
- **Denial reasons / i18n** — stable reason codes + params in core, localized at
  the edge via a `ReasonCatalog` (its own `gatekeep-fluent` crate); the `Hidden`
  shape suppresses specific reasons (§5.4).
- **Context & tenancy** — the kernel is pure over `(Policy, KnownFacts)` and
  never reads a `Context`; tenant isolation has two explicit integration points,
  tenant-scoped resolution and tenant-keyed policy composition (§3.1).
- **Fact model** — presence-only (`Present` / `Absent` / `Unknown`) with
  `KnownFacts` for full decisions and `PartialFacts` for query-mode residuals;
  value comparisons are reified into distinct facts by the resolver, with an
  optional opaque `TraceValue` for audit only (§4.3).
- **Stable identities** — `FactId`, `ClauseLabel`, `ObligationId`, `ReasonCode`,
  `ParamKey`, `TenantId` follow keepsake's `RelationKey` pattern: validated
  newtype + `Static*` const + marker trait; no raw strings at call sites
  (§4.3, §4.5).
- **Boundary records** — typed models validate on construction and deserialize
  through flat `*Record` shapes when storage/wire compatibility needs a flatter
  representation (§4.6).
- **Audit and caching** — audit sinks return typed write errors and durable audit
  storage stays queryable; caches are adapter/application concerns with concrete
  generic seams and no-op defaults (§7).
- **Policy hash** — `blake3(postcard(policy))` hex, anchored as
  `{ policy_id, policy_hash }` (§4.4).
- **Empty arms** — `policy::all([])` / `policy::any([])` evaluate fail-closed to
  `Deny`; constructors stay infallible (§6.2).
- **Decision procedure** — bottom-up, source-order; tie-break and `consulted`
  accumulation specified (§5 decision procedure).
