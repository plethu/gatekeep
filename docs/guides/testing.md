# Testing policies

Enable the core `test` feature to use `testing::compare_scenario` and
`testing::check_lattice`. Keep scenarios small and synthetic: owner, non-owner,
disabled account, another tenant, expired grant and backend failure are more
useful than copies of sensitive production records.

`compare_scenario` retains both full decisions. `authority_changed` compares
effect, permitted outcome, obligations and denial disclosure shape.
`explanation_changed` compares traces separately. A label change should not be
mistaken for newly granted access. The comparison covers the supplied scenario;
it is not proof that two policies agree for every possible input.

`check_lattice` checks bounds, closure, idempotence, identity, absorption,
commutativity and associativity. Supply every value for an exhaustive finite
check. A handful of values from a large type only establishes those examples.
Failures name the law without dumping context or protected values.

`PreparedPolicy::inspect` lists labels, reason codes and obligations, with advice
for missing and duplicate metadata. `FluentCatalog::missing_reasons` checks an
exact locale so fallback messages do not hide translation gaps. Formatting
arguments still need real rendering scenarios.

Use `decision.explain(ExplanationAudience::Audit)` for internal recorded checks,
or `Public` for minimal response text. Hidden public denials stay generic. The
audit explanation lists only consulted observations: it does not rerun providers
or invent the contents of skipped checks.

`prepared.replay(&entry)` requires the matching policy anchor and every required
boolean observation. It reports a mismatched policy or all missing inputs;
selected evidence may intentionally be incomplete. A digest cannot reconstruct
a fact set. Replay does not query providers, establish event integrity or grant
fresh authority for a protected operation.
