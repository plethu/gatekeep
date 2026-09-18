# Checked authoring and evidence migration

This guide covers the upgrade from Gatekeep 4 to 5 and from
`gatekeep-keepsake` 5 to 6. Keepsake itself remains on version 6.

Use `grant_clause(...).into_policy()` for new grants and `with_bool::<Fact>` for
ordinary checks. Existing pure policies keep their evaluation semantics and
policy-hash format. Moving to `authorize_prepared` is deliberate: every required
fact must now be returned explicitly, including false observations.

The shared `AuthorizationError` is also exposed under the existing Axum error
name. Core `FactResolutionEvidenceError` now includes selected-observation
validation failures. Deserializing `FactResolution<F>` requires `F` to implement
`ObservationFacts`; `KnownFacts` and `PartialFacts` do. A custom implementation
must report supplied entries and preserve omission as `None`. These public
contract changes require a major release of the core and dependent adapters.

`FactResolver` now requires only `resolve_for_decision`. For SQL list filtering,
move `resolve_for_query` into a separate `impl QueryFactResolver` on the same
resolver and import that trait at query call sites. Its error type comes from
`FactResolver`. Point-only resolvers can delete their unused query method.

New decision records use audit schema 2. Readers accept schema 1 and 2; old
schema-1 records retain their marker, and empty selected evidence is not added
to their serialized payload. A schema-1 record cannot claim schema-2 individual
observations. Historical database migration files and policy hash version 1
remain unchanged. Pre-4.0 records still require the existing explicit importer.
Deploy readers that understand schema 2 before enabling new writers. Old readers
correctly reject schema 2 rather than silently dropping richer evidence.

Failed attempts use their own schema 1 and event type
`gatekeep.authorization_attempt_failed` in the existing audit stream. Exporters
must dispatch on event type before choosing the decision or attempt decoder.
No new history table or parallel outbox is introduced.

For retries, retain `PendingDecision` or the frozen attempt returned on a failed
attempt write. Reusing an occurrence with freshly resolved facts can conflict
with an already stored event. The older occurrence setter remains available for
existing integrations, but it is not a general reauthorization retry mechanism.

SQLx event encoding and current decoding reject payloads larger than one MiB.
The bound applies to the complete JSON payload, independently of the 256 selected
observation limit. Oversized custom metadata needs an application-owned reference
or a separately reviewed historical importer, not an unbounded default decoder.
