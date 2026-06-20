# keepsake DX follow-up acceptance criteria

This is the keepsake-side follow-up discovered while building
`gatekeep-keepsake` and the runnable axum keepsake example. It is intentionally
written as a fresh-context task brief for an agent working in
`/home/mari/code/personal/keepsake-rs`.

## Goal

Make keepsake's in-memory/testing contract ergonomic enough that adapters such
as `gatekeep-keepsake` do not need their own relation seeding wrappers or
example-only lifecycle plumbing.

The work should preserve keepsake's existing direction: explicit time,
typed `RelationSpec`s, validated boundary types, and no authorization-specific
concepts in keepsake itself.

## Current pain

- `gatekeep-keepsake` needs an `in_memory::grant_relation_at` wrapper only to
  seed `InMemoryActiveRelations` with a typed `RelationSpec`, deterministic
  timestamp, UUID instance id, subject, and empty attributes.
- Examples/tests still have to construct timestamps and UUIDs at call sites
  even when they only need "grant this active relation at this known time".
- Subject construction remains application-owned, but examples need a clean path
  from a validated subject value into in-memory relation seeding without copying
  low-level fixture code.

## Acceptance criteria

1. Add a first-party keepsake test/example seeding API.
   - It must be backed by keepsake's real `InMemoryActiveRelations`
     implementation, not a separate fake source.
   - It must support typed `RelationSpec` seeding.
   - It must accept caller-owned deterministic time; do not hide `Utc::now()` or
     any wall-clock call inside the helper.
   - It must accept a caller-provided relation instance id, or expose a
     deterministic builder path where the id is explicit before insertion.
   - It must preserve attributes support. Empty attributes should be easy, but
     not the only supported path.

2. Provide an ergonomic builder or helper for the common case.
   - A test should be able to express "subject S has active relation R at time T"
     in one short call or a small fluent builder.
   - The API should avoid leaking `BTreeMap::new()`, UUID conversion, and
     relation-spec insertion boilerplate into adapter tests.
   - The helper name should be keepsake-domain language such as active relation
     insertion/seeding/granting, not gatekeep-specific policy language.

3. Keep the boundary explicit.
   - The helper must not infer tenant, principal, or application authorization
     semantics.
   - It should take a keepsake `SubjectRef` or an existing typed keepsake subject
     value, not a gatekeep `Context`.
   - It must return keepsake's typed error path rather than panicking or using
     `unwrap`/`expect`.

4. Add tests in keepsake.
   - Cover typed `RelationSpec` seeding into `InMemoryActiveRelations`.
   - Cover empty attributes and non-empty attributes.
   - Cover deterministic time by asserting the stored/retrieved active relation
     matches the provided timestamp or activity window semantics already owned by
     keepsake.
   - Cover explicit instance id use so tests are reproducible.

5. Update keepsake docs/examples.
   - Document the helper in the same place keepsake documents in-memory/test
     relation sources.
   - Show the minimal common-case example and one attributes example.
   - Keep prose library-neutral: it should mention adapters/tests/examples, not
     gatekeep as the only consumer.

6. Gatekeep compatibility follow-up.
   - After the keepsake API exists, update `gatekeep-rs` to use it in
     `examples/axum-keepsake-authorized-list`.
   - Remove or shrink `gatekeep_keepsake::in_memory::grant_relation_at` if it
     becomes a pure pass-through.
   - `gatekeep-rs` must still pass `make check` and `make test-db` after that
     integration.

## Non-goals

- Do not add authorization concepts to keepsake.
- Do not add gatekeep types or a gatekeep dependency to keepsake.
- Do not make relation seeding depend on wall-clock time.
- Do not replace keepsake's real in-memory source with a test double.
- Do not broaden this into lifecycle API redesign unless the existing contract
  makes the seeding helper impossible.

## Suggested verification

In `keepsake-rs`:

- `make check`
- `make test-db` if the touched crates participate in database-backed tests.
- Any keepsake publish dry-run already used for release readiness.

In `gatekeep-rs`, after consuming the keepsake change:

- `make check`
- `make test-db`
