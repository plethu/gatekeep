# Versioning

Gatekeep uses crate versions for both API and schema expectations. From 1.0
onward, semver applies to the public Rust API and to schema expectations in
`gatekeep-sqlx`.

## Semver

- **Major**: breaking changes to public API types, policy semantics, decision
  audit record layout, or migration ordering.
- **Minor**: additive API, new query helpers, new migrations that existing code
  can ignore until adopted.
- **Patch**: bug fixes and non-breaking schema corrections.

Pin published Gatekeep crates to the same release when they share a workspace
version. Apply matching `gatekeep-sqlx` migrations before deploying code that
depends on new audit schema.

## Upgrade checklist

- Read the changelog for API changes, new migration files, and required ordering.
- Apply matching migrations before deploying code that depends on new schema.
- Test request paths and list-filter lowering when SQLx or policy shapes change.

Embedded migrations define the required audit schema. Your service decides when
and how to apply them.
