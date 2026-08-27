# Versioning

Gatekeep uses crate versions for API expectations. Gatekeep 2.0 moves durable
SQL audit ownership to Dovecote; semver applies to the public Rust API and the
event mapping contract.

## Semver

- **Major**: breaking changes to public API types, policy semantics, decision
  audit event layout, or migration ordering.
- **Minor**: additive API, new query helpers, new migrations that existing code
  can ignore until adopted.
- **Patch**: bug fixes and non-breaking schema corrections.

Pin published Gatekeep crates to the same release when they share a workspace
version. Install and check the matching Dovecote schema before deploying code
that emits durable audit events.

## Upgrade checklist

- Read the changelog for API changes, new migration files, and required ordering.
- Apply matching migrations before deploying code that depends on new schema.
- Test request paths and list-filter lowering when SQLx or policy shapes change.

The historical Gatekeep audit migrations remain available for v1 upgrade and
reconciliation only. They are not the 2.0 runtime schema and must remain
byte-identical. Dovecote migrations define the required 2.0 event and delivery
schema; your service decides when and how to apply them.
