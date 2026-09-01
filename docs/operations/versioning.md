# Versioning

Gatekeep uses crate versions for API expectations. Gatekeep 4.0 makes the
current audit representation and durable version markers explicit; semver applies to the public
Rust API and the event mapping contract.

## Semver

- **Major**: breaking changes to public API types, policy semantics, decision
  audit event layout, or migration ordering. Gatekeep 4.0 requires current
  `AuditEntry` construction through validated types and emits explicit audit
  schema and policy-hash versions; 3.x payloads must use the explicit legacy
  decoder/import path.
- **Minor**: additive API, new query helpers, new migrations that existing code
  can ignore until adopted.
- **Patch**: bug fixes and non-breaking schema corrections.

Pin published Gatekeep crates to the same release when they share a workspace
version. Gatekeep 4.0 requires Dovecote 0.2 for durable audit and Keepsake 4
for the relation bridge. Install and check the matching schemas before
deploying code that emits durable audit events or resolves Keepsake relations.

## Upgrade checklist

- Read the changelog for API changes, new migration files, and required ordering.
- Apply matching migrations before deploying code that depends on new schema.
- Test request paths and list-filter lowering when SQLx or policy shapes change.
- Test every relation-backed path with equal subject ids in two tenants and
  assert that a wrong-tenant lookup is absent.

The historical Gatekeep audit migrations remain available for v1 upgrade and
reconciliation only. They are not the 4.0 runtime schema and must remain
byte-identical. Dovecote migrations define the required 4.0 event and delivery
schema; your service decides when and how to apply them.
