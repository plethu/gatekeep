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

Gatekeep crates can advance independently when their compatibility boundaries
differ. The current release candidates are:

| Crate | Candidate | Compatible dependencies |
| --- | --- | --- |
| gatekeep | 4.0.1 | Runtime-free authorization core |
| gatekeep-sqlx | 4.0.1 | Gatekeep 4 and Dovecote 0.2 |
| gatekeep-keepsake | 5.0.0 | Gatekeep 4 and Keepsake 6 |
| gatekeep-axum | Existing 4.0.0 | Gatekeep 4 |
| gatekeep-fluent | Existing 4.0.0 | Gatekeep 4 |

The published gatekeep-keepsake 4.0.0 bridge uses Keepsake 4; adopting the new
effective-relation contract requires bridge 5 and Keepsake 6. Compatible lower
bounds remain unchanged where no new API is needed. Install and check matching
schemas before deploying code that emits durable audit events or resolves
Keepsake relations. Package semver does not replace durable schema validation.

## Upgrade checklist

- Read the changelog for API changes, new migration files, and required ordering.
- Apply matching migrations before deploying code that depends on new schema.
- Test request paths and list-filter lowering when SQLx or policy shapes change.
- Test every relation-backed path with equal subject ids in two tenants and
  assert that a wrong-tenant scope cannot produce an accepted authorization fact.

The historical Gatekeep audit migrations remain available for v1 upgrade and
reconciliation only. They are not the 4.0 runtime schema and must remain
byte-identical. Dovecote migrations define the required 4.0 event and delivery
schema; your service decides when and how to apply them.

## Coordinated release checks

Before publishing the current candidates:

1. Obtain green `ci` / `gates` results for the reviewed Gatekeep commit. That job
   runs the canonical gate and the PostgreSQL/MySQL database lanes. Registry-only
   resolution of gatekeep-keepsake 5 requires Keepsake 6 to exist in the registry;
   a local source override is separate evidence.
2. Run the `relation consumer` / `source-integration` job on reviewed matching
   Keepsake 6 and Dovecote 0.2.2 commits. The workflow supports both direct
   dispatch and reuse from CI. The required PR/main caller pins Keepsake
   `fe87616ad4661bd17981b64eeb680e11f2191f83` and Dovecote
   `5a1803935c868359e3e41d783bc29dd9ab1c0212`; the source consumer's lock
   matches those reviewed sibling versions. Update pins deliberately rather
   than following mutable branches.
3. Verify the package archives that will actually be published, including a
   registry-only check after dependency publication. Publish `gatekeep` 4.0.1
   before the new SQLx and Keepsake adapters. Publish gatekeep-keepsake 5 only
   after Keepsake 6 is available. Do not republish unchanged 4.0.0 Axum or Fluent
   versions.
4. Record the individual crate versions in release notes and tags. This release
   is not a claim that every crate has become version 5. Update candidate
   changelog headings only when the corresponding release is ready.

Dovecote's candidate 0.2.2 remains compatible with the existing 0.2 minimum and
is not a newly required Gatekeep runtime API. Its reviewed source commit is
required for the current locked integration proof. Source CI, dependency release,
registry package verification and final publication remain distinct steps.
