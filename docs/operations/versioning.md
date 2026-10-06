# Versioning

Semver applies to Gatekeep's public Rust APIs and event mapping contracts.
Breaking changes require a major release; additive APIs use minor releases,
and compatible fixes use patches. Crates can advance independently when their
compatibility boundaries differ. Dependency requirements live in the package
manifests; released changes belong in the [changelog](https://github.com/plethu/gatekeep/blob/main/CHANGELOG.md).

> [!NOTE]
> Those early releases really should’ve stayed at 0.x. I got a bit ahead of
> myself with 1.0! I’d been used to private projects and writing software at
> work, so putting my own libraries out there has been a learning experience.

## Maintenance

I’m maintaining these release lines:

| Crate | Maintained versions |
| --- | --- |
| `gatekeep` | 5.x |
| `gatekeep-axum` | 5.x |
| `gatekeep-fluent` | 5.x |
| `gatekeep-sqlx` | 5.x |
| `gatekeep-keepsake` | 6.x |

Minor and patch releases will preserve compatibility within these lines.
I’m not promising backports to older major versions.

Planned breaking changes will be tested in a consumer application and offered
as prereleases, with migration guidance, before a stable release.

## Durable formats

Package versions, audit schemas and policy-hash formats have separate consumers.
A Rust API change does not justify rewriting stored history. Keep historical
migration files byte-identical and provide explicit readers or importers for
older event formats. Deploy compatible readers before enabling new writers.
See [migrations](migrations.md) and the
[checked-authoring upgrade](improvement-migration.md) for concrete transitions.

## Release checks

Before publishing, run the checks in [Contributing](https://github.com/plethu/gatekeep/blob/main/CONTRIBUTING.md) and
verify the actual package archives. Publish dependencies before their adapters,
then verify registry-only resolution: sibling source overrides do not establish
that published consumers can build. The relation-consumer workflow owns the
pinned sibling revisions; do not duplicate those pins in documentation.

Compare public APIs against the published baselines in
`scripts/check-public-api.sh`. Use major-release mode only for an intentional
breaking release. After publication, update the baselines and return the CI lane
to minor-change enforcement. API comparison does not replace behavior, database
or durable-format tests.
