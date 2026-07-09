# SQLx List Filtering

List endpoints need authorization before rows leave the database. `gatekeep-sqlx`
lowers a residual policy into trusted SQL fragments that can be appended to a
`sqlx::QueryBuilder`.

## Use Partial Evaluation

Start with the same policy used for single-resource checks. Mark request-known
facts in `PartialFacts` and leave row-level facts unknown.

For example, the request may know the caller is a support user. The database
row determines whether the caller owns the case. Partial evaluation removes the
request-known branch and leaves the row-level branch for SQL lowering.

## Bind Row Facts

`gatekeep-sqlx` does not guess table names or joins. The application maps fact
ids to trusted predicates through `SqlxFactPredicates`. That keeps schema
knowledge in the service.

Use one policy module for both request checks and list filtering. The list path
should only add the database mapping from fact ids to row predicates.

## Lowered Output

The adapter produces:

- a filter fragment for the `WHERE` clause
- a grade expression for the selected outcome
- bind values for trusted predicates

The lowered fragment is designed for application-owned query builders. Keep user
input in SQLx bind values. Do not build fact predicates from request strings.

## Backends

Postgres is the default backend. SQLite and MySQL are available behind
`sqlite` and `mysql` features. Backend-specific tests cover bind rendering and
grade combination.
