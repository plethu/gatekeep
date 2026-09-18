# Resource policies

Keep related operations together with `ResourcePolicy`. Its associated types
name the application's principal, resource, action and permitted outcome. An
action enum selects a `PreparedPolicy`; the async `resolve` method supplies
named boolean observations using your functions and services.

The complete ownership example is in
[`resource_policy.rs`](https://github.com/plethu/gatekeep/blob/main/crates/gatekeep/examples/resource_policy.rs).
Run it from a checkout:

```sh
cargo run -p gatekeep --example resource_policy
```

It uses `Authorizer::unaudited` deliberately. For audited application work, pass
an `AuditSink` to `Authorizer::new`. Call `authorize_resource` with the action,
principal, resource and authenticated `Context`, then inspect the returned
decision. A successful call can contain an audited denial.

The policy implementation checks that its domain principal and resource agree
with the context. Gatekeep cannot infer that an arbitrary `User` value came
from authentication, or that a loaded document belongs to the selected tenant.
There is no global actor, registry or string-based action dispatch.

Small gates can use `PreparedPolicy<()>` and a `FactResolver` directly. Neither
entry point requires a custom outcome type. Both reach the same evaluator and
audit boundary, and both propagate reported source failures.

Use `grant_clause` when attaching labels, reasons, hidden-denial presentation
or obligations. Its methods apply to a grant by construction. Compose the
resulting policies with `all`, `any` and `or_else`; `or_else` tries emergency
access only when the normal path denies. A normal shared-access permit should
not silently become full access merely because an emergency grant also exists.

Opaque Rust checks need explicit mappings for SQL filtering. They are not a
second policy language and Gatekeep does not translate arbitrary Rust into SQL.
