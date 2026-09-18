# Alternatives

Gatekeep is for applications that keep authorization in Rust and need typed
outcomes and inspectable decision evidence. It has one maintainer and limited
adoption. Choose it for that fit, not a claim that it replaces every policy
system.

[Gatehouse](https://github.com/thepartly/gatehouse) is the closest code-first
Rust alternative. Its ordinary Rust checks, veto rules and request-scoped fact
loading are worth considering. Our source comparison used commit `cb6c08d`:
its automatic provenance retained load status but erased successful fact values,
and its serializable results did not themselves provide a durable audit store.
An application can supply those boundaries. That is a design tradeoff, not a
claim that Gatehouse cannot serve sensitive applications.

[Cedar](https://github.com/cedar-policy/cedar) provides a dedicated policy language
and substantial validation work. [OPA](https://www.openpolicyagent.org/) fits
systems that want shared Rego policy and a broader policy-engine boundary.
[Casbin](https://github.com/apache/casbin-rs) offers configurable authorization
models and ecosystem adapters. These are credible choices when their policy
representation and deployment model match the application.

The motivation here is narrower: Laravel-like gates and resource policies,
written and tested as ordinary Rust, with durable evidence for consequential
checks. Gatekeep does not offer a hosted policy service, general graph database,
or automatic translation of Rust predicates into SQL.
