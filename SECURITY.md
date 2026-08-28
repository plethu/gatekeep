# Security

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's
GitHub Security Advisories. Include the affected crate and version, enabled
feature flags, database backend where relevant, a minimal reproduction, and
the impact you observed. Do not include production credentials, bearer
tokens, raw claims, or tenant data in a report.

We will acknowledge a report when it is received, investigate it, and
coordinate a fix or mitigation with the reporter. A public issue is suitable
for ordinary bugs, documentation mistakes, or questions that do not expose a
security boundary.

## Security boundaries

Gatekeep evaluates policies and carries an application-established tenant
binding through authorization, query lowering, and audit records. It does not
authenticate requests, verify JWTs or OIDC claims, choose a tenant, manage
sessions, configure database row-level security, encrypt data, manage KMS
keys, or execute policy obligations.

The application must verify the identity provider assertion, audience,
issuer, lifetime, principal/tenant relationship, and any membership rules
before constructing an application-verified binding. Gatekeep records only
bounded authority metadata, validity, and a fixed-size digest; it never needs
raw claims or tokens. Trusted-service bindings are a separate, explicitly
named path and are not end-user authentication evidence.

`gatekeep-sqlx` requires a validated tenant table/column identifier and emits
a typed tenant predicate for both the filter and grade projection. Raw SQL,
exports, caches, pooled connection settings, background workers, and admin
queries remain application responsibilities. `gatekeep-keepsake` passes the
requested tenant explicitly to every Keepsake relation lookup and retains it
on lifecycle targets, but it cannot repair a caller that bypasses its API.

Durable audit is an append-only event request to Dovecote. A successful audit
enqueue is not proof that an external obligation ran, and an audit occurrence
identity is not an authentication or replay-prevention token.

## Assurance limits

The project does not claim an independent security audit, certification, or
regulatory compliance. The local project gate includes compiler, lint, test,
and cargo-deny advisory, license, source, and ban checks. Those checks are
evidence about the reviewed dependency graph and source revision, not a
guarantee that an application deployment is secure. Review the dependency
policy and deployment controls when dependencies or enabled features change.

## Temporary MySQL RSA advisory exception

The optional MySQL SQLx path inherits SQLx's `mysql-rsa` feature so a non-TLS
connection can complete `sha256_password` or full `caching_sha2_password`
authentication. SQLx encrypts the password with the server's public key;
Gatekeep does not accept private keys or perform RSA decryption or signing.

RustSec `RUSTSEC-2023-0071` concerns timing leakage in RSA private-key
operations, and no patched `rsa` release is currently available. The
repository's targeted cargo-deny exception applies only to this transitive
SQLx path and only when the optional MySQL graph is enabled. Prefer TLS for
deployed connections. Review by 2026-12-31, or immediately when SQLx or `rsa`
ships a replacement/fix, the authentication policy changes, or private-key RSA
use is introduced; remove the exception at that review.
