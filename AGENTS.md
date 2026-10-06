@~/.config/agents/AGENTS.md

# Gatekeep

Published Rust authorization library. Read `README.md`, `CONTRIBUTING.md` and
`docs/operations/versioning.md` before changing public or durable contracts.
Use the global `public-library` skill for release decisions.

- Stabilize the current published major lines. Preserve project names, release
  history, historical migration bytes and policy-hash identities; do not reset
  versions or retire the project to repair the appearance of earlier churn.
- Kumite's control plane is a real application consumer. Where available,
  exercise affected authorization, denial, transaction and audit workflows
  before publication. Keep application policy in the consumer and Gatekeep
  generic; neither builds nor ordinary tests should require that private repo.
- Follow the existing contribution and versioning gates, including public API
  comparison and package-consumer checks. A permitted major bump alone does
  not establish that publishing the break is worthwhile.
