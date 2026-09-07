# Structural Rust checks

These rules cover a few structural patterns that rustfmt and Clippy do not
express well. Run them with:

```sh
mise run lint-structure
```

Error-severity rules fail the task. Warnings need review and may be intentional.

| Signal | Tool | Severity | Threshold |
| --- | --- | --- | --- |
| Deep block nesting | Clippy `excessive_nesting` | error | `4` |
| Long `if` / `else if` cascade | `rust-elseif-cascade` | error | 3 branches |
| Ordered `if let Some(...)` cascade | `rust-if-let-policy-cascade` | warning | 2 guards |
| Dense `if let Some(...)` cascade | `rust-if-let-policy-cascade-dense` | error | 3 guards |
| Missing blank after control flow | `rust-block-spacing` | error | — |

`rust-block-spacing` runs after rustfmt. Rustfmt preserves intentional blank
lines after closing braces but has no stable option to insert them selectively.

Refactor the owning operation when a rule identifies excessive nesting or mixed
responsibilities. Do not add lint suppressions, exclude paths, or raise thresholds
to make a gate pass. If a public compatibility contract prevents a compliant
change, document the specific boundary for maintainer review.
