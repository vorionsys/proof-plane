---
"@vorionsys/proof-plane": patch
---

Extract `proof-plane` into its own standalone repository (`vorionsys/proof-plane`) with tokenless OIDC trusted publishing + provenance. Source recovered from the 0.1.4 commit (the canonical 0.1.4 was published from an unmerged branch, never landed on monorepo main). Pin `@vorionsys/contracts` to `^1.1.2` (was an unbounded `*`); declare `pg`/`fastify`/`express` as optional peer dependencies for the storage/API adapters (previously undeclared). Relicensed Apache-2.0.
