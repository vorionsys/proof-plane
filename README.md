# @vorionsys/proof-plane

[![npm version](https://img.shields.io/npm/v/@vorionsys/proof-plane.svg)](https://www.npmjs.com/package/@vorionsys/proof-plane)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](./LICENSE)

Tamper-evident event log for AI-agent governance decisions: an append-only,
hash-chained record with **dual hashing (SHA-256 + SHA3-256)** and **Ed25519
signatures**, plus chain anchoring for periodic external commitment.

```bash
npm install @vorionsys/proof-plane
```

Consumed by [`@vorionsys/mcp-server`](https://github.com/vorionsys/mcp-server)
(the `vorion_log_proof` / `vorion_execute_governed` tools write through this
package). Types come from [`@vorionsys/contracts`](https://github.com/vorionsys/contracts).

## Design

- **Append-only chain** — each event embeds the previous event's hash;
  any mutation breaks every downstream link.
- **Dual hash** — every event is hashed with both SHA-256 and SHA3-256.
  An attack must collide two unrelated hash constructions simultaneously;
  it also gives the chain an escape hatch if one family weakens.
- **Ed25519 signing** — events and anchor checkpoints are signed
  (`node:crypto` — no custom crypto).
- **Anchoring** (`events/chain-anchoring`, `events/external-anchor`) —
  periodic checkpoints of the chain tip, signable and exportable to an
  external witness.
- **Proof adapter** (`createProofAdapter`) — the integration surface: hand it
  a `ProofCommitterLike` and it turns governance decisions into committed,
  chained proof events.
- **Projections / API** — read-side views and HTTP routes for chain
  inspection, including dual-hash integrity verification.

## ⚠ Two proof-chain formats currently ship under the Vorion umbrella

This is a known, tracked divergence — stated here so nobody discovers it the
hard way:

| Format | Hashing | Producer | Verifier |
|---|---|---|---|
| **BASIS / proof-plane** | SHA-256 **+ SHA3-256** (dual) | this package, `gate-core`, `mcp-server` | [`@vorionsys/verify`](https://www.npmjs.com/package/@vorionsys/verify) (`npx basis-verify`) |
| **Aurais** | SHA-256 (single) | [`@vorionsys/aurais-core`](https://www.npmjs.com/package/@vorionsys/aurais-core) | [`@vorionsys/aurais-verify`](https://www.npmjs.com/package/@vorionsys/aurais-verify) |

A chain from one family will **not** verify under the other family's verifier.
Convergence (shared canonical serialization per RFC-0002 plus a declared
hash-suite field, so one verifier can check both) is tracked in
[vorionsys/basis-spec#17](https://github.com/vorionsys/basis-spec/issues/17).
Until that lands, always pair a chain with its own family's verifier.

## Verification

For BASIS-family chains produced by this package:

```bash
npx @vorionsys/verify chain.json --strict
```

## Status

Published and consumed in production surfaces, pre-1.0: the event shape
follows [RFC-0002](https://github.com/vorionsys/basis-spec/blob/main/rfcs/0002-proof-event-chain.md)
(canonical serialization, linkage, verification rules), and breaking changes
before 1.0 will be called out in the changelog.

## License

Apache-2.0.
