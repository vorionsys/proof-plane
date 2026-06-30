# Changelog

## 0.1.5

### Patch Changes

- d0142c4: Extract `proof-plane` into its own standalone repository (`vorionsys/proof-plane`) with tokenless OIDC trusted publishing + provenance. Source recovered from the 0.1.4 commit (the canonical 0.1.4 was published from an unmerged branch, never landed on monorepo main). Pin `@vorionsys/contracts` to `^1.1.2` (was an unbounded `*`); declare `pg`/`fastify`/`express` as optional peer dependencies for the storage/API adapters (previously undeclared). Relicensed Apache-2.0.

All notable changes to `@vorionsys/proof-plane` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-02-17

### Changed

- Standardized package metadata for npm publish

## [0.1.1] - 2026-02-16

### Added

- Dual-hash verification: SHA3-256 integrity anchor (`eventHash3`) alongside SHA-256 chain hash
- Ed25519 digital signatures for event authenticity and non-repudiation
  - `generateSigningKeyPair()`, `signEvent()`, `verifyEventSignature()`
  - `EventSigningService` class with trusted key management
  - Batch signature verification via `verifyEventSignatures()`
- Shadow mode support for T0_SANDBOX testnet agents
  - `getUnverifiedShadowEvents()` query
  - `verifyShadowEvent()` for HITL verification workflow
- Hook manager integration (`EVENT_EMITTED` hook for A3I)
- REST API routes (Fastify + Express adapters)
  - `POST /proof` -- submit events
  - `GET /proof/:id` -- retrieve events
  - `GET /proof/verify/:id` -- verify single event (hash + signature)
  - `GET /proof/chain/:correlationId` -- trace queries
  - `POST /proof/chain/verify` -- full chain verification
  - `GET /proof/stats` -- aggregate statistics
  - `GET /proof/latest` -- most recent event
- OpenAPI 3.1 specification (`openapi.yaml`)
- `ProofPlaneLogger` bridge for A3I authorization engine integration
- Combined chain + signature verification via `verifyChainAndSignatures()`
- Environment tagging (`production`, `testnet`, `development`)

### Changed

- License updated from MIT to proprietary

## [0.1.0] - 2026-02-04

### Added

- Initial release
- `ProofPlane` class with event logging (`logIntentReceived`, `logDecisionMade`, `logTrustDelta`, `logExecutionStarted`, `logExecutionCompleted`, `logExecutionFailed`)
- SHA-256 hash-chained event model with genesis event support
- `ProofEventStore` abstract interface for pluggable storage
- `InMemoryEventStore` reference implementation
- `ProofEventEmitter` with serialized emission and batch support
- Chain verification (`verifyChain`, `verifyChainWithDetails`)
- Correlation-based trace queries (`getTrace`)
- Agent history queries (`getAgentHistory`)
- Real-time event subscriptions (`subscribe`, `subscribeToType`)
- Event statistics (`getStats`)

[0.1.1]: https://github.com/vorionsys/vorion/compare/proof-plane-v0.1.0...proof-plane-v0.1.1
[0.1.0]: https://github.com/vorionsys/vorion/releases/tag/proof-plane-v0.1.0
