/**
 * ProofAdapter - Unified routing layer for strict and deferred proof modes
 *
 * In 'strict' mode, every governance event is written synchronously through
 * the ProofPlane (~5-8ms per event). Tamper-evident immediately.
 *
 * In 'deferred' mode, events are committed as a hash into the ProofCommitter's
 * in-memory buffer (<1ms), then batch-flushed with Merkle trees, signatures,
 * and persistence asynchronously. Same tamper-evidence, just delayed.
 *
 * Both ProofPlane and ProofCommitter continue to work exactly as they do now.
 * This adapter is a thin routing layer, not a rewrite.
 *
 * @packageDocumentation
 */

import { ProofEventType, type ProofEventPayload } from '@vorionsys/contracts';
import type { ProofPlane } from './proof-plane/proof-plane.js';

/**
 * Minimal proof event shape accepted by the adapter.
 *
 * This is intentionally compatible with the runtime ProofCommitter's ProofEvent
 * so the orchestrator hot path can pass events without conversion.
 */
export interface ProofAdapterEvent {
  /** Event type identifier (matches ProofEventType enum values at runtime) */
  type: string;
  /** Entity ID (agent, intent, etc.) */
  entityId: string;
  /** Event payload */
  payload: Record<string, unknown>;
  /** Timestamp (epoch ms) */
  timestamp: number;
  /** Optional correlation ID for linking events */
  correlationId?: string;
}

/**
 * Unified interface for routing proof events to either
 * ProofPlane (strict) or ProofCommitter (deferred).
 */
export interface ProofAdapter {
  /** Which mode this adapter is operating in */
  readonly mode: 'strict' | 'deferred';

  /**
   * Log a proof event.
   *
   * - strict mode: delegates to ProofPlane, returns event ID
   * - deferred mode: delegates to ProofCommitter.commit(), returns commitment ID
   */
  logEvent(event: ProofAdapterEvent): string | Promise<string>;
}

/**
 * Duck-typed ProofCommitter interface so this package doesn't need
 * a hard dependency on @vorionsys/runtime.
 */
export interface ProofCommitterLike {
  commit(event: ProofAdapterEvent): string;
}

/**
 * Configuration for createProofAdapter factory.
 */
export interface ProofAdapterConfig {
  /** Operating mode */
  mode: 'strict' | 'deferred';
  /** Required when mode='strict' */
  proofPlane?: ProofPlane;
  /** Required when mode='deferred' */
  proofCommitter?: ProofCommitterLike;
}

/**
 * Strict-mode adapter: delegates to ProofPlane synchronously.
 */
class StrictProofAdapter implements ProofAdapter {
  readonly mode = 'strict' as const;
  private readonly proofPlane: ProofPlane;

  constructor(proofPlane: ProofPlane) {
    this.proofPlane = proofPlane;
  }

  async logEvent(event: ProofAdapterEvent): Promise<string> {
    // Cast the string type to the enum — values match at runtime
    const eventType = event.type as ProofEventType;
    const payload = { type: event.type, ...event.payload } as ProofEventPayload;
    const correlationId = event.correlationId ?? event.entityId;

    const result = await this.proofPlane.logEvent(
      eventType,
      correlationId,
      payload,
      event.entityId,
    );
    return result.event.eventId;
  }
}

/**
 * Deferred-mode adapter: delegates to ProofCommitter.commit() (<1ms).
 */
class DeferredProofAdapter implements ProofAdapter {
  readonly mode = 'deferred' as const;
  private readonly committer: ProofCommitterLike;

  constructor(committer: ProofCommitterLike) {
    this.committer = committer;
  }

  logEvent(event: ProofAdapterEvent): string {
    return this.committer.commit(event);
  }
}

/**
 * Factory function to create a ProofAdapter.
 *
 * @param config - mode plus the required backend for that mode
 * @returns A ProofAdapter that routes events to the correct backend
 * @throws if the required backend is not provided for the selected mode
 *
 * @example
 * ```typescript
 * // Strict mode (existing behavior)
 * const adapter = createProofAdapter({
 *   mode: 'strict',
 *   proofPlane: myProofPlane,
 * });
 *
 * // Deferred mode (60x faster hot path)
 * const adapter = createProofAdapter({
 *   mode: 'deferred',
 *   proofCommitter: myProofCommitter,
 * });
 *
 * // Usage is identical regardless of mode
 * const id = await adapter.logEvent({
 *   type: 'decision_made',
 *   entityId: 'agent-123',
 *   payload: { permitted: true },
 *   timestamp: Date.now(),
 * });
 * ```
 */
export function createProofAdapter(config: ProofAdapterConfig): ProofAdapter {
  if (config.mode === 'strict') {
    if (!config.proofPlane) {
      throw new Error(
        'ProofAdapter: strict mode requires a proofPlane instance',
      );
    }
    return new StrictProofAdapter(config.proofPlane);
  }

  if (config.mode === 'deferred') {
    if (!config.proofCommitter) {
      throw new Error(
        'ProofAdapter: deferred mode requires a proofCommitter instance',
      );
    }
    return new DeferredProofAdapter(config.proofCommitter);
  }

  // Exhaustive check
  throw new Error(`ProofAdapter: unknown mode '${config.mode as string}'`);
}
