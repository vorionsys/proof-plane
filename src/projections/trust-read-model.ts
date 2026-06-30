/**
 * CQRS Trust Read Model Projector
 *
 * Materializes trust state from proof events into queryable read models
 * designed for 100K-agent fleet operations. Consumes the proof event
 * stream and projects three read models:
 *
 *   - AgentTrustSummary: per-agent trust snapshot
 *   - FleetOverview: fleet-wide aggregate metrics
 *   - ProofChainStatus: chain health and throughput
 *
 * Architecture:
 *   ProofEventStore  ──►  TrustReadModelProjector  ──►  In-memory read models
 *                                                   └──►  Optional persistence callback
 *
 * The projector supports full replay from event store on startup and
 * continuous incremental projection from new events.
 *
 * @packageDocumentation
 */

import { EventEmitter } from 'node:events';
import type { ProofEvent } from '@vorionsys/contracts';
import type { ProofEventStore, EventQueryOptions } from '../events/event-store.js';

// ---------------------------------------------------------------------------
// Read Model Types
// ---------------------------------------------------------------------------

/** Per-agent trust snapshot — the primary CQRS read model. */
export interface AgentTrustSummary {
  agentId: string;
  currentTier: number;
  currentScore: number;
  lastActionTime: Date;
  totalActions: number;
  denialRate: number;
  integrityScore: number;
}

/** Fleet-wide aggregate metrics. */
export interface FleetOverview {
  totalAgents: number;
  tierDistribution: Record<string, number>; // T0-T7
  avgIntegrity: number;
  activeCount: number;
  containedCount: number;
}

/** Chain health and throughput metrics. */
export interface ProofChainStatus {
  totalProofs: number;
  proofsPerSecond: number;
  anchoredCount: number;
  pendingCount: number;
  lastAnchorTime: Date | null;
}

/** Configuration for the projector. */
export interface TrustReadModelProjectorConfig {
  /** Batch size when replaying from event store (default: 500). */
  replayBatchSize: number;
  /** Poll interval in ms when subscribing (default: 1000). */
  pollIntervalMs: number;
  /** Threshold (seconds) for considering an agent "active" (default: 300). */
  activeThresholdSec: number;
  /** Trust score threshold below which an agent is "contained" (default: 200). */
  containedScoreThreshold: number;
  /** Optional async callback to persist read models externally. */
  persistCallback?: (models: {
    agents: Map<string, AgentTrustSummary>;
    fleet: FleetOverview;
    chain: ProofChainStatus;
  }) => Promise<void>;
}

const DEFAULT_CONFIG: TrustReadModelProjectorConfig = {
  replayBatchSize: 500,
  pollIntervalMs: 1_000,
  activeThresholdSec: 300,
  containedScoreThreshold: 200,
};

// ---------------------------------------------------------------------------
// Internal tracking
// ---------------------------------------------------------------------------

interface AgentAccumulator {
  agentId: string;
  currentTier: number;
  currentScore: number;
  lastActionTime: Date;
  totalActions: number;
  totalDenials: number;
  integrityScore: number;
}

// ---------------------------------------------------------------------------
// Projector
// ---------------------------------------------------------------------------

export type ProjectorEvent =
  | 'projection:updated'
  | 'projection:replay_started'
  | 'projection:replay_completed'
  | 'projection:error';

export class TrustReadModelProjector extends EventEmitter {
  private readonly store: ProofEventStore;
  private readonly config: TrustReadModelProjectorConfig;

  // ── Read models ──────────────────────────────────────────────────────
  private agents: Map<string, AgentAccumulator> = new Map();
  private totalProofs = 0;
  private anchoredCount = 0;
  private pendingCount = 0;
  private lastAnchorTime: Date | null = null;

  // ── Throughput tracking ──────────────────────────────────────────────
  private proofTimestamps: number[] = [];
  private readonly throughputWindowMs = 60_000; // 1 minute window

  // ── Subscription ─────────────────────────────────────────────────────
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private lastProcessedTime: Date | null = null;
  private running = false;

  constructor(store: ProofEventStore, config?: Partial<TrustReadModelProjectorConfig>) {
    super();
    this.store = store;
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  /**
   * Start the projector: replay existing events then begin polling for new ones.
   */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    // Replay existing events
    await this.replay();

    // Begin polling for new events
    this.pollTimer = setInterval(() => {
      this.pollNewEvents().catch((err) => {
        this.emit('projection:error', err);
      });
    }, this.config.pollIntervalMs);
  }

  /**
   * Stop the projector gracefully.
   */
  stop(): void {
    this.running = false;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  /**
   * Check whether the projector is running.
   */
  isRunning(): boolean {
    return this.running;
  }

  // -----------------------------------------------------------------------
  // Query API
  // -----------------------------------------------------------------------

  /**
   * Get the trust summary for a single agent.
   */
  getAgentSummary(agentId: string): AgentTrustSummary | null {
    const acc = this.agents.get(agentId);
    if (!acc) return null;
    return this.accumulatorToSummary(acc);
  }

  /**
   * Get all agent summaries (for dashboards / bulk export).
   */
  getAllAgentSummaries(): AgentTrustSummary[] {
    return Array.from(this.agents.values()).map((acc) => this.accumulatorToSummary(acc));
  }

  /**
   * Get the fleet-wide overview.
   */
  getFleetOverview(): FleetOverview {
    const now = Date.now();
    const tierDist: Record<string, number> = {};
    for (let t = 0; t <= 7; t++) {
      tierDist[`T${t}`] = 0;
    }

    let totalIntegrity = 0;
    let activeCount = 0;
    let containedCount = 0;

    for (const acc of this.agents.values()) {
      const tierKey = `T${Math.min(Math.max(acc.currentTier, 0), 7)}`;
      tierDist[tierKey] = (tierDist[tierKey] ?? 0) + 1;

      totalIntegrity += acc.integrityScore;

      const ageSec = (now - acc.lastActionTime.getTime()) / 1_000;
      if (ageSec <= this.config.activeThresholdSec) {
        activeCount++;
      }

      if (acc.currentScore < this.config.containedScoreThreshold) {
        containedCount++;
      }
    }

    const totalAgents = this.agents.size;
    return {
      totalAgents,
      tierDistribution: tierDist,
      avgIntegrity: totalAgents > 0 ? totalIntegrity / totalAgents : 1.0,
      activeCount,
      containedCount,
    };
  }

  /**
   * Get proof chain status.
   */
  getProofStatus(): ProofChainStatus {
    const now = Date.now();
    // Prune old timestamps outside the throughput window
    this.proofTimestamps = this.proofTimestamps.filter(
      (t) => now - t < this.throughputWindowMs,
    );

    const windowSec = this.throughputWindowMs / 1_000;
    const proofsPerSecond =
      this.proofTimestamps.length > 0
        ? this.proofTimestamps.length / windowSec
        : 0;

    return {
      totalProofs: this.totalProofs,
      proofsPerSecond,
      anchoredCount: this.anchoredCount,
      pendingCount: this.pendingCount,
      lastAnchorTime: this.lastAnchorTime,
    };
  }

  // -----------------------------------------------------------------------
  // Replay
  // -----------------------------------------------------------------------

  /**
   * Rebuild all read models from the event store (full replay).
   * Called automatically on start() but can also be invoked manually.
   */
  async replay(): Promise<void> {
    this.emit('projection:replay_started');

    // Reset state
    this.agents.clear();
    this.totalProofs = 0;
    this.anchoredCount = 0;
    this.pendingCount = 0;
    this.lastAnchorTime = null;
    this.proofTimestamps = [];

    let offset = 0;
    const batchSize = this.config.replayBatchSize;
    let hasMore = true;

    while (hasMore) {
      const options: EventQueryOptions = {
        limit: batchSize,
        offset,
        order: 'asc',
        includePayload: true,
      };

      const result = await this.store.query(undefined, options);

      for (const event of result.events) {
        this.projectEvent(event);
      }

      offset += result.events.length;
      hasMore = result.hasMore;
    }

    this.lastProcessedTime =
      this.totalProofs > 0
        ? (await this.store.getLatest())?.occurredAt ?? null
        : null;

    this.emit('projection:replay_completed', { eventsReplayed: this.totalProofs });

    // Persist after replay
    await this.persistIfConfigured();
  }

  // -----------------------------------------------------------------------
  // Event Projection
  // -----------------------------------------------------------------------

  /**
   * Project a single event into the read models.
   * Exposed publicly for testing and manual injection.
   */
  projectEvent(event: ProofEvent): void {
    this.totalProofs++;
    this.proofTimestamps.push(event.occurredAt.getTime());

    // Track anchoring
    if (event.signature) {
      this.anchoredCount++;
    } else {
      this.pendingCount++;
    }

    if (event.verifiedAt) {
      this.lastAnchorTime = event.verifiedAt;
    }

    // Agent-specific projection
    if (event.agentId) {
      this.projectAgentEvent(event.agentId, event);
    }
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  private projectAgentEvent(agentId: string, event: ProofEvent): void {
    let acc = this.agents.get(agentId);

    if (!acc) {
      acc = {
        agentId,
        currentTier: 0,
        currentScore: 0,
        lastActionTime: event.occurredAt,
        totalActions: 0,
        totalDenials: 0,
        integrityScore: 1.0,
      };
      this.agents.set(agentId, acc);
    }

    acc.totalActions++;
    acc.lastActionTime = event.occurredAt;

    // Extract trust state from payload
    const payload = event.payload as Record<string, unknown>;
    const payloadType = payload?.type as string | undefined;

    if (payloadType === 'trust_delta') {
      const newScore = payload.newScore as number | undefined;
      const newBand = payload.newBand as string | undefined;
      if (typeof newScore === 'number') {
        acc.currentScore = newScore;
      }
      if (typeof newBand === 'string') {
        // Extract tier number from band string (e.g., "T3_TRUSTED" -> 3)
        const tierMatch = newBand.match(/T(\d)/);
        if (tierMatch) {
          acc.currentTier = parseInt(tierMatch[1], 10);
        }
      }
    }

    if (payloadType === 'decision_made') {
      const permitted = payload.permitted as boolean | undefined;
      if (permitted === false) {
        acc.totalDenials++;
      }
      // Extract trust score from decision payload
      const trustScore = payload.trustScore as number | undefined;
      if (typeof trustScore === 'number') {
        acc.currentScore = trustScore;
      }
      // Extract trust band
      const trustBand = payload.trustBand as string | undefined;
      if (typeof trustBand === 'string') {
        const tierMatch = trustBand.match(/T(\d)/);
        if (tierMatch) {
          acc.currentTier = parseInt(tierMatch[1], 10);
        }
      }
    }

    // Incident detection degrades integrity
    if (payloadType === 'incident_detected') {
      acc.integrityScore = Math.max(0, acc.integrityScore - 0.1);
    }

    // Successful execution slightly restores integrity (capped at 1.0)
    if (payloadType === 'execution_completed') {
      acc.integrityScore = Math.min(1.0, acc.integrityScore + 0.01);
    }
  }

  private accumulatorToSummary(acc: AgentAccumulator): AgentTrustSummary {
    return {
      agentId: acc.agentId,
      currentTier: acc.currentTier,
      currentScore: acc.currentScore,
      lastActionTime: acc.lastActionTime,
      totalActions: acc.totalActions,
      denialRate: acc.totalActions > 0 ? acc.totalDenials / acc.totalActions : 0,
      integrityScore: acc.integrityScore,
    };
  }

  private async pollNewEvents(): Promise<void> {
    if (!this.running) return;

    const options: EventQueryOptions = {
      limit: this.config.replayBatchSize,
      order: 'asc',
      includePayload: true,
    };

    // Only fetch events after the last processed time
    const filter = this.lastProcessedTime
      ? { from: new Date(this.lastProcessedTime.getTime() + 1) }
      : undefined;

    const result = await this.store.query(filter, options);

    if (result.events.length === 0) return;

    for (const event of result.events) {
      this.projectEvent(event);
    }

    // Track the latest processed timestamp
    const lastEvent = result.events[result.events.length - 1];
    this.lastProcessedTime = lastEvent.occurredAt;

    this.emit('projection:updated', { newEvents: result.events.length });

    await this.persistIfConfigured();
  }

  private async persistIfConfigured(): Promise<void> {
    if (!this.config.persistCallback) return;

    try {
      await this.config.persistCallback({
        agents: new Map(
          Array.from(this.agents.entries()).map(([id, acc]) => [
            id,
            this.accumulatorToSummary(acc),
          ]),
        ),
        fleet: this.getFleetOverview(),
        chain: this.getProofStatus(),
      });
    } catch {
      // Persistence is best-effort; the in-memory model remains authoritative.
    }
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a CQRS trust read model projector.
 */
export function createTrustReadModelProjector(
  store: ProofEventStore,
  config?: Partial<TrustReadModelProjectorConfig>,
): TrustReadModelProjector {
  return new TrustReadModelProjector(store, config);
}
