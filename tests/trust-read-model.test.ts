import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  TrustReadModelProjector,
  createTrustReadModelProjector,
  type AgentTrustSummary,
  type FleetOverview,
  type ProofChainStatus,
} from '../src/projections/trust-read-model.js';
import type { ProofEvent, ProofEventType } from '@vorionsys/contracts';
import type {
  ProofEventStore,
  EventQueryResult,
  EventStats,
} from '../src/events/event-store.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let eventSeq = 0;

function makeEvent(overrides: Partial<ProofEvent> = {}): ProofEvent {
  eventSeq++;
  return {
    eventId: `evt-${eventSeq}`,
    eventType: 'execution_completed' as ProofEventType,
    correlationId: `corr-${eventSeq}`,
    agentId: overrides.agentId ?? 'agent-1',
    payload: { type: 'execution_completed' } as any,
    previousHash: null,
    eventHash: `hash-${eventSeq}`,
    occurredAt: overrides.occurredAt ?? new Date(),
    recordedAt: new Date(),
    ...(overrides as any),
  };
}

function makeTrustDeltaEvent(
  agentId: string,
  newScore: number,
  newBand: string,
): ProofEvent {
  return makeEvent({
    agentId,
    eventType: 'trust_delta' as ProofEventType,
    payload: {
      type: 'trust_delta',
      deltaId: `delta-${eventSeq + 1}`,
      previousScore: 0,
      newScore,
      previousBand: 'T0_SANDBOX',
      newBand,
      reason: 'test',
    } as any,
  });
}

function makeDecisionEvent(
  agentId: string,
  permitted: boolean,
  trustScore: number,
  trustBand: string,
): ProofEvent {
  return makeEvent({
    agentId,
    eventType: 'decision_made' as ProofEventType,
    payload: {
      type: 'decision_made',
      decisionId: `dec-${eventSeq + 1}`,
      intentId: `int-${eventSeq + 1}`,
      permitted,
      trustBand,
      trustScore,
      reasoning: ['test'],
    } as any,
  });
}

function makeIncidentEvent(agentId: string): ProofEvent {
  return makeEvent({
    agentId,
    eventType: 'incident_detected' as ProofEventType,
    payload: {
      type: 'incident_detected',
    } as any,
  });
}

/** Minimal in-memory store mock for projection testing. */
function createMockStore(events: ProofEvent[]): ProofEventStore {
  return {
    append: vi.fn(),
    get: vi.fn(),
    getLatest: vi.fn(async () => events.length > 0 ? events[events.length - 1] : null),
    getLatestHash: vi.fn(),
    query: vi.fn(async (filter?: any, options?: any) => {
      let filtered = [...events];
      if (filter?.from) {
        filtered = filtered.filter((e) => e.occurredAt >= filter.from);
      }
      const offset = options?.offset ?? 0;
      const limit = options?.limit ?? 100;
      const slice = filtered.slice(offset, offset + limit);
      return {
        events: slice,
        totalCount: filtered.length,
        hasMore: offset + limit < filtered.length,
      } as EventQueryResult;
    }),
    getByCorrelationId: vi.fn(),
    getByAgentId: vi.fn(),
    getByTimeRange: vi.fn(),
    getByType: vi.fn(),
    getSummaries: vi.fn(),
    getChain: vi.fn(),
    count: vi.fn(async () => events.length),
    getStats: vi.fn(async (): Promise<EventStats> => ({
      totalEvents: events.length,
      byType: {},
      byAgent: {},
    })),
    exists: vi.fn(),
    clear: vi.fn(),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TrustReadModelProjector — CQRS Read Models', () => {
  beforeEach(() => {
    eventSeq = 0;
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // -----------------------------------------------------------------------
  // Factory
  // -----------------------------------------------------------------------

  describe('Factory', () => {
    it('TRM-1: createTrustReadModelProjector returns instance', () => {
      const store = createMockStore([]);
      const projector = createTrustReadModelProjector(store);
      expect(projector).toBeInstanceOf(TrustReadModelProjector);
    });
  });

  // -----------------------------------------------------------------------
  // Single event projection
  // -----------------------------------------------------------------------

  describe('Event projection', () => {
    it('TRM-2: projects a single event into agent summary', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      const event = makeEvent({ agentId: 'agent-a' });
      projector.projectEvent(event);

      const summary = projector.getAgentSummary('agent-a');
      expect(summary).not.toBeNull();
      expect(summary!.agentId).toBe('agent-a');
      expect(summary!.totalActions).toBe(1);
    });

    it('TRM-3: trust_delta event updates score and tier', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      projector.projectEvent(
        makeTrustDeltaEvent('agent-a', 750, 'T5_ESTABLISHED'),
      );

      const summary = projector.getAgentSummary('agent-a');
      expect(summary!.currentScore).toBe(750);
      expect(summary!.currentTier).toBe(5);
    });

    it('TRM-4: decision_made denied event increments denial count', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      projector.projectEvent(
        makeDecisionEvent('agent-a', true, 500, 'T3_TRUSTED'),
      );
      projector.projectEvent(
        makeDecisionEvent('agent-a', false, 500, 'T3_TRUSTED'),
      );
      projector.projectEvent(
        makeDecisionEvent('agent-a', false, 500, 'T3_TRUSTED'),
      );

      const summary = projector.getAgentSummary('agent-a');
      expect(summary!.totalActions).toBe(3);
      expect(summary!.denialRate).toBeCloseTo(2 / 3);
    });

    it('TRM-5: incident_detected degrades integrity', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      projector.projectEvent(makeEvent({ agentId: 'agent-a' }));
      expect(projector.getAgentSummary('agent-a')!.integrityScore).toBe(1.0);

      projector.projectEvent(makeIncidentEvent('agent-a'));
      expect(projector.getAgentSummary('agent-a')!.integrityScore).toBeCloseTo(0.9);
    });

    it('TRM-6: execution_completed slowly restores integrity', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      // Degrade first
      projector.projectEvent(makeIncidentEvent('agent-a'));
      expect(projector.getAgentSummary('agent-a')!.integrityScore).toBeCloseTo(0.9);

      // Restore
      projector.projectEvent(makeEvent({
        agentId: 'agent-a',
        payload: { type: 'execution_completed' } as any,
      }));
      expect(projector.getAgentSummary('agent-a')!.integrityScore).toBeCloseTo(0.91);
    });

    it('TRM-7: unknown agent returns null', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);
      expect(projector.getAgentSummary('nonexistent')).toBeNull();
    });

    it('TRM-8: events without agentId still increment proof count', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      projector.projectEvent(makeEvent({ agentId: undefined }));

      const status = projector.getProofStatus();
      expect(status.totalProofs).toBe(1);
      expect(projector.getAgentSummary('agent-1')).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // Fleet overview
  // -----------------------------------------------------------------------

  describe('Fleet overview', () => {
 t store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      projector.projectEvent(
        makeTrustDeltaEvent('a', 750, 'T5_ESTABLISHED'),
      );
      projector.projectEvent(
        makeTrustDeltaEvent('b', 300, 'T2_PROBATION'),
      );
      projector.projectEvent(
        makeTrustDeltaEvent('c', 100, 'T0_SANDBOX'),
      );

      const overview = projector.getFleetOverview();
      expect(overview.totalAgents).toBe(3);
      expect(overview.tierDistribution['T5']).toBe(1);
      expect(overview.tierDistribution['T2']).toBe(1);
      expect(overview.tierDistribution['T0']).toBe(1);
    });

    it('TRM-10: avgIntegrity reflects agent integrity scores', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      projector.projectEvent(makeEvent({ agentId: 'a' }));
      projector.projectEvent(makeIncidentEvent('b'));

      const overview = projector.getFleetOverview();
      // a=1.0, b=0.9 -> avg=0.95
      expect(overview.avgIntegrity).toBeCloseTo(0.95);
    });

    it('TRM-11: containedCount counts low-score agents', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store, {
        containedScoreThreshold: 200,
      });

      projector.projectEvent(
        makeTrustDeltaEvent('a', 750, 'T5_ESTABLISHED'),
      );
      projector.projectEvent(
        makeTrustDeltaEvent('b', 100, 'T0_SANDBOX'),
      );

      const overview = projector.getFleetOverview();
      expect(overview.containedCount).toBe(1);
    });

    it('TRM-12: activeCount reflects recently active agents', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store, {
        activeThresholdSec: 60,
      });

      const now = new Date();
      projector.projectEvent(
        makeEvent({ agentId: 'a', occurredAt: now }),
      );
      projector.projectEvent(
        makeEvent({
          agentId: 'b',
          occurredAt: new Date(now.getTime() - 120_000), // 2 min ago
        }),
      );

      const overview = projector.getFleetOverview();
      expect(overview.activeCount).toBe(1);
    });

    it('TRM-13: empty fleet returns zeroed overview', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      const overview = projector.getFleetOverview();
      expect(overview.totalAgents).toBe(0);
      expect(overview.avgIntegrity).toBe(1.0);
      expect(overview.activeCount).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // Proof chain status
  // -----------------------------------------------------------------------

  describe('Proof chain status', () => {
    it('TRM-14: tracks total proof count', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      projector.projectEvent(makeEvent());
      projector.projectEvent(makeEvent());
      projector.projectEvent(makeEvent());

      expect(projector.getProofStatus().totalProofs).toBe(3);
    });

    it('TRM-15: tracks anchored vs pending counts', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      projector.projectEvent(makeEvent({
        signature: 'sig-1',
      }));
      projector.projectEvent(makeEvent({
        signature: undefined,
      }));

      const status = projector.getProofStatus();
      expect(status.anchoredCount).toBe(1);
      expect(status.pendingCount).toBe(1);
    });

    it('TRM-16: proofsPerSecond based on throughput window', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      const now = Date.now();
      // Inject 10 events at "now"
      for (let i = 0; i < 10; i++) {
        projector.projectEvent(
          makeEvent({ occurredAt: new Date(now) }),
        );
      }

      const status = projector.getProofStatus();
      // 10 events in 60s window = ~0.167/sec
      expect(status.proofsPerSecond).toBeCloseTo(10 / 60, 1);
    });
  });

  // -----------------------------------------------------------------------
  // Replay from store
  // -----------------------------------------------------------------------

  describe('Replay from store', () => {
    it('TRM-17: rebuilds read models from event store', async () => {
      const events = [
        makeTrustDeltaEvent('agent-a', 500, 'T3_TRUSTED'),
        makeDecisionEvent('agent-a', true, 500, 'T3_TRUSTED'),
        makeDecisionEvent('agent-b', false, 200, 'T1_QUARANTINE'),
      ];
      const store = createMockStore(events);
      const projector = new TrustReadModelProjector(store, {
        replayBatchSize: 2, // test batching
      });

      await projector.replay();

      expect(projector.getAgentSummary('agent-a')!.totalActions).toBe(2);
      expect(projector.getAgentSummary('agent-b')!.denialRate).toBe(1.0);
      expect(projector.getProofStatus().totalProofs).toBe(3);
    });

    it('TRM-18: replay emits started and completed events', async () => {
      const store = createMockStore([makeEvent()]);
      const projector = new TrustReadModelProjector(store);

      const events: string[] = [];
      projector.on('projection:replay_started', () => events.push('started'));
      projector.on('projection:replay_completed', () => events.push('completed'));

      await projector.replay();

      expect(events).toEqual(['started', 'completed']);
    });

    it('TRM-19: replay clears previous state', async () => {
      const events = [makeEvent({ agentId: 'a' })];
      const store = createMockStore(events);
      const projector = new TrustReadModelProjector(store);

      // First replay
      await projector.replay();
      expect(projector.getAgentSummary('a')!.totalActions).toBe(1);

      // Second replay should reset
      await projector.replay();
      expect(projector.getAgentSummary('a')!.totalActions).toBe(1);
    });

    it('TRM-20: replay with empty store produces empty models', async () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      await projector.replay();

      expect(projector.getFleetOverview().totalAgents).toBe(0);
      expect(projector.getProofStatus().totalProofs).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // Start / Stop lifecycle
  // -----------------------------------------------------------------------

  describe('Lifecycle', () => {
    it('TRM-21: start begins polling', async () => {
      const events = [makeEvent({ agentId: 'a' })];
      const store = createMockStore(events);
      const projector = new TrustReadModelProjector(store, {
        pollIntervalMs: 100,
      });

      await projector.start();
      expect(projector.isRunning()).toBe(true);

      projector.stop();
      expect(projector.isRunning()).toBe(false);
    });

    it('TRM-22: double start is a no-op', async () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      await projector.start();
      await projector.start(); // should not throw
      expect(projector.isRunning()).toBe(true);

      projector.stop();
    });

    it('TRM-23: stop halts polling', async () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store, {
        pollIntervalMs: 100,
      });

      await projector.start();
      projector.stop();

      const callCount = (store.query as ReturnType<typeof vi.fn>).mock.calls.length;
      vi.advanceTimersByTime(500);
      // No additional calls after stop
      expect((store.query as ReturnType<typeof vi.fn>).mock.calls.length).toBe(callCount);
    });
  });

  // -----------------------------------------------------------------------
  // Persistence callback
  // -----------------------------------------------------------------------

  describe('Persistence callback', () => {
    it('TRM-24: calls persistCallback after replay', async () => {
      const persistCallback = vi.fn(async () => {});
      const events = [makeEvent({ agentId: 'a' })];
      const store = createMockStore(events);
      const projector = new TrustReadModelProjector(store, {
        persistCallback,
      });

      await projector.replay();

      expect(persistCallback).toHaveBeenCalledTimes(1);
      const args = persistCallback.mock.calls[0][0];
      expect(args.agents).toBeInstanceOf(Map);
      expect(args.fleet.totalAgents).toBe(1);
      expect(args.chain.totalProofs).toBe(1);
    });
  });

  // -----------------------------------------------------------------------
  // getAllAgentSummaries
  // -----------------------------------------------------------------------

  describe('Bulk queries', () => {
    it('TRM-25: getAllAgentSummaries returns all agents', () => {
      const store = createMockStore([]);
      const projector = new TrustReadModelProjector(store);

      projector.projectEvent(makeEvent({ agentId: 'a' }));
      projector.projectEvent(makeEvent({ agentId: 'b' }));
      projector.projectEvent(makeEvent({ agentId: 'c' }));

      const summaries = projector.getAllAgentSummaries();
      expect(summaries.length).toBe(3);
      const ids = summaries.map((s) => s.agentId).sort();
      expect(ids).toEqual(['a', 'b', 'c']);
    });
  });
});
