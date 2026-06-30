/**
 * Proof Plane API Tests
 *
 * Covers logIntentReceived, logDecisionMade, logSignalRecorded,
 * logExecutionStarted/Completed, event type classification,
 * configuration options, shadow mode, multiple instances.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import {
  ProofEventType,
  TrustBand,
  ActionType,
  DataSensitivity,
  Reversibility,
  ObservationTier,
  type Intent,
  type Decision,
  type TrustProfile,
} from '@vorionsys/contracts';
import {
  ProofPlane,
  createProofPlane,
  createInMemoryEventStore,
} from '../src/index.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function createIntent(overrides: Partial<Intent> = {}): Intent {
  return {
    intentId: uuidv4(),
    agentId: uuidv4(),
    correlationId: uuidv4(),
    action: 'read-file',
    actionType: ActionType.READ,
    resourceScope: ['/data/test.txt'],
    dataSensitivity: DataSensitivity.INTERNAL,
    reversibility: Reversibility.REVERSIBLE,
    justification: 'Test',
    createdAt: new Date(),
    ...overrides,
  };
}

function createDecision(overrides: Partial<Decision> = {}): Decision {
  return {
    decisionId: uuidv4(),
    intentId: uuidv4(),
    agentId: uuidv4(),
    correlationId: uuidv4(),
    permitted: true,
    trustBand: TrustBand.T3_MONITORED,
    trustScore: 65,
    reasoning: ['test'],
    decidedAt: new Date(),
    expiresAt: new Date(Date.now() + 300000),
    latencyMs: 3,
    version: 1,
    ...overrides,
  };
}

function createProfile(overrides: Partial<TrustProfile> = {}): TrustProfile {
  return {
    profileId: uuidv4(),
    agentId: uuidv4(),
    rawScore: 50,
    adjustedScore: 50,
    band: TrustBand.T2_PROVISIONAL,
    observationTier: ObservationTier.GRAY_BOX,
    dimensionScores: { CT: 50, RL: 50, EC: 50, OT: 50, SB: 50, AC: 50, IQ: 50 },
    evidence: [],
    calculatedAt: new Date(),
    version: 1,
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Proof Plane API', () => {
  let pp: ProofPlane;

  beforeEach(() => {
    pp = createProofPlane({ signedBy: 'api-test' });
  });

  // ── logIntentReceived ─────────────────────────────────────────────────

  describe('logIntentReceived', () => {
    it('returns EmitResult with event', async () => {
      const r = await pp.logIntentReceived(createIntent());
      expect(r.event).toBeDefined();
      expect(r.event.eventId).toBeTruthy();
    });

    it('event has correct type', async () => {
      const r = await pp.logIntentReceived(createIntent());
      expect(r.event.eventType).toBe(ProofEventType.INTENT_RECEIVED);
    });

    it('event payload contains intentId', async () => {
      const intent = createIntent({ intentId: 'intent-123' });
      const r = await pp.logIntentReceived(intent);
      expect((r.event.payload as { intentId: string }).intentId).toBe('intent-123');
    });

    it('event hash is 64-char hex', async () => {
      const r = await pp.logIntentReceived(createIntent());
      expect(r.event.eventHash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  // ── logDecisionMade ───────────────────────────────────────────────────

  describe('logDecisionMade', () => {
    it('returns EmitResult with event', async () => {
      const r = await pp.logDecisionMade(createDecision());
      expect(r.event).toBeDefined();
    });

    it('event type is DECISION_MADE', async () => {
      const r = await pp.logDecisionMade(createDecision());
      expect(r.event.eventType).toBe(ProofEventType.DECISION_MADE);
    });

    it('payload contains permitted flag', async () => {
      const r = await pp.logDecisionMade(createDecision({ permitted: false }));
      expect((r.event.payload as { permitted: boolean }).permitted).toBe(false);
    });
  });

  // ── logTrustDelta (signal recorded) ───────────────────────────────────

  describe('logTrustDelta (signal recorded)', () => {
    it('returns EmitResult', async () => {
      const agentId = uuidv4();
      const r = await pp.logTrustDelta(
        agentId,
        createProfile({ agentId, adjustedScore: 40, band: TrustBand.T1_QUARANTINED }),
        createProfile({ agentId, adjustedScore: 55, band: TrustBand.T2_PROVISIONAL }),
        'improvement',
      );
      expect(r.event.eventType).toBe(ProofEventType.TRUST_DELTA);
    });

    it('payload has previous and new scores', async () => {
      const agentId = uuidv4();
      const r = await pp.logTrustDelta(
        agentId,
        createProfile({ agentId, adjustedScore: 30 }),
        createProfile({ agentId, adjustedScore: 70 }),
        'big jump',
      );
      const p = r.event.payload as { previousScore: number; newScore: number };
      expect(p.previousScore).toBe(30);
      expect(p.newScore).toBe(70);
    });
  });

  // ── logExecutionStarted / logExecutionCompleted ───────────────────────

  describe('logExecutionStarted', () => {
    it('creates EXECUTION_STARTED event', async () => {
      const r = await pp.logExecutionStarted('e1', 'a1', 'd1', 'adapter', 'agent', 'corr');
      expect(r.event.eventType).toBe(ProofEventType.EXECUTION_STARTED);
      expect((r.event.payload as { executionId: string }).executionId).toBe('e1');
    });
  });

  describe('logExecutionCompleted', () => {
    it('creates EXECUTION_COMPLETED event with success', async () => {
      const r = await pp.logExecutionCompleted('e1', 'a1', 150, 'hash', 'agent', 'corr');
      expect(r.event.eventType).toBe(ProofEventType.EXECUTION_COMPLETED);
      expect((r.event.payload as { status: string }).status).toBe('success');
    });

    it('supports partial status', async () => {
      const r = await pp.logExecutionCompleted('e1', 'a1', 100, 'hash', 'agent', 'corr', 'partial');
      expect((r.event.payload as { status: string }).status).toBe('partial');
    });
  });

  describe('logExecutionFailed', () => {
    it('creates EXECUTION_FAILED event', async () => {
      const r = await pp.logExecutionFailed('e1', 'a1', 'timeout', 5000, true, 'agent', 'corr');
      expect(r.event.eventType).toBe(ProofEventType.EXECUTION_FAILED);
      expect((r.event.payload as { retryable: boolean }).retryable).toBe(true);
    });
  });

  // ── Event type classification ─────────────────────────────────────────

  describe('event type classification', () => {
    it('each log method produces the correct event type', async () => {
      const types: Array<[string, ProofEventType]> = [];

      const r1 = await pp.logIntentReceived(createIntent());
      types.push([r1.event.eventType, ProofEventType.INTENT_RECEIVED]);

      const r2 = await pp.logDecisionMade(createDecision());
      types.push([r2.event.eventType, ProofEventType.DECISION_MADE]);

      const r3 = await pp.logExecutionStarted('e', 'a', 'd', 'ad', 'ag', 'c');
      types.push([r3.event.eventType, ProofEventType.EXECUTION_STARTED]);

      for (const [actual, expected] of types) {
        expect(actual).toBe(expected);
      }
    });

    it('logEvent accepts any ProofEventType', async () => {
      const r = await pp.logEvent(
        ProofEventType.INCIDENT_DETECTED,
        uuidv4(),
        { type: 'incident_detected', incidentId: 'inc-1', severity: 'high' as const, description: 'breach', affectedResources: ['/db'] },
      );
      expect(r.event.eventType).toBe(ProofEventType.INCIDENT_DETECTED);
    });
  });

  // ── Configuration options ─────────────────────────────────────────────

  describe('configuration options', () => {
    it('custom signedBy appears on events', async () => {
      const pp2 = createProofPlane({ signedBy: 'my-custom-signer' });
      const r = await pp2.logIntentReceived(createIntent());
      expect(r.event.signedBy).toBe('my-custom-signer');
    });

    it('default signedBy is "orion-proof-plane"', async () => {
      const pp2 = createProofPlane();
      const r = await pp2.logIntentReceived(createIntent());
      expect(r.event.signedBy).toBe('orion-proof-plane');
    });

    it('custom store is used', async () => {
      const store = createInMemoryEventStore();
      const pp2 = createProofPlane({ store });
      await pp2.logIntentReceived(createIntent());
      expect(await store.count()).toBe(1);
    });

    it('getStore returns the configured store', () => {
      const store = createInMemoryEventStore();
      const pp2 = createProofPlane({ store });
      expect(pp2.getStore()).toBe(store);
    });

    it('environment defaults to production', () => {
      const pp2 = createProofPlane();
      expect(pp2.getEnvironment()).toBe('production');
    });

    it('environment can be set to testnet', () => {
      const pp2 = createProofPlane({ environment: 'testnet' });
      expect(pp2.getEnvironment()).toBe('testnet');
    });
  });

  // ── Shadow mode ───────────────────────────────────────────────────────

  describe('shadow mode', () => {
    it('default is not shadow mode', () => {
      expect(pp.isShadowMode()).toBe(false);
      expect(pp.getShadowMode()).toBe('production');
    });

    it('shadow mode tags events', async () => {
      const pp2 = createProofPlane({ shadowMode: 'shadow' });
      expect(pp2.isShadowMode()).toBe(true);
      expect(pp2.getShadowMode()).toBe('shadow');

      const r = await pp2.logIntentReceived(createIntent());
      expect(r.event.shadowMode).toBe('shadow');
    });

    it('testnet mode tags events', async () => {
      const pp2 = createProofPlane({ shadowMode: 'testnet' });
      expect(pp2.isShadowMode()).toBe(true);
      const r = await pp2.logIntentReceived(createIntent());
      expect(r.event.shadowMode).toBe('testnet');
    });

    it('production mode does not set shadowMode on events', async () => {
      const r = await pp.logIntentReceived(createIntent());
      expect(r.event.shadowMode).toBeUndefined();
    });
  });

  // ── Multiple instances with separate stores ───────────────────────────

  describe('multiple instances with separate stores', () => {
    it('two instances have independent event counts', async () => {
      const pp1 = createProofPlane({ signedBy: 'pp1' });
      const pp2 = createProofPlane({ signedBy: 'pp2' });

      await pp1.logIntentReceived(createIntent());
      await pp1.logIntentReceived(createIntent());
      await pp2.logIntentReceived(createIntent());

      expect(await pp1.getEventCount()).toBe(2);
      expect(await pp2.getEventCount()).toBe(1);
    });

    it('two instances sharing a store see the same events', async () => {
      const store = createInMemoryEventStore();
      const pp1 = createProofPlane({ store, signedBy: 'pp1' });
      const pp2 = createProofPlane({ store, signedBy: 'pp2' });

      await pp1.logIntentReceived(createIntent());
      await pp2.logIntentReceived(createIntent());

      expect(await pp1.getEventCount()).toBe(2);
      expect(await pp2.getEventCount()).toBe(2);
    });

    it('clearing one instance does not affect another', async () => {
      const pp1 = createProofPlane();
      const pp2 = createProofPlane();

      await pp1.logIntentReceived(createIntent());
      await pp2.logIntentReceived(createIntent());

      await pp1.clear();
      expect(await pp1.getEventCount()).toBe(0);
      expect(await pp2.getEventCount()).toBe(1);
    });
  });
});
