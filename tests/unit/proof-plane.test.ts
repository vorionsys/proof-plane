/**
 * Proof Plane Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import {
  ProofEventType,
  TrustBand,
  ActionType,
  DataSensitivity,
  Reversibility,
  type Intent,
  type Decision,
  type TrustProfile,
  ObservationTier,
} from '@vorionsys/contracts';
import {
  ProofPlane,
  createProofPlane,
  createProofPlaneLogger,
} from '../../src/index.js';

describe('ProofPlane', () => {
  let proofPlane: ProofPlane;

  beforeEach(() => {
    proofPlane = createProofPlane({ signedBy: 'test-service', enableSignatures: false });
  });

  describe('logIntentReceived', () => {
    it('should log an intent received event', async () => {
      const intent = createIntent();
      const result = await proofPlane.logIntentReceived(intent);

      expect(result.event).toBeDefined();
      expect(result.event.eventType).toBe(ProofEventType.INTENT_RECEIVED);
      expect(result.event.correlationId).toBe(intent.correlationId);
      expect(result.event.agentId).toBe(intent.agentId);
      expect(result.event.payload.type).toBe('intent_received');
    });

    it('should create genesis event with null previousHash', async () => {
      const intent = createIntent();
      const result = await proofPlane.logIntentReceived(intent);

      expect(result.isGenesis).toBe(true);
      expect(result.previousHash).toBeNull();
      expect(result.event.previousHash).toBeNull();
    });

    it('should chain subsequent events', async () => {
      const intent1 = createIntent();
      const intent2 = createIntent();

      const result1 = await proofPlane.logIntentReceived(intent1);
      const result2 = await proofPlane.logIntentReceived(intent2);

      expect(result1.isGenesis).toBe(true);
      expect(result2.isGenesis).toBe(false);
      expect(result2.previousHash).toBe(result1.event.eventHash);
    });
  });

  describe('logDecisionMade', () => {
    it('should log a decision made event', async () => {
      const decision = createDecision();
      const result = await proofPlane.logDecisionMade(decision);

      expect(result.event.eventType).toBe(ProofEventType.DECISION_MADE);
      expect(result.event.payload.type).toBe('decision_made');

      const payload = result.event.payload as { permitted: boolean; trustBand: string };
      expect(payload.permitted).toBe(decision.permitted);
      expect(payload.trustBand).toBe(TrustBand[decision.trustBand]);
    });
  });

  describe('logTrustDelta', () => {
    it('should log a trust delta event', async () => {
      const agentId = uuidv4();
      const prevProfile = createProfile({ agentId, adjustedScore: 450, band: TrustBand.T2_PROVISIONAL });
      const newProfile = createProfile({ agentId, adjustedScore: 600, band: TrustBand.T3_MONITORED });

      const result = await proofPlane.logTrustDelta(
        agentId,
        prevProfile,
        newProfile,
        'Positive behavioral evidence'
      );

      expect(result.event.eventType).toBe(ProofEventType.TRUST_DELTA);
      expect(result.event.agentId).toBe(agentId);

      const payload = result.event.payload as {
        previousScore: number;
        newScore: number;
        previousBand: string;
        newBand: string;
      };
      expect(payload.previousScore).toBe(450);
      expect(payload.newScore).toBe(600);
      expect(payload.previousBand).toBe('T2_PROVISIONAL');
      expect(payload.newBand).toBe('T3_MONITORED');
    });
  });

  describe('logExecutionStarted', () => {
    it('should log execution started event', async () => {
      const result = await proofPlane.logExecutionStarted(
        uuidv4(), // executionId
        uuidv4(), // actionId
        uuidv4(), // decisionId
        'file-adapter',
        uuidv4(), // agentId
        uuidv4()  // correlationId
      );

      expect(result.event.eventType).toBe(ProofEventType.EXECUTION_STARTED);
      expect(result.event.payload.type).toBe('execution_started');
    });
  });

  describe('logExecutionCompleted', () => {
    it('should log execution completed event', async () => {
      const result = await proofPlane.logExecutionCompleted(
        uuidv4(),
        uuidv4(),
        150, // durationMs
        'sha256-output-hash',
        uuidv4(),
        uuidv4()
      );

      expect(result.event.eventType).toBe(ProofEventType.EXECUTION_COMPLETED);
      const payload = result.event.payload as { durationMs: number; status: string };
      expect(payload.durationMs).toBe(150);
      expect(payload.status).toBe('success');
    });
  });

  describe('logExecutionFailed', () => {
    it('should log execution failed event', async () => {
      const result = await proofPlane.logExecutionFailed(
        uuidv4(),
        uuidv4(),
        'Permission denied',
        100,
        true, // retryable
        uuidv4(),
        uuidv4()
      );

      expect(result.event.eventType).toBe(ProofEventType.EXECUTION_FAILED);
      const payload = result.event.payload as { error: string; retryable: boolean };
      expect(payload.error).toBe('Permission denied');
      expect(payload.retryable).toBe(true);
    });
  });

  describe('getTrace', () => {
    it('should return all events for a correlation ID', async () => {
      const correlationId = uuidv4();
      const intent = createIntent({ correlationId });
      const decision = createDecision({ correlationId });

      await proofPlane.logIntentReceived(intent);
      await proofPlane.logDecisionMade(decision);
      await proofPlane.logIntentReceived(createIntent()); // Different correlation

      const trace = await proofPlane.getTrace(correlationId);
      expect(trace).toHaveLength(2);
      expect(trace[0].eventType).toBe(ProofEventType.INTENT_RECEIVED);
      expect(trace[1].eventType).toBe(ProofEventType.DECISION_MADE);
    });
  });

  describe('getAgentHistory', () => {
    it('should return all events for an agent', async () => {
      const agentId = uuidv4();
      const intent1 = createIntent({ agentId });
      const intent2 = createIntent({ agentId });
      const intent3 = createIntent(); // Different agent

      await proofPlane.logIntentReceived(intent1);
      await proofPlane.logIntentReceived(intent2);
      await proofPlane.logIntentReceived(intent3);

      const history = await proofPlane.getAgentHistory(agentId);
      expect(history).toHaveLength(2);
    });
  });

  describe('verifyChain', () => {
    it('should verify empty chain', async () => {
      const result = await proofPlane.verifyChain();
      expect(result.valid).toBe(true);
      expect(result.totalEvents).toBe(0);
    });

    it('should verify chain with events', async () => {
      await proofPlane.logIntentReceived(createIntent());
      await proofPlane.logDecisionMade(createDecision());
      await proofPlane.logIntentReceived(createIntent());

      const result = await proofPlane.verifyChain();
      expect(result.valid).toBe(true);
      expect(result.totalEvents).toBe(3);
      expect(result.verifiedCount).toBe(3);
    });
  });

  describe('subscribe', () => {
    it('should call listener on new events', async () => {
      const events: string[] = [];
      const unsubscribe = proofPlane.subscribe((event) => {
        events.push(event.eventId);
      });

      await proofPlane.logIntentReceived(createIntent());
      await proofPlane.logDecisionMade(createDecision());

      expect(events).toHaveLength(2);

      unsubscribe();

      await proofPlane.logIntentReceived(createIntent());
      expect(events).toHaveLength(2); // No new events after unsubscribe
    });
  });

  describe('subscribeToType', () => {
    it('should only call listener for specific event type', async () => {
      const events: string[] = [];
      proofPlane.subscribeToType(ProofEventType.DECISION_MADE, (event) => {
        events.push(event.eventId);
      });

      await proofPlane.logIntentReceived(createIntent());
      await proofPlane.logDecisionMade(createDecision());
      await proofPlane.logIntentReceived(createIntent());

      expect(events).toHaveLength(1);
    });
  });

  describe('getStats', () => {
    it('should return event statistics', async () => {
      await proofPlane.logIntentReceived(createIntent());
      await proofPlane.logDecisionMade(createDecision());
      await proofPlane.logIntentReceived(createIntent());

      const stats = await proofPlane.getStats();
      expect(stats.totalEvents).toBe(3);
      expect(stats.byType[ProofEventType.INTENT_RECEIVED]).toBe(2);
      expect(stats.byType[ProofEventType.DECISION_MADE]).toBe(1);
    });
  });
});

describe('ProofPlaneLogger', () => {
  it('should log intent and decision', async () => {
    const proofPlane = createProofPlane();
    const logger = createProofPlaneLogger({
      proofPlane,
      logIntentReceived: true,
      logDecisionMade: true,
    });

    const intent = createIntent();
    const decision = createDecision({ correlationId: intent.correlationId });

    await logger.logDecision(decision, intent);

    const count = await proofPlane.getEventCount();
    expect(count).toBe(2);
  });

  it('should respect configuration flags', async () => {
    const proofPlane = createProofPlane();
    const logger = createProofPlaneLogger({
      proofPlane,
      logIntentReceived: false,
      logDecisionMade: true,
    });

    const intent = createIntent();
    const decision = createDecision();

    await logger.logDecision(decision, intent);

    const count = await proofPlane.getEventCount();
    expect(count).toBe(1);

    const events = await proofPlane.queryEvents();
    expect(events.events[0].eventType).toBe(ProofEventType.DECISION_MADE);
  });
});

describe('ProofPlane with Hooks', () => {
  it('should fire EVENT_EMITTED hook when event is logged', async () => {
    const hookCalls: Array<{ correlationId: string; eventType: string }> = [];

    // Create a mock hook manager
    const mockHookManager = {
      executeEventEmitted: async (ctx: { correlationId: string; event: { eventType: string } }) => {
        hookCalls.push({
          correlationId: ctx.correlationId,
          eventType: ctx.event.eventType,
        });
        return { aborted: false };
      },
    };

    const proofPlane = createProofPlane({
      hookManager: mockHookManager,
    });

    const intent = createIntent();
    await proofPlane.logIntentReceived(intent);

    // Wait a tick for async hook to fire
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(hookCalls).toHaveLength(1);
    expect(hookCalls[0]!.correlationId).toBe(intent.correlationId);
    expect(hookCalls[0]!.eventType).toBe(ProofEventType.INTENT_RECEIVED);
  });

  it('should fire hook for each event emitted', async () => {
    const hookCalls: string[] = [];

    const mockHookManager = {
      executeEventEmitted: async (ctx: { event: { eventType: string } }) => {
        hookCalls.push(ctx.event.eventType);
        return { aborted: false };
      },
    };

    const proofPlane = createProofPlane({ hookManager: mockHookManager });

    const intent = createIntent();
    const decision = createDecision({ correlationId: intent.correlationId });

    await proofPlane.logIntentReceived(intent);
    await proofPlane.logDecisionMade(decision);

    // Wait for async hooks
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(hookCalls).toHaveLength(2);
    expect(hookCalls).toContain(ProofEventType.INTENT_RECEIVED);
    expect(hookCalls).toContain(ProofEventType.DECISION_MADE);
  });

  it('should not fire hooks when disabled', async () => {
    const hookCalls: string[] = [];

    const mockHookManager = {
      executeEventEmitted: async () => {
        hookCalls.push('called');
        return { aborted: false };
      },
    };

    const proofPlane = createProofPlane({
      hookManager: mockHookManager,
      enableHooks: false,
    });

    await proofPlane.logIntentReceived(createIntent());

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(hookCalls).toHaveLength(0);
  });

  it('should enable hooks by default when hookManager is provided', () => {
    const mockHookManager = {
      executeEventEmitted: async () => ({ aborted: false }),
    };

    const proofPlane = createProofPlane({ hookManager: mockHookManager });

    expect(proofPlane.isHooksEnabled()).toBe(true);
    expect(proofPlane.getHookManager()).toBe(mockHookManager);
  });

  it('should not enable hooks when no hookManager is provided', () => {
    const proofPlane = createProofPlane();

    expect(proofPlane.isHooksEnabled()).toBe(false);
    expect(proofPlane.getHookManager()).toBeUndefined();
  });

  it('should pass full event to hook', async () => {
    let receivedEvent: Record<string, unknown> | null = null;

    const mockHookManager = {
      executeEventEmitted: async (ctx: { event: Record<string, unknown> }) => {
        receivedEvent = ctx.event;
        return { aborted: false };
      },
    };

    const proofPlane = createProofPlane({ hookManager: mockHookManager });

    const intent = createIntent();
    await proofPlane.logIntentReceived(intent);

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(receivedEvent).not.toBeNull();
    expect(receivedEvent!.eventId).toBeDefined();
    expect(receivedEvent!.eventType).toBe(ProofEventType.INTENT_RECEIVED);
    expect(receivedEvent!.correlationId).toBe(intent.correlationId);
    expect(receivedEvent!.agentId).toBe(intent.agentId);
    expect(receivedEvent!.payload).toBeDefined();
    expect(receivedEvent!.eventHash).toBeDefined();
  });
});

// Test helpers

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
    justification: 'Test intent',
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
    trustBand: TrustBand.T2_PROVISIONAL,
    trustScore: 55,
    reasoning: ['Test decision'],
    decidedAt: new Date(),
    expiresAt: new Date(Date.now() + 300000),
    latencyMs: 5,
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
    dimensionScores: {
      CT: 50,
      RL: 50,
      EC: 50,
      OT: 50,
      SB: 50,
      AC: 50,
      IQ: 50,
    },
    evidence: [],
    calculatedAt: new Date(),
    version: 1,
    ...overrides,
  };
}
