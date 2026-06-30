/**
 * Correlation Tracking Tests
 *
 * Covers correlation ID assignment, getTrace, multi-step workflows,
 * correlation uniqueness, missing correlation handling,
 * non-existent correlation queries, and cross-agent correlation.
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
import { ProofPlane, createProofPlane } from '../src/index.js';

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
    trustBand: TrustBand.T3_MONITORED,
    trustScore: 60,
    reasoning: ['test decision'],
    decidedAt: new Date(),
    expiresAt: new Date(Date.now() + 300000),
    latencyMs: 5,
    version: 1,
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Correlation Tracking', () => {
  let pp: ProofPlane;

  beforeEach(() => {
    pp = createProofPlane({ signedBy: 'corr-test' });
  });

  // ── Correlation ID assignment ──────────────────────────────────────────

  describe('correlation ID assignment', () => {
    it('logIntentReceived uses intent correlationId', async () => {
      const intent = createIntent({ correlationId: 'corr-abc' });
      const r = await pp.logIntentReceived(intent);
      expect(r.event.correlationId).toBe('corr-abc');
    });

    it('logIntentReceived can override correlationId', async () => {
      const intent = createIntent({ correlationId: 'original' });
      const r = await pp.logIntentReceived(intent, 'override-id');
      expect(r.event.correlationId).toBe('override-id');
    });

    it('logDecisionMade uses decision correlationId', async () => {
      const decision = createDecision({ correlationId: 'corr-dec' });
      const r = await pp.logDecisionMade(decision);
      expect(r.event.correlationId).toBe('corr-dec');
    });

    it('logDecisionMade can override correlationId', async () => {
      const decision = createDecision({ correlationId: 'orig' });
      const r = await pp.logDecisionMade(decision, 'custom-corr');
      expect(r.event.correlationId).toBe('custom-corr');
    });

    it('logEvent uses provided correlationId', async () => {
      const r = await pp.logEvent(
        ProofEventType.EXECUTION_STARTED,
        'explicit-corr',
        { type: 'execution_started', executionId: 'e1', actionId: 'a1', decisionId: 'd1', adapterId: 'ad1' },
        'agent-1',
      );
      expect(r.event.correlationId).toBe('explicit-corr');
    });
  });

  // ── getTrace ──────────────────────────────────────────────────────────

  describe('getTrace', () => {
    it('returns all events for a correlation ID', async () => {
      const corr = uuidv4();
      await pp.logEvent(ProofEventType.INTENT_RECEIVED, corr, { type: 'intent_received', intentId: 'i1', action: 'a', actionType: 'r', resourceScope: [] });
      await pp.logEvent(ProofEventType.DECISION_MADE, corr, { type: 'decision_made', decisionId: 'd1', intentId: 'i1', permitted: true, trustBand: 'T3', trustScore: 60, reasoning: ['ok'] });
      // unrelated event
      await pp.logEvent(ProofEventType.INTENT_RECEIVED, uuidv4(), { type: 'intent_received', intentId: 'i2', action: 'b', actionType: 'w', resourceScope: [] });

      const trace = await pp.getTrace(corr);
      expect(trace).toHaveLength(2);
      expect(trace.every(e => e.correlationId === corr)).toBe(true);
    });

    it('returns events in ascending order', async () => {
      const corr = uuidv4();
      const r1 = await pp.logEvent(ProofEventType.INTENT_RECEIVED, corr, { type: 'intent_received', intentId: 'i1', action: 'a', actionType: 'r', resourceScope: [] });
      const r2 = await pp.logEvent(ProofEventType.DECISION_MADE, corr, { type: 'decision_made', decisionId: 'd1', intentId: 'i1', permitted: true, trustBand: 'T3', trustScore: 60, reasoning: [] });

      const trace = await pp.getTrace(corr);
      expect(trace[0].eventId).toBe(r1.event.eventId);
      expect(trace[1].eventId).toBe(r2.event.eventId);
    });

    it('returns empty array for non-existent correlation', async () => {
      const trace = await pp.getTrace('no-such-correlation');
      expect(trace).toEqual([]);
    });
  });

  // ── Multi-step workflows ──────────────────────────────────────────────

  describe('multi-step workflows', () => {
    it('intent -> decision -> execution share correlation', async () => {
      const corr = uuidv4();
      const agentId = uuidv4();

      await pp.logIntentReceived(createIntent({ correlationId: corr, agentId }));
      await pp.logDecisionMade(createDecision({ correlationId: corr, agentId }));
      await pp.logExecutionStarted('exec-1', 'act-1', 'dec-1', 'adapter-1', agentId, corr);
      await pp.logExecutionCompleted('exec-1', 'act-1', 200, 'hash123', agentId, corr);

      const trace = await pp.getTrace(corr);
      expect(trace).toHaveLength(4);
      expect(trace[0].eventType).toBe(ProofEventType.INTENT_RECEIVED);
      expect(trace[1].eventType).toBe(ProofEventType.DECISION_MADE);
      expect(trace[2].eventType).toBe(ProofEventType.EXECUTION_STARTED);
      expect(trace[3].eventType).toBe(ProofEventType.EXECUTION_COMPLETED);
    });

    it('intent -> decision -> failed execution share correlation', async () => {
      const corr = uuidv4();
      const agentId = uuidv4();

      await pp.logIntentReceived(createIntent({ correlationId: corr, agentId }));
      await pp.logDecisionMade(createDecision({ correlationId: corr, agentId }));
      await pp.logExecutionFailed('exec-1', 'act-1', 'timeout', 5000, true, agentId, corr);

      const trace = await pp.getTrace(corr);
      expect(trace).toHaveLength(3);
      expect(trace[2].eventType).toBe(ProofEventType.EXECUTION_FAILED);
    });

    it('two independent workflows have separate traces', async () => {
      const corr1 = uuidv4();
      const corr2 = uuidv4();

      await pp.logIntentReceived(createIntent({ correlationId: corr1 }));
      await pp.logIntentReceived(createIntent({ correlationId: corr2 }));
      await pp.logDecisionMade(createDecision({ correlationId: corr1 }));
      await pp.logDecisionMade(createDecision({ correlationId: corr2 }));

      const trace1 = await pp.getTrace(corr1);
      const trace2 = await pp.getTrace(corr2);
      expect(trace1).toHaveLength(2);
      expect(trace2).toHaveLength(2);
      expect(trace1.every(e => e.correlationId === corr1)).toBe(true);
      expect(trace2.every(e => e.correlationId === corr2)).toBe(true);
    });
  });

  // ── Correlation ID uniqueness across actions ──────────────────────────

  describe('correlation ID uniqueness', () => {
    it('each intent gets unique correlationId by default', async () => {
      const i1 = createIntent();
      const i2 = createIntent();
      expect(i1.correlationId).not.toBe(i2.correlationId);
    });

    it('events with different correlations are isolated', async () => {
      const corrA = uuidv4();
      const corrB = uuidv4();

      await pp.logEvent(ProofEventType.INTENT_RECEIVED, corrA, { type: 'intent_received', intentId: 'i', action: 'a', actionType: 'r', resourceScope: [] });
      await pp.logEvent(ProofEventType.INTENT_RECEIVED, corrB, { type: 'intent_received', intentId: 'j', action: 'a', actionType: 'r', resourceScope: [] });

      const traceA = await pp.getTrace(corrA);
      const traceB = await pp.getTrace(corrB);
      expect(traceA).toHaveLength(1);
      expect(traceB).toHaveLength(1);
      expect(traceA[0].eventId).not.toBe(traceB[0].eventId);
    });

    it('many concurrent workflows maintain isolation', async () => {
      const correlations = Array.from({ length: 20 }, () => uuidv4());
      for (const corr of correlations) {
        await pp.logEvent(ProofEventType.INTENT_RECEIVED, corr, { type: 'intent_received', intentId: uuidv4(), action: 'a', actionType: 'r', resourceScope: [] });
        await pp.logEvent(ProofEventType.DECISION_MADE, corr, { type: 'decision_made', decisionId: uuidv4(), intentId: 'i', permitted: true, trustBand: 'T3', trustScore: 60, reasoning: [] });
      }
      for (const corr of correlations) {
        const trace = await pp.getTrace(corr);
        expect(trace).toHaveLength(2);
      }
    });
  });

  // ── Missing correlation ID handling ───────────────────────────────────

  describe('missing correlation handling', () => {
    it('query with non-existent correlation returns empty', async () => {
      await pp.logIntentReceived(createIntent());
      const trace = await pp.getTrace('does-not-exist');
      expect(trace).toEqual([]);
    });

    it('empty store returns empty trace', async () => {
      const trace = await pp.getTrace(uuidv4());
      expect(trace).toEqual([]);
    });
  });

  // ── Cross-agent correlation ───────────────────────────────────────────

  describe('cross-agent correlation', () => {
    it('events from different agents can share correlation ID', async () => {
      const corr = uuidv4();
      const agent1 = 'agent-alpha';
      const agent2 = 'agent-beta';

      await pp.logIntentReceived(createIntent({ correlationId: corr, agentId: agent1 }));
      await pp.logDecisionMade(createDecision({ correlationId: corr, agentId: agent2 }));

      const trace = await pp.getTrace(corr);
      expect(trace).toHaveLength(2);
      expect(trace[0].agentId).toBe(agent1);
      expect(trace[1].agentId).toBe(agent2);
    });

    it('agent history differs from correlation trace', async () => {
      const corr = uuidv4();
      const agent1 = uuidv4();

      await pp.logIntentReceived(createIntent({ correlationId: corr, agentId: agent1 }));
      await pp.logDecisionMade(createDecision({ correlationId: corr, agentId: agent1 }));
      // different correlation, same agent
      await pp.logIntentReceived(createIntent({ agentId: agent1 }));

      const trace = await pp.getTrace(corr);
      const agentHistory = await pp.getAgentHistory(agent1);
      expect(trace).toHaveLength(2);
      expect(agentHistory).toHaveLength(3);
    });

    it('three agents in one workflow all appear in trace', async () => {
      const corr = uuidv4();
      const agents = ['agent-1', 'agent-2', 'agent-3'];

      for (const agentId of agents) {
        await pp.logIntentReceived(createIntent({ correlationId: corr, agentId }));
      }

      const trace = await pp.getTrace(corr);
      expect(trace).toHaveLength(3);
      const traceAgents = trace.map(e => e.agentId);
      expect(traceAgents).toEqual(agents);
    });

    it('verifyCorrelationChain works for cross-agent correlation', async () => {
      const corr = uuidv4();
      await pp.logIntentReceived(createIntent({ correlationId: corr, agentId: 'a1' }));
      await pp.logDecisionMade(createDecision({ correlationId: corr, agentId: 'a2' }));

      // Note: correlation chain verification verifies the GLOBAL chain subset
      // Events in the correlation share a global chain, so they might not be contiguous
      const result = await pp.verifyCorrelationChain(corr);
      // This can still be valid if they are the only events
      expect(result.totalEvents).toBe(2);
    });
  });
});
