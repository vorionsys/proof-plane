/**
 * A3I Bridge Logger Tests
 *
 * Comprehensive tests for the ProofPlaneLogger that bridges
 * the A3I authorization engine with the Vorion proof plane,
 * covering factory creation, flag combinations, logDecision
 * behavior, and the noop logger.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
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
  createProofPlaneLogger,
  noopProofPlaneLogger,
  ProofPlaneLoggerImpl,
  type ProofPlaneLogger,
} from '../../src/index.js';

// ─── Test Data Helpers ──────────────────────────────────────────────────────

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
    trustScore: 65,
    reasoning: ['test decision'],
    decidedAt: new Date(),
    expiresAt: new Date(Date.now() + 300000),
    latencyMs: 3,
    version: 1,
    ...overrides,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('ProofPlaneLogger', () => {
  let proofPlane: ProofPlane;

  beforeEach(() => {
    proofPlane = createProofPlane({ signedBy: 'logger-test', enableSignatures: false });
  });

  // ── Factory Creation ────────────────────────────────────────────────

  describe('createProofPlaneLogger', () => {
    it('should create a ProofPlaneLoggerImpl instance', () => {
      const logger = createProofPlaneLogger({ proofPlane });
      expect(logger).toBeInstanceOf(ProofPlaneLoggerImpl);
    });

    it('should implement the ProofPlaneLogger interface', () => {
      const logger = createProofPlaneLogger({ proofPlane });
      expect(typeof logger.logDecision).toBe('function');
    });

    it('should accept proofPlane as the only required config', () => {
      const logger = createProofPlaneLogger({ proofPlane });
      expect(logger).toBeDefined();
    });

    it('should accept logIntentReceived config flag', () => {
      const logger = createProofPlaneLogger({
        proofPlane,
        logIntentReceived: false,
      });
      expect(logger).toBeDefined();
    });

    it('should accept logDecisionMade config flag', () => {
      const logger = createProofPlaneLogger({
        proofPlane,
        logDecisionMade: false,
      });
      expect(logger).toBeDefined();
    });
  });

  // ── logDecision ─────────────────────────────────────────────────────

  describe('logDecision', () => {
    it('should log both intent and decision by default', async () => {
      const logger = createProofPlaneLogger({ proofPlane });
      const correlationId = uuidv4();
      const intent = createIntent({ correlationId });
      const decision = createDecision({ correlationId });

      await logger.logDecision(decision, intent);

      const count = await proofPlane.getEventCount();
      expect(count).toBe(2);
    });

    it('should log intent before decision (ordering)', async () => {
      const logger = createProofPlaneLogger({ proofPlane });
      const correlationId = uuidv4();
      const intent = createIntent({ correlationId });
      const decision = createDecision({ correlationId });

      await logger.logDecision(decision, intent);

      const trace = await proofPlane.getTrace(correlationId);
      expect(trace).toHaveLength(2);
      expect(trace[0].eventType).toBe(ProofEventType.INTENT_RECEIVED);
      expect(trace[1].eventType).toBe(ProofEventType.DECISION_MADE);
    });

    it('should use decision correlationId for both events', async () => {
      const correlationId = uuidv4();
      const logger = createProofPlaneLogger({ proofPlane });
      const intent = createIntent({ correlationId: uuidv4() }); // different correlationId
      const decision = createDecision({ correlationId });

      await logger.logDecision(decision, intent);

      // Both events should use the decision's correlationId
      const trace = await proofPlane.getTrace(correlationId);
      expect(trace).toHaveLength(2);
    });

    it('should pass intent data correctly to logIntentReceived', async () => {
      const logger = createProofPlaneLogger({ proofPlane });
      const intent = createIntent({ action: 'write-file' });
      const decision = createDecision({ correlationId: intent.correlationId });

      await logger.logDecision(decision, intent);

      const events = await proofPlane.getTrace(decision.correlationId);
      const intentEvent = events.find(
        (e) => e.eventType === ProofEventType.INTENT_RECEIVED
      );
      expect(intentEvent).toBeDefined();
      const payload = intentEvent!.payload as { action: string };
      expect(payload.action).toBe('write-file');
    });

    it('should pass decision data correctly to logDecisionMade', async () => {
      const logger = createProofPlaneLogger({ proofPlane });
      const intent = createIntent();
      const decision = createDecision({
        correlationId: intent.correlationId,
        permitted: false,
        trustScore: 30,
      });

      await logger.logDecision(decision, intent);

      const events = await proofPlane.getTrace(decision.correlationId);
      const decisionEvent = events.find(
        (e) => e.eventType === ProofEventType.DECISION_MADE
      );
      expect(decisionEvent).toBeDefined();
      const payload = decisionEvent!.payload as { permitted: boolean; trustScore: number };
      expect(payload.permitted).toBe(false);
      expect(payload.trustScore).toBe(30);
    });

    it('should return void (not the EmitResult)', async () => {
      const logger = createProofPlaneLogger({ proofPlane });
      const result = await logger.logDecision(createDecision(), createIntent());
      expect(result).toBeUndefined();
    });
  });

  // ── Flag Combinations ───────────────────────────────────────────────

  describe('flag combinations', () => {
    it('both flags true (default) logs 2 events', async () => {
      const logger = createProofPlaneLogger({
        proofPlane,
        logIntentReceived: true,
        logDecisionMade: true,
      });

      await logger.logDecision(createDecision(), createIntent());

      expect(await proofPlane.getEventCount()).toBe(2);
    });

    it('logIntentReceived=false skips intent event', async () => {
      const logger = createProofPlaneLogger({
        proofPlane,
        logIntentReceived: false,
        logDecisionMade: true,
      });

      await logger.logDecision(createDecision(), createIntent());

      const count = await proofPlane.getEventCount();
      expect(count).toBe(1);

      const events = await proofPlane.queryEvents();
      expect(events.events[0].eventType).toBe(ProofEventType.DECISION_MADE);
    });

    it('logDecisionMade=false skips decision event', async () => {
      const logger = createProofPlaneLogger({
        proofPlane,
        logIntentReceived: true,
        logDecisionMade: false,
      });

      await logger.logDecision(createDecision(), createIntent());

      const count = await proofPlane.getEventCount();
      expect(count).toBe(1);

      const events = await proofPlane.queryEvents();
      expect(events.events[0].eventType).toBe(ProofEventType.INTENT_RECEIVED);
    });

    it('both flags false logs 0 events', async () => {
      const logger = createProofPlaneLogger({
        proofPlane,
        logIntentReceived: false,
        logDecisionMade: false,
      });

      await logger.logDecision(createDecision(), createIntent());

      expect(await proofPlane.getEventCount()).toBe(0);
    });

    it('flags default to true when omitted', async () => {
      const logger = createProofPlaneLogger({ proofPlane });

      await logger.logDecision(createDecision(), createIntent());

      expect(await proofPlane.getEventCount()).toBe(2);
    });
  });

  // ── noopProofPlaneLogger ────────────────────────────────────────────

  describe('noopProofPlaneLogger', () => {
    it('should expose a logDecision method', () => {
      expect(typeof noopProofPlaneLogger.logDecision).toBe('function');
    });

    it('should satisfy the ProofPlaneLogger interface', () => {
      const logger: ProofPlaneLogger = noopProofPlaneLogger;
      expect(logger).toBeDefined();
    });

    it('should not throw when logDecision is called', async () => {
      const decision = createDecision();
      const intent = createIntent();

      await expect(
        noopProofPlaneLogger.logDecision(decision, intent)
      ).resolves.not.toThrow();
    });

    it('should return undefined from logDecision', async () => {
      const result = await noopProofPlaneLogger.logDecision(
        createDecision(),
        createIntent()
      );
      expect(result).toBeUndefined();
    });

    it('should not log any events anywhere', async () => {
      // Use a real proof plane to ensure noop does nothing
      const pp = createProofPlane({ enableSignatures: false });

      // Call noop logger - it should not interact with any proof plane
      await noopProofPlaneLogger.logDecision(createDecision(), createIntent());

      const count = await pp.getEventCount();
      expect(count).toBe(0);
    });

    it('should handle multiple sequential calls without error', async () => {
      for (let i = 0; i < 10; i++) {
        await noopProofPlaneLogger.logDecision(createDecision(), createIntent());
      }
      // No error means success
    });
  });

  // ── Multiple loggers sharing a proof plane ──────────────────────────

  describe('multiple loggers', () => {
    it('two loggers sharing a proof plane both write to it', async () => {
      const logger1 = createProofPlaneLogger({ proofPlane });
      const logger2 = createProofPlaneLogger({ proofPlane });

      await logger1.logDecision(createDecision(), createIntent());
      await logger2.logDecision(createDecision(), createIntent());

      expect(await proofPlane.getEventCount()).toBe(4);
    });
  });
});
