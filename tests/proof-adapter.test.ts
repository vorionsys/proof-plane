/**
 * ProofAdapter Tests
 *
 * Validates the strict/deferred routing layer without modifying
 * ProofPlane or ProofCommitter internals.
 */

import { describe, it, expect, vi } from 'vitest';
import {
  createProofAdapter,
  type ProofAdapterEvent,
  type ProofCommitterLike,
} from '../src/proof-adapter.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvent(overrides?: Partial<ProofAdapterEvent>): ProofAdapterEvent {
  return {
    type: 'decision_made',
    entityId: 'agent-001',
    payload: { permitted: true, score: 450 },
    timestamp: Date.now(),
    correlationId: 'corr-001',
    ...overrides,
  };
}

/**
 * Minimal mock ProofPlane — duck-typed to satisfy the adapter's
 * internal call to proofPlane.logEvent().
 */
function mockProofPlane() {
  const eventId = 'evt-' + Math.random().toString(36).slice(2, 10);
  return {
    logEvent: vi.fn().mockResolvedValue({
      event: { eventId },
      isGenesis: false,
      previousHash: 'abc123',
    }),
    _lastEventId: eventId,
  };
}

/**
 * Minimal mock ProofCommitter.
 */
function mockProofCommitter(): ProofCommitterLike {
  const commitmentId = 'cmt-' + Math.random().toString(36).slice(2, 10);
  return {
    commit: vi.fn().mockReturnValue(commitmentId),
    _lastCommitmentId: commitmentId,
  } as unknown as ProofCommitterLike;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ProofAdapter', () => {
  // ---- mode property ----

  describe('mode property', () => {
    it('returns "strict" for strict mode', () => {
      const adapter = createProofAdapter({
        mode: 'strict',
        proofPlane: mockProofPlane() as any,
      });
      expect(adapter.mode).toBe('strict');
    });

    it('returns "deferred" for deferred mode', () => {
      const adapter = createProofAdapter({
        mode: 'deferred',
        proofCommitter: mockProofCommitter(),
      });
      expect(adapter.mode).toBe('deferred');
    });
  });

  // ---- strict mode ----

  describe('strict mode', () => {
    it('delegates to ProofPlane and returns event ID', async () => {
      const pp = mockProofPlane();
      const adapter = createProofAdapter({ mode: 'strict', proofPlane: pp as any });
      const event = makeEvent();

      const id = await adapter.logEvent(event);

      expect(id).toBe(pp._lastEventId);
      expect(pp.logEvent).toHaveBeenCalledOnce();

      // Verify the ProofPlane received the right arguments
      const [eventType, correlationId, payload, agentId] = pp.logEvent.mock.calls[0]!;
      expect(eventType).toBe('decision_made');
      expect(correlationId).toBe('corr-001');
      expect(payload.type).toBe('decision_made');
      expect(agentId).toBe('agent-001');
    });

    it('throws if ProofPlane not provided', () => {
      expect(() =>
        createProofAdapter({ mode: 'strict' }),
      ).toThrow('strict mode requires a proofPlane instance');
    });

    it('completes without performance assertion (it writes synchronously)', async () => {
      const pp = mockProofPlane();
      const adapter = createProofAdapter({ mode: 'strict', proofPlane: pp as any });

      // Just verify it resolves successfully
      const id = await adapter.logEvent(makeEvent());
      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);
    });
  });

  // ---- deferred mode ----

  describe('deferred mode', () => {
    it('delegates to ProofCommitter and returns commitment ID', () => {
      const pc = mockProofCommitter();
      const adapter = createProofAdapter({ mode: 'deferred', proofCommitter: pc });
      const event = makeEvent();

      const id = adapter.logEvent(event);

      // deferred mode is synchronous — returns string, not Promise
      expect(typeof id).toBe('string');
      expect(id).toBe((pc as any)._lastCommitmentId);
      expect((pc as any).commit).toHaveBeenCalledOnce();
      expect((pc as any).commit).toHaveBeenCalledWith(event);
    });

    it('throws if ProofCommitter not provided', () => {
      expect(() =>
        createProofAdapter({ mode: 'deferred' }),
      ).toThrow('deferred mode requires a proofCommitter instance');
    });

    it('commit completes in under 1ms', () => {
      // Use a real-ish committer that just returns a string
      const fastCommitter: ProofCommitterLike = {
        commit: (_event) => 'fast-id',
      };
      const adapter = createProofAdapter({
        mode: 'deferred',
        proofCommitter: fastCommitter,
      });
      const event = makeEvent();

      const start = performance.now();
      adapter.logEvent(event);
      const elapsed = performance.now() - start;

      // Allow generous margin — the adapter routing itself should be ~0ms.
      // The 1ms budget is for ProofCommitter.commit() which includes SHA-256.
      // This test only measures the adapter overhead.
      expect(elapsed).toBeLessThan(1);
    });
  });

  // ---- factory validation ----

  describe('factory validates config', () => {
    it('strict mode without proofPlane throws', () => {
      expect(() => createProofAdapter({ mode: 'strict' })).toThrow();
    });

    it('deferred mode without proofCommitter throws', () => {
      expect(() => createProofAdapter({ mode: 'deferred' })).toThrow();
    });

    it('unknown mode throws', () => {
      expect(() =>
        createProofAdapter({ mode: 'invalid' as any }),
      ).toThrow("unknown mode 'invalid'");
    });

    it('strict mode with proofPlane succeeds', () => {
      expect(() =>
        createProofAdapter({ mode: 'strict', proofPlane: mockProofPlane() as any }),
      ).not.toThrow();
    });

    it('deferred mode with proofCommitter succeeds', () => {
      expect(() =>
        createProofAdapter({ mode: 'deferred', proofCommitter: mockProofCommitter() }),
      ).not.toThrow();
    });
  });

  // ---- uses correlationId fallback ----

  describe('correlationId handling', () => {
    it('strict mode falls back to entityId when correlationId is missing', async () => {
      const pp = mockProofPlane();
      const adapter = createProofAdapter({ mode: 'strict', proofPlane: pp as any });

      await adapter.logEvent(makeEvent({ correlationId: undefined }));

      const [, correlationId] = pp.logEvent.mock.calls[0]!;
      expect(correlationId).toBe('agent-001');
    });
  });
});
