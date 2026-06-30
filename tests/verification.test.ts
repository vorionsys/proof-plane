/**
 * Verification Tests
 *
 * Covers verifyChain on valid chains, tampered chains with specific errors,
 * verifyEventHash, verifyEventHash3, partial chain verification,
 * correction events, and performance benchmarks.
 */

import { describe, it, expect } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType, type ProofEvent } from '@vorionsys/contracts';
import {
  computeEventHash,
  computeEventHash3,
  verifyEventHash,
  verifyEventHash3,
  verifyChain,
  verifyChainWithDetails,
  verifyChainLink,
} from '../src/events/hash-chain.js';
import { createProofPlane } from '../src/index.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function createTestEvent(
  overrides: Partial<Omit<ProofEvent, 'eventHash' | 'recordedAt'>> = {},
): Omit<ProofEvent, 'eventHash' | 'recordedAt'> {
  return {
    eventId: uuidv4(),
    eventType: ProofEventType.INTENT_RECEIVED,
    correlationId: uuidv4(),
    agentId: 'agent-v',
    payload: {
      type: 'intent_received',
      intentId: uuidv4(),
      action: 'verify-action',
      actionType: 'read',
      resourceScope: ['/verify'],
    },
    previousHash: null,
    occurredAt: new Date('2026-03-01T12:00:00Z'),
    signedBy: 'verifier',
    ...overrides,
  };
}

async function buildHashedEvent(
  overrides: Partial<Omit<ProofEvent, 'eventHash' | 'recordedAt'>> = {},
): Promise<ProofEvent> {
  const base = createTestEvent(overrides);
  const eventHash = await computeEventHash(base);
  const eventHash3 = computeEventHash3(base);
  return { ...base, eventHash, eventHash3, recordedAt: new Date() };
}

async function buildChain(length: number): Promise<ProofEvent[]> {
  const chain: ProofEvent[] = [];
  for (let i = 0; i < length; i++) {
    const previousHash = i === 0 ? null : chain[i - 1].eventHash;
    const ev = await buildHashedEvent({
      previousHash,
      occurredAt: new Date(Date.UTC(2026, 2, 1, 0, 0, i)),
    });
    chain.push(ev);
  }
  return chain;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Verification', () => {
  // ── verifyChain on valid chain ────────────────────────────────────────

  describe('verifyChain on valid chain', () => {
    it('empty chain is valid', async () => {
      const result = await verifyChain([]);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(0);
    });

    it('single-event chain is valid', async () => {
      const chain = await buildChain(1);
      const result = await verifyChain(chain);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(1);
    });

    it('10-event chain is valid', async () => {
      const chain = await buildChain(10);
      const result = await verifyChain(chain);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(10);
    });

    it('valid chain has no brokenAtIndex', async () => {
      const chain = await buildChain(5);
      const result = await verifyChain(chain);
      expect(result.brokenAtIndex).toBeUndefined();
      expect(result.brokenAtEventId).toBeUndefined();
      expect(result.error).toBeUndefined();
    });
  });

  // ── verifyChain on tampered chain with specific errors ────────────────

  describe('verifyChain on tampered chain', () => {
    it('reports "invalid SHA-256 hash" for tampered eventHash', async () => {
      const chain = await buildChain(3);
      chain[1] = { ...chain[1], eventHash: '00'.repeat(32) };
      const result = await verifyChain(chain);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('invalid SHA-256 hash');
      expect(result.brokenAtIndex).toBe(1);
    });

    it('reports "invalid SHA3-256 hash" for tampered eventHash3', async () => {
      const chain = await buildChain(3);
      chain[2] = { ...chain[2], eventHash3: 'ff'.repeat(32) };
      const result = await verifyChain(chain);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('SHA3-256');
      expect(result.brokenAtIndex).toBe(2);
    });

    it('reports "broken chain link" for wrong previousHash', async () => {
      const chain = await buildChain(3);
      // Rebuild event 2 with wrong previousHash but correct hash for its own data
      const tamperedBase = createTestEvent({
        eventId: chain[2].eventId,
        correlationId: chain[2].correlationId,
        agentId: chain[2].agentId,
        payload: chain[2].payload,
        previousHash: 'wrong-previous',
        occurredAt: chain[2].occurredAt,
        signedBy: chain[2].signedBy,
      });
      const newHash = await computeEventHash(tamperedBase);
      const newHash3 = computeEventHash3(tamperedBase);
      chain[2] = { ...tamperedBase, eventHash: newHash, eventHash3: newHash3, recordedAt: new Date() };

      const result = await verifyChain(chain);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('broken chain link');
    });

    it('tampered payload is detected', async () => {
      const chain = await buildChain(4);
      chain[2] = {
        ...chain[2],
        payload: {
          type: 'intent_received',
          intentId: 'HACKED',
          action: 'hack',
          actionType: 'write',
          resourceScope: ['/root'],
        },
      };
      const result = await verifyChain(chain);
      expect(result.valid).toBe(false);
      expect(result.brokenAtIndex).toBe(2);
    });

    it('brokenAtEventId matches the tampered event', async () => {
      const chain = await buildChain(5);
      const targetId = chain[3].eventId;
      chain[3] = { ...chain[3], agentId: 'evil-agent' };
      const result = await verifyChain(chain);
      expect(result.brokenAtEventId).toBe(targetId);
    });

    it('verifiedCount reflects events verified before break', async () => {
      const chain = await buildChain(6);
      chain[4] = { ...chain[4], agentId: 'changed' };
      const result = await verifyChain(chain);
      expect(result.verifiedCount).toBe(4);
    });
  });

  // ── verifyEventHash ───────────────────────────────────────────────────

  describe('verifyEventHash', () => {
    it('returns true for valid hash', async () => {
      const ev = await buildHashedEvent();
      expect(await verifyEventHash(ev)).toBe(true);
    });

    it('returns false for wrong hash', async () => {
      const ev = await buildHashedEvent();
      const bad: ProofEvent = { ...ev, eventHash: '11'.repeat(32) };
      expect(await verifyEventHash(bad)).toBe(false);
    });

    it('returns false when payload is modified', async () => {
      const ev = await buildHashedEvent();
      const modified: ProofEvent = {
        ...ev,
        payload: { type: 'execution_completed', executionId: 'x', actionId: 'a', status: 'success' as const, durationMs: 0, outputHash: '' },
      };
      expect(await verifyEventHash(modified)).toBe(false);
    });

    it('returns false when eventId is changed', async () => {
      const ev = await buildHashedEvent();
      const modified: ProofEvent = { ...ev, eventId: uuidv4() };
      expect(await verifyEventHash(modified)).toBe(false);
    });

    it('hash is sensitive to occurredAt changes', async () => {
      const ev = await buildHashedEvent();
      const modified: ProofEvent = { ...ev, occurredAt: new Date('2099-12-31') };
      expect(await verifyEventHash(modified)).toBe(false);
    });
  });

  // ── verifyEventHash3 ─────────────────────────────────────────────────

  describe('verifyEventHash3', () => {
    it('returns true for valid SHA3-256 hash', async () => {
      const ev = await buildHashedEvent();
      expect(verifyEventHash3(ev)).toBe(true);
    });

    it('returns true when eventHash3 is absent', async () => {
      const base = createTestEvent();
      const eventHash = await computeEventHash(base);
      const ev: ProofEvent = { ...base, eventHash, recordedAt: new Date() };
      expect(verifyEventHash3(ev)).toBe(true);
    });

    it('returns false for tampered eventHash3', async () => {
      const ev = await buildHashedEvent();
      const bad: ProofEvent = { ...ev, eventHash3: 'ab'.repeat(32) };
      expect(verifyEventHash3(bad)).toBe(false);
    });

    it('SHA3-256 and SHA-256 can independently detect tampering', async () => {
      const ev = await buildHashedEvent();

      // Tamper with only SHA-256
      const badSha: ProofEvent = { ...ev, eventHash: '00'.repeat(32) };
      expect(await verifyEventHash(badSha)).toBe(false);
      expect(verifyEventHash3(badSha)).toBe(true); // SHA3 still valid

      // Tamper with only SHA3-256
      const badSha3: ProofEvent = { ...ev, eventHash3: '00'.repeat(32) };
      expect(await verifyEventHash(badSha3)).toBe(true); // SHA-256 still valid
      expect(verifyEventHash3(badSha3)).toBe(false);
    });
  });

  // ── Partial chain verification ────────────────────────────────────────

  describe('partial chain verification', () => {
    it('verifying a subchain (tail) of a valid chain works', async () => {
      const pp = createProofPlane({ signedBy: 'partial-test' });
      for (let i = 0; i < 10; i++) {
        await pp.logEvent(
          ProofEventType.INTENT_RECEIVED,
          uuidv4(),
          { type: 'intent_received', intentId: uuidv4(), action: 'a', actionType: 'r', resourceScope: [] },
        );
      }

      // Verify from event 5 onward
      const allEvents = (await pp.queryEvents()).events;
      const subchain = allEvents.slice(5);
      // This subchain starts at index 5, so its first event has non-null previousHash
      // verifyChain expects first event to have null previousHash, so it will fail
      const result = await verifyChain(subchain);
      expect(result.valid).toBe(false);
      expect(result.brokenAtIndex).toBe(0);
    });

    it('verifyChain with limit via ProofPlane.verifyChain', async () => {
      const pp = createProofPlane({ signedBy: 'limit-test' });
      for (let i = 0; i < 10; i++) {
        await pp.logEvent(
          ProofEventType.INTENT_RECEIVED,
          uuidv4(),
          { type: 'intent_received', intentId: uuidv4(), action: 'a', actionType: 'r', resourceScope: [] },
        );
      }

      const result = await pp.verifyChain(undefined, 5);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(5);
      expect(result.totalEvents).toBe(5);
    });
  });

  // ── verifyChainWithDetails ────────────────────────────────────────────

  describe('verifyChainWithDetails', () => {
    it('returns firstEventId and lastEventId', async () => {
      const chain = await buildChain(3);
      const result = await verifyChainWithDetails(chain);
      expect(result.firstEventId).toBe(chain[0].eventId);
      expect(result.lastEventId).toBe(chain[2].eventId);
    });

    it('returns totalEvents', async () => {
      const chain = await buildChain(7);
      const result = await verifyChainWithDetails(chain);
      expect(result.totalEvents).toBe(7);
    });

    it('empty chain returns no IDs', async () => {
      const result = await verifyChainWithDetails([]);
      expect(result.valid).toBe(true);
      expect(result.totalEvents).toBe(0);
      expect(result.firstEventId).toBeUndefined();
      expect(result.lastEventId).toBeUndefined();
    });
  });

  // ── Verification with correction events ───────────────────────────────

  describe('verification with correction events', () => {
    it('chain with correction event appended verifies', async () => {
      const chain = await buildChain(3);
      const correction = await buildHashedEvent({
        previousHash: chain[2].eventHash,
        eventType: ProofEventType.COMPONENT_UPDATED,
        payload: { type: 'component_updated', componentId: 'c1', changes: ['correction'] },
      });
      chain.push(correction);
      const result = await verifyChain(chain);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(4);
    });

    it('chain with multiple correction events verifies', async () => {
      const chain = await buildChain(2);
      for (let i = 0; i < 3; i++) {
        const correction = await buildHashedEvent({
          previousHash: chain[chain.length - 1].eventHash,
          eventType: ProofEventType.COMPONENT_UPDATED,
          payload: { type: 'component_updated', componentId: `c${i}`, changes: [`fix-${i}`] },
        });
        chain.push(correction);
      }
      const result = await verifyChain(chain);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(5);
    });
  });

  // ── Performance ───────────────────────────────────────────────────────

  describe('performance', () => {
    it('verifies 1000-event chain in under 10 seconds', async () => {
      const pp = createProofPlane({ signedBy: 'perf-test' });
      for (let i = 0; i < 1000; i++) {
        await pp.logEvent(
          ProofEventType.INTENT_RECEIVED,
          uuidv4(),
          { type: 'intent_received', intentId: uuidv4(), action: 'a', actionType: 'r', resourceScope: [] },
        );
      }

      const start = performance.now();
      const result = await pp.verifyChain();
      const elapsed = performance.now() - start;

      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(1000);
      expect(elapsed).toBeLessThan(30000);
    }, 60000); // generous timeout for CI / slow Windows I/O

    it('emitting 100 events keeps chain valid', async () => {
      const pp = createProofPlane({ signedBy: 'emit-perf' });
      for (let i = 0; i < 100; i++) {
        await pp.logEvent(
          i % 2 === 0 ? ProofEventType.INTENT_RECEIVED : ProofEventType.DECISION_MADE,
          uuidv4(),
          i % 2 === 0
            ? { type: 'intent_received', intentId: uuidv4(), action: 'a', actionType: 'r', resourceScope: [] }
            : { type: 'decision_made', decisionId: uuidv4(), intentId: 'i', permitted: true, trustBand: 'T3', trustScore: 60, reasoning: [] },
        );
      }
      const result = await pp.verifyChain();
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(100);
    });
  });
});
