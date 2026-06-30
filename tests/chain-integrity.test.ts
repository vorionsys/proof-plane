/**
 * Chain Integrity Tests
 *
 * Covers hash chain linking, dual-hash verification, canonical JSON,
 * tampering detection, replay attacks, genesis events, large chains,
 * correction events, and timestamp monotonicity.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType, type ProofEvent } from '@vorionsys/contracts';
import {
  sha256,
  sha3_256,
  computeEventHash,
  computeEventHash3,
  verifyEventHash,
  verifyEventHash3,
  verifyChainLink,
  verifyChain,
  verifyChainWithDetails,
  getGenesisHash,
} from '../src/events/hash-chain.js';
import { createProofPlane, type ProofPlane } from '../src/index.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function createTestEvent(
  overrides: Partial<Omit<ProofEvent, 'eventHash' | 'recordedAt'>> = {},
): Omit<ProofEvent, 'eventHash' | 'recordedAt'> {
  return {
    eventId: uuidv4(),
    eventType: ProofEventType.INTENT_RECEIVED,
    correlationId: uuidv4(),
    agentId: 'agent-01',
    payload: {
      type: 'intent_received',
      intentId: uuidv4(),
      action: 'read-file',
      actionType: 'read',
      resourceScope: ['/data'],
    },
    previousHash: null,
    occurredAt: new Date('2026-01-01T00:00:00Z'),
    signedBy: 'test-signer',
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
      occurredAt: new Date(Date.UTC(2026, 0, 1, 0, 0, i)),
    });
    chain.push(ev);
  }
  return chain;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Chain Integrity', () => {
  // ── Hash chain linking ──────────────────────────────────────────────────

  describe('hash chain linking', () => {
    it('each event previousHash equals prior eventHash in a 3-event chain', async () => {
      const chain = await buildChain(3);
      expect(chain[0].previousHash).toBeNull();
      expect(chain[1].previousHash).toBe(chain[0].eventHash);
      expect(chain[2].previousHash).toBe(chain[1].eventHash);
    });

    it('each event previousHash equals prior eventHash in a 5-event chain', async () => {
      const chain = await buildChain(5);
      for (let i = 1; i < chain.length; i++) {
        expect(chain[i].previousHash).toBe(chain[i - 1].eventHash);
      }
    });

    it('verifyChainLink returns true for each link in a valid chain', async () => {
      const chain = await buildChain(4);
      expect(verifyChainLink(chain[0], null)).toBe(true);
      for (let i = 1; i < chain.length; i++) {
        expect(verifyChainLink(chain[i], chain[i - 1])).toBe(true);
      }
    });

    it('swapping two events breaks chain links', async () => {
      const chain = await buildChain(4);
      // swap events at index 1 and 2
      const swapped = [chain[0], chain[2], chain[1], chain[3]];
      const result = await verifyChain(swapped);
      expect(result.valid).toBe(false);
    });

    it('removing an event from the middle breaks the chain', async () => {
      const chain = await buildChain(5);
      // remove index 2
      const gapped = [chain[0], chain[1], chain[3], chain[4]];
      const result = await verifyChain(gapped);
      expect(result.valid).toBe(false);
      expect(result.brokenAtIndex).toBe(2);
    });
  });

  // ── Dual-hash verification ─────────────────────────────────────────────

  describe('dual-hash verification', () => {
    it('computeEventHash produces a 64-char hex SHA-256', async () => {
      const hash = await computeEventHash(createTestEvent());
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('computeEventHash3 produces a 64-char hex SHA3-256', () => {
      const hash3 = computeEventHash3(createTestEvent());
      expect(hash3).toHaveLength(64);
      expect(hash3).toMatch(/^[0-9a-f]{64}$/);
    });

    it('SHA-256 and SHA3-256 of same event are different', async () => {
      const ev = createTestEvent();
      const h1 = await computeEventHash(ev);
      const h2 = computeEventHash3(ev);
      expect(h1).not.toBe(h2);
    });

    it('verifyEventHash passes for correctly hashed event', async () => {
      const ev = await buildHashedEvent();
      expect(await verifyEventHash(ev)).toBe(true);
    });

    it('verifyEventHash3 passes for correctly hashed event', async () => {
      const ev = await buildHashedEvent();
      expect(verifyEventHash3(ev)).toBe(true);
    });

    it('verifyEventHash3 passes when eventHash3 is absent (pre-upgrade)', async () => {
      const base = createTestEvent();
      const eventHash = await computeEventHash(base);
      const ev: ProofEvent = { ...base, eventHash, recordedAt: new Date() };
      // no eventHash3
      expect(verifyEventHash3(ev)).toBe(true);
    });

    it('verifyEventHash3 fails when eventHash3 is wrong', async () => {
      const ev = await buildHashedEvent();
      const tampered: ProofEvent = { ...ev, eventHash3: 'ff'.repeat(32) };
      expect(verifyEventHash3(tampered)).toBe(false);
    });

    it('verifyChain detects invalid SHA3-256 hash', async () => {
      const chain = await buildChain(3);
      chain[1] = { ...chain[1], eventHash3: '00'.repeat(32) };
      const result = await verifyChain(chain);
      expect(result.valid).toBe(false);
      expect(result.brokenAtIndex).toBe(1);
      expect(result.error).toContain('SHA3-256');
    });
  });

  // ── Canonical JSON serialization ───────────────────────────────────────

  describe('canonical JSON serialization', () => {
    it('same event data in different key order yields same hash', async () => {
      const ev1 = createTestEvent({ agentId: 'a', signedBy: 'z' });
      const ev2 = {
        signedBy: 'z',
        agentId: 'a',
        eventId: ev1.eventId,
        eventType: ev1.eventType,
        correlationId: ev1.correlationId,
        payload: ev1.payload,
        previousHash: ev1.previousHash,
        occurredAt: ev1.occurredAt,
      } as Omit<ProofEvent, 'eventHash' | 'recordedAt'>;

      const h1 = await computeEventHash(ev1);
      const h2 = await computeEventHash(ev2);
      expect(h1).toBe(h2);
    });

    it('payload with keys in different order produces same hash', async () => {
      const ev1 = createTestEvent({
        payload: {
          type: 'intent_received',
          intentId: 'x',
          action: 'read',
          actionType: 'read',
          resourceScope: ['a'],
        },
      });
      const ev2 = {
        ...ev1,
        payload: {
          resourceScope: ['a'],
          actionType: 'read',
          action: 'read',
          intentId: 'x',
          type: 'intent_received' as const,
        },
      };

      const h1 = await computeEventHash(ev1);
      const h2 = await computeEventHash(ev2);
      expect(hy', async () => {
      const payload1 = {
        type: 'intent_received' as const,
        intentId: 'x',
        action: 'read',
        actionType: 'read',
        resourceScope: ['/a'],
      };
      const payload2 = {
        actionType: 'read',
        type: 'intent_received' as const,
        resourceScope: ['/a'],
        action: 'read',
        intentId: 'x',
      };

      const ev1 = createTestEvent({ payload: payload1 });
      const ev2 = { ...ev1, payload: payload2 };

      expect(await computeEventHash(ev1)).toBe(await computeEventHash(ev2));
    });

    it('different payload values produce different hashes', async () => {
      const ev1 = createTestEvent();
      const ev2 = createTestEvent({
        ...ev1,
        payload: {
          type: 'intent_received',
          intentId: 'DIFFERENT',
          action: 'write',
          actionType: 'write',
          resourceScope: ['/other'],
        },
      });
      // Keep same eventId etc but different payload
      ev2.eventId = ev1.eventId;
      ev2.correlationId = ev1.correlationId;
      ev2.occurredAt = ev1.occurredAt;

      const h1 = await computeEventHash(ev1);
      const h2 = await computeEventHash(ev2);
      expect(h1).not.toBe(h2);
    });
  });

  // ── Tampering detection ────────────────────────────────────────────────

  describe('tampering detection', () => {
    it('modifying agentId makes hash invalid', async () => {
      const ev = await buildHashedEvent({ agentId: 'original-agent' });
      const tampered: ProofEvent = { ...ev, agentId: 'hacker-agent' };
      expect(await verifyEventHash(tampered)).toBe(false);
    });

    it('modifying correlationId makes hash invalid', async () => {
      const ev = await buildHashedEvent();
      const tampered: ProofEvent = { ...ev, correlationId: 'tampered-corr' };
      expect(await verifyEventHash(tampered)).toBe(false);
    });

    it('modifying eventType makes hash invalid', async () => {
      const ev = await buildHashedEvent();
      const tampered: ProofEvent = {
        ...ev,
        eventType: ProofEventType.DECISION_MADE,
      };
      expect(await verifyEventHash(tampered)).toBe(false);
    });

    it('modifying occurredAt makes hash invalid', async () => {
      const ev = await buildHashedEvent();
      const tampered: ProofEvent = { ...ev, occurredAt: new Date('2099-01-01') };
      expect(await verifyEventHash(tampered)).toBe(false);
    });

    it('modifying previousHash makes hash invalid', async () => {
      const chain = await buildChain(2);
      const tampered: ProofEvent = {
        ...chain[1],
        previousHash: 'aa'.repeat(32),
      };
      expect(await verifyEventHash(tampered)).toBe(false);
    });

    it('modifying payload field makes hash invalid', async () => {
      const ev = await buildHashedEvent();
      const tampered: ProofEvent = {
        ...ev,
        payload: { ...ev.payload, type: 'execution_started' } as ProofEvent['payload'],
      };
      expect(await verifyEventHash(tampered)).toBe(false);
    });

    it('verifyChain catches tampered event in middle of chain', async () => {
      const chain = await buildChain(5);
      chain[2] = { ...chain[2], agentId: 'tampered' };
      const result = await verifyChain(chain);
      expect(result.valid).toBe(false);
      expect(result.brokenAtIndex).toBe(2);
    });

    it('modifying signedBy makes hash invalid', async () => {
      const ev = await buildHashedEvent({ signedBy: 'original' });
      const tampered: ProofEvent = { ...ev, signedBy: 'impersonator' };
      expect(await verifyEventHash(tampered)).toBe(false);
    });
  });

  // ── Chain replay attacks ───────────────────────────────────────────────

  describe('chain replay attacks', () => {
    it('reordering events breaks the chain', async () => {
      const chain = await buildChain(4);
      const reordered = [chain[0], chain[3], chain[1], chain[2]];
      const result = await verifyChain(reordered);
      expect(result.valid).toBe(false);
    });

    it('reversing the chain breaks it', async () => {
      const chain = await buildChain(4);
      const reversed = [...chain].reverse();
      const result = await verifyChain(reversed);
      expect(result.valid).toBe(false);
    });

    it('duplicating an event breaks the chain', async () => {
      const chain = await buildChain(3);
      // insert duplicate of event 1 after event 1
      const duped = [chain[0], chain[1], chain[1], chain[2]];
      const result = await verifyChain(duped);
      expect(result.valid).toBe(false);
    });

    it('prepending a fake genesis breaks the chain', async () => {
      const chain = await buildChain(3);
      const fakeGenesis = await buildHashedEvent({ previousHash: null });
      const withFake = [fakeGenesis, ...chain];
      const result = await verifyChain(withFake);
      expect(result.valid).toBe(false);
      // second event should fail because its previousHash != fakeGenesis.eventHash
      expect(result.brokenAtIndex).toBe(1);
    });
  });

  // ── Genesis event ─────────────────────────────────────────────────────

  describe('genesis event', () => {
    it('getGenesisHash returns null', () => {
      expect(getGenesisHash()).toBeNull();
    });

    it('first event in chain has null previousHash', async () => {
      const chain = await buildChain(1);
      expect(chain[0].previousHash).toBeNull();
    });

    it('single genesis event verifies', async () => {
      const chain = await buildChain(1);
      const result = await verifyChain(chain);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(1);
    });

    it('genesis event with non-null previousHash fails chain verification', async () => {
      const ev = await buildHashedEvent({ previousHash: 'bb'.repeat(32) });
      const result = await verifyChain([ev]);
      expect(result.valid).toBe(false);
      expect(result.brokenAtIndex).toBe(0);
    });

    it('verifyChainLink rejects genesis with non-null previousHash', () => {
      const ev: ProofEvent = {
        eventId: uuidv4(),
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: uuidv4(),
        payload: { type: 'intent_received', intentId: 'x', action: 'a', actionType: 'r', resourceScope: [] },
        previousHash: 'something',
        eventHash: 'aa'.repeat(32),
        occurredAt: new Date(),
        recordedAt: new Date(),
      };
      expect(verifyChainLink(ev, null)).toBe(false);
    });
  });

  // ── Large chains ──────────────────────────────────────────────────────

  describe('large chains maintain integrity', () => {
    it('100-event chain verifies successfully', async () => {
      const chain = await buildChain(100);
      const result = await verifyChain(chain);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(100);
    }, 15000);

    it('150-event chain verifies successfully', async () => {
      const chain = await buildChain(150);
      const result = await verifyChain(chain);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(150);
    }, 30000); // generous timeout for slow Windows I/O

    it('tampering event 50 in a 100-event chain is detected', async () => {
      const chain = await buildChain(100);
      chain[50] = { ...chain[50], agentId: 'tampered' };
      const result = await verifyChain(chain);
      expect(result.valid).toBe(false);
      expect(result.brokenAtIndex).toBe(50);
    });
  });

  // ── Correction events ─────────────────────────────────────────────────

  describe('correction events', () => {
    it('a correction event appended to chain verifies', async () => {
      const chain = await buildChain(3);
      const correction = await buildHashedEvent({
        previousHash: chain[2].eventHash,
        eventType: ProofEventType.COMPONENT_UPDATED,
        payload: {
          type: 'component_updated',
          componentId: 'comp-1',
          changes: ['corrected score'],
        },
      });
      chain.push(correction);
      const result = await verifyChain(chain);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(4);
    });

    it('correction event references correct previousHash', async () => {
      const chain = await buildChain(2);
      const correction = await buildHashedEvent({
        previousHash: chain[1].eventHash,
        eventType: ProofEventType.COMPONENT_UPDATED,
        payload: {
          type: 'component_updated',
          componentId: 'comp-1',
          changes: ['fix'],
        },
      });
      expect(correction.previousHash).toBe(chain[1].eventHash);
    });
  });

  // ── Timestamp monotonicity ─────────────────────────────────────────────

  describe('timestamp monotonicity', () => {
    it('events emitted via ProofPlane have non-decreasing occurredAt', async () => {
      const pp = createProofPlane({ signedBy: 'ts-test' });
      const results = [];
      for (let i = 0; i < 10; i++) {
        const r = await pp.logEvent(
          ProofEventType.INTENT_RECEIVED,
          uuidv4(),
          { type: 'intent_received', intentId: uuidv4(), action: 'a', actionType: 'r', resourceScope: [] },
          'agent-1',
        );
        results.push(r.event);
      }
      for (let i = 1; i < results.length; i++) {
        expect(results[i].occurredAt.getTime()).toBeGreaterThanOrEqual(
          results[i - 1].occurredAt.getTime(),
        );
      }
    });

    it('recordedAt is always set on stored events', async () => {
      const pp = createProofPlane();
      const r = await pp.logEvent(
        ProofEventType.INTENT_RECEIVED,
        uuidv4(),
        { type: 'intent_received', intentId: 'i', action: 'a', actionType: 'r', resourceScope: [] },
      );
      expect(r.event.recordedAt).toBeInstanceOf(Date);
    });

    it('recordedAt >= occurredAt for emitted events', async () => {
      const pp = createProofPlane();
      const r = await pp.logEvent(
        ProofEventType.INTENT_RECEIVED,
        uuidv4(),
        { type: 'intent_received', intentId: 'i', action: 'a', actionType: 'r', resourceScope: [] },
      );
      expect(r.event.recordedAt.getTime()).toBeGreaterThanOrEqual(
        r.event.occurredAt.getTime(),
      );
    });
  });
});
