/**
 * Hash Chain Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType, type ProofEvent } from '@vorionsys/contracts';
import {
  sha256,
  computeEventHash,
  verifyEventHash,
  verifyChainLink,
  verifyChain,
  verifyChainWithDetails,
  getGenesisHash,
} from '../../src/events/hash-chain.js';

describe('Hash Chain', () => {
  describe('sha256', () => {
    it('should produce consistent hashes', async () => {
      const data = 'test data';
      const hash1 = await sha256(data);
      const hash2 = await sha256(data);
      expect(hash1).toBe(hash2);
    });

    it('should produce 64 character hex strings', async () => {
      const hash = await sha256('test');
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('should produce different hashes for different data', async () => {
      const hash1 = await sha256('data1');
      const hash2 = await sha256('data2');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('computeEventHash', () => {
    it('should compute hash for an event', async () => {
      const event = createTestEvent();
      const hash = await computeEventHash(event);
      expect(hash).toHaveLength(64);
    });

    it('should produce consistent hashes for same event', async () => {
      const event = createTestEvent();
      const hash1 = await computeEventHash(event);
      const hash2 = await computeEventHash(event);
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different events', async () => {
      const event1 = createTestEvent();
      const event2 = createTestEvent({ eventId: uuidv4() });
      const hash1 = await computeEventHash(event1);
      const hash2 = await computeEventHash(event2);
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyEventHash', () => {
    it('should verify valid event hash', async () => {
      const event = createTestEvent();
      const hash = await computeEventHash(event);
      const fullEvent: ProofEvent = {
        ...event,
        eventHash: hash,
        recordedAt: new Date(),
      };
      const valid = await verifyEventHash(fullEvent);
      expect(valid).toBe(true);
    });

    it('should reject invalid event hash', async () => {
      const event = createTestEvent();
      const fullEvent: ProofEvent = {
        ...event,
        eventHash: 'invalid-hash-0000000000000000000000000000000000000000000000',
        recordedAt: new Date(),
      };
      const valid = await verifyEventHash(fullEvent);
      expect(valid).toBe(false);
    });

    it('should detect tampered payload', async () => {
      // Create original event
      const originalEvent = createTestEvent();
      const originalHash = await computeEventHash(originalEvent);

      // Create a tampered version with different intentId
      const tamperedPayload = {
        type: 'intent_received' as const,
        intentId: uuidv4(), // Different intentId
        action: (originalEvent.payload as { action: string }).action,
        actionType: (originalEvent.payload as { actionType: string }).actionType,
        resourceScope: (originalEvent.payload as { resourceScope: string[] }).resourceScope,
      };

      // Event with original hash but tampered payload
      const tamperedEvent: ProofEvent = {
        eventId: originalEvent.eventId,
        eventType: originalEvent.eventType,
        correlationId: originalEvent.correlationId,
        agentId: originalEvent.agentId,
        payload: tamperedPayload,
        previousHash: originalEvent.previousHash,
        occurredAt: originalEvent.occurredAt,
        eventHash: originalHash, // Hash from original payload
        recordedAt: new Date(),
        signedBy: originalEvent.signedBy,
      };

      const valid = await verifyEventHash(tamperedEvent);
      expect(valid).toBe(false);
    });
  });

  describe('verifyChainLink', () => {
    it('should verify genesis event (null previous)', () => {
      const genesisEvent = createFullEvent({ previousHash: null });
      const valid = verifyChainLink(genesisEvent, null);
      expect(valid).toBe(true);
    });

    it('should verify linked events', () => {
      const firstEvent = createFullEvent({ previousHash: null, eventHash: 'hash1' });
      const secondEvent = createFullEvent({ previousHash: 'hash1' });
      const valid = verifyChainLink(secondEvent, firstEvent);
      expect(valid).toBe(true);
    });

    it('should reject broken chain link', () => {
      const firstEvent = createFullEvent({ previousHash: null, eventHash: 'hash1' });
      const secondEvent = createFullEvent({ previousHash: 'wrong-hash' });
      const valid = verifyChainLink(secondEvent, firstEvent);
      expect(valid).toBe(false);
    });

    it('should reject genesis event with non-null previous', () => {
      const event = createFullEvent({ previousHash: 'some-hash' });
      const valid = verifyChainLink(event, null);
      expect(valid).toBe(false);
    });
  });

  describe('verifyChain', () => {
    it('should verify empty chain', async () => {
      const result = await verifyChain([]);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(0);
    });

    it('should verify single event chain', async () => {
      const event = await createHashedEvent({ previousHash: null });
      const result = await verifyChain([event]);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(1);
    });

    it('should verify multi-event chain', async () => {
      const event1 = await createHashedEvent({ previousHash: null });
      const event2 = await createHashedEvent({ previousHash: event1.eventHash });
      const event3 = await createHashedEvent({ previousHash: event2.eventHash });

      const result = await verifyChain([event1, event2, event3]);
      expect(result.valid).toBe(true);
      expect(result.verifiedCount).toBe(3);
    });

    it('should detect broken hash', async () => {
      const event1 = await createHashedEvent({ previousHash: null });
      const event2: ProofEvent = {
        ...await createHashedEvent({ previousHash: event1.eventHash }),
        eventHash: 'tampered-hash-00000000000000000000000000000000000000000000',
      };

      const result = await verifyChain([event1, event2]);
      expect(result.valid).toBe(false);
      expect(result.brokenAtIndex).toBe(1);
    });

    it('should detect broken chain link', async () => {
      const event1 = await createHashedEvent({ previousHash: null });
      const event2 = await createHashedEvent({ previousHash: 'wrong-previous-hash' });

      const result = await verifyChain([event1, event2]);
      expect(result.valid).toBe(false);
      expect(result.brokenAtIndex).toBe(1);
    });
  });

  describe('verifyChainWithDetails', () => {
    it('should return detailed results for valid chain', async () => {
      const event1 = await createHashedEvent({ previousHash: null });
      const event2 = await createHashedEvent({ previousHash: event1.eventHash });

      const result = await verifyChainWithDetails([event1, event2]);
      expect(result.valid).toBe(true);
      expect(result.totalEvents).toBe(2);
      expect(result.verifiedCount).toBe(2);
      expect(result.firstEventId).toBe(event1.eventId);
      expect(result.lastEventId).toBe(event2.eventId);
    });

    it('should return detailed results for invalid chain', async () => {
      const event1 = await createHashedEvent({ previousHash: null });
      const event2: ProofEvent = {
        ...await createHashedEvent({ previousHash: event1.eventHash }),
        eventHash: 'bad-hash-0000000000000000000000000000000000000000000000000',
      };

      const result = await verifyChainWithDetails([event1, event2]);
      expect(result.valid).toBe(false);
      expect(result.brokenAtEventId).toBe(event2.eventId);
      expect(result.brokenAtIndex).toBe(1);
      expect(result.error).toContain('invalid SHA-256 hash');
    });
  });

  describe('getGenesisHash', () => {
    it('should return null', () => {
      expect(getGenesisHash()).toBeNull();
    });
  });
});

// Test helpers

function createTestEvent(
  overrides: Partial<Omit<ProofEvent, 'eventHash' | 'recordedAt'>> = {}
): Omit<ProofEvent, 'eventHash' | 'recordedAt'> {
  return {
    eventId: uuidv4(),
    eventType: ProofEventType.INTENT_RECEIVED,
    correlationId: uuidv4(),
    agentId: uuidv4(),
    payload: {
      type: 'intent_received',
      intentId: uuidv4(),
      action: 'test-action',
      actionType: 'read',
      resourceScope: ['test'],
    },
    previousHash: null,
    occurredAt: new Date('2026-01-01T00:00:00Z'),
    signedBy: 'test',
    ...overrides,
  };
}

function createFullEvent(
  overrides: Partial<ProofEvent> = {}
): ProofEvent {
  return {
    eventId: uuidv4(),
    eventType: ProofEventType.INTENT_RECEIVED,
    correlationId: uuidv4(),
    agentId: uuidv4(),
    payload: {
      type: 'intent_received',
      intentId: uuidv4(),
      action: 'test-action',
      actionType: 'read',
      resourceScope: ['test'],
    },
    previousHash: null,
    eventHash: 'a'.repeat(64),
    occurredAt: new Date('2026-01-01T00:00:00Z'),
    recordedAt: new Date('2026-01-01T00:00:00Z'),
    signedBy: 'test',
    ...overrides,
  };
}

async function createHashedEvent(
  overrides: Partial<Omit<ProofEvent, 'eventHash' | 'recordedAt'>> = {}
): Promise<ProofEvent> {
  const event = createTestEvent(overrides);
  const eventHash = await computeEventHash(event);
  return {
    ...event,
    eventHash,
    recordedAt: new Date(),
  };
}
