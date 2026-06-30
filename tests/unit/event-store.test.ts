/**
 * Event Store Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType, type ProofEvent } from '@vorionsys/contracts';
import {
  InMemoryEventStore,
  createInMemoryEventStore,
  EventStoreError,
  EventStoreErrorCode,
} from '../../src/events/index.js';

describe('InMemoryEventStore', () => {
  let store: InMemoryEventStore;

  beforeEach(() => {
    store = createInMemoryEventStore();
  });

  describe('append', () => {
    it('should append an event', async () => {
      const event = createEvent();
      const stored = await store.append(event);
      expect(stored.eventId).toBe(event.eventId);
      expect(stored.recordedAt).toBeInstanceOf(Date);
    });

    it('should reject duplicate event IDs', async () => {
      const event = createEvent();
      await store.append(event);

      await expect(store.append(event)).rejects.toThrow(EventStoreError);
      await expect(store.append(event)).rejects.toMatchObject({
        code: EventStoreErrorCode.DUPLICATE_EVENT,
      });
    });
  });

  describe('get', () => {
    it('should retrieve an event by ID', async () => {
      const event = createEvent();
      await store.append(event);

      const retrieved = await store.get(event.eventId);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.eventId).toBe(event.eventId);
    });

    it('should return null for non-existent event', async () => {
      const retrieved = await store.get(uuidv4());
      expect(retrieved).toBeNull();
    });
  });

  describe('getLatest', () => {
    it('should return null for empty store', async () => {
      const latest = await store.getLatest();
      expect(latest).toBeNull();
    });

    it('should return the most recently added event', async () => {
      const event1 = createEvent();
      const event2 = createEvent();
      const event3 = createEvent();

      await store.append(event1);
      await store.append(event2);
      await store.append(event3);

      const latest = await store.getLatest();
      expect(latest!.eventId).toBe(event3.eventId);
    });
  });

  describe('getLatestHash', () => {
    it('should return null for empty store', async () => {
      const hash = await store.getLatestHash();
      expect(hash).toBeNull();
    });

    it('should return hash of latest event', async () => {
      const event = createEvent({ eventHash: 'test-hash-' + '0'.repeat(55) });
      await store.append(event);

      const hash = await store.getLatestHash();
      expect(hash).toBe(event.eventHash);
    });
  });

  describe('query', () => {
    beforeEach(async () => {
      // Add test events
      const correlationId = uuidv4();
      const agentId = uuidv4();

      await store.append(createEvent({
        correlationId,
        agentId,
        eventType: ProofEventType.INTENT_RECEIVED,
      }));
      await store.append(createEvent({
        correlationId,
        agentId,
        eventType: ProofEventType.DECISION_MADE,
      }));
      await store.append(createEvent({
        correlationId: uuidv4(),
        agentId,
        eventType: ProofEventType.INTENT_RECEIVED,
      }));
    });

    it('should return all events without filter', async () => {
      const result = await store.query();
      expect(result.events).toHaveLength(3);
      expect(result.totalCount).toBe(3);
    });

    it('should filter by correlationId', async () => {
      const allEvents = await store.query();
      const correlationId = allEvents.events[0].correlationId;

      const result = await store.query({ correlationId });
      expect(result.events).toHaveLength(2);
      expect(result.events.every(e => e.correlationId === correlationId)).toBe(true);
    });

    it('should filter by eventTypes', async () => {
      const result = await store.query({ eventTypes: [ProofEventType.INTENT_RECEIVED] });
      expect(result.events).toHaveLength(2);
      expect(result.events.every(e => e.eventType === ProofEventType.INTENT_RECEIVED)).toBe(true);
    });

    it('should support pagination', async () => {
      const result1 = await store.query({}, { limit: 2, offset: 0 });
      expect(result1.events).toHaveLength(2);
      expect(result1.hasMore).toBe(true);

      const result2 = await store.query({}, { limit: 2, offset: 2 });
      expect(result2.events).toHaveLength(1);
      expect(result2.hasMore).toBe(false);
    });

    it('should support descending order', async () => {
      const asc = await store.query({}, { order: 'asc' });
      const desc = await store.query({}, { order: 'desc' });

      expect(asc.events[0].eventId).toBe(desc.events[2].eventId);
      expect(asc.events[2].eventId).toBe(desc.events[0].eventId);
    });
  });

  describe('getByCorrelationId', () => {
    it('should return events for a correlation ID', async () => {
      const correlationId = uuidv4();
      await store.append(createEvent({ correlationId }));
      await store.append(createEvent({ correlationId }));
      await store.append(createEvent({ correlationId: uuidv4() }));

      const events = await store.getByCorrelationId(correlationId);
      expect(events).toHaveLength(2);
    });
  });

  describe('getByAgentId', () => {
    it('should return events for an agent', async () => {
      const agentId = uuidv4();
      await store.append(createEvent({ agentId }));
      await store.append(createEvent({ agentId }));
      await store.append(createEvent({ agentId: uuidv4() }));

      const events = await store.getByAgentId(agentId);
      expect(events).toHaveLength(2);
    });
  });

  describe('getByTimeRange', () => {
    it('should return events in time range', async () => {
      const now = new Date();
      const past = new Date(now.getTime() - 100000);
      const future = new Date(now.getTime() + 100000);

      await store.append(createEvent({ occurredAt: past }));
      await store.append(createEvent({ occurredAt: now }));
      await store.append(createEvent({ occurredAt: future }));

      const events = await store.getByTimeRange(
        new Date(past.getTime() - 1000),
        new Date(now.getTime() + 1000)
      );
      expect(events).toHaveLength(2);
    });
  });

  describe('getByType', () => {
    it('should return events of a specific type', async () => {
      await store.append(createEvent({ eventType: ProofEventType.INTENT_RECEIVED }));
      await store.append(createEvent({ eventType: ProofEventType.DECISION_MADE }));
      await store.append(createEvent({ eventType: ProofEventType.INTENT_RECEIVED }));

      const events = await store.getByType(ProofEventType.INTENT_RECEIVED);
      expect(events).toHaveLength(2);
    });
  });

  describe('getSummaries', () => {
    it('should return event summaries', async () => {
      await store.append(createEvent());
      await store.append(createEvent());

      const summaries = await store.getSummaries();
      expect(summaries).toHaveLength(2);
      expect(summaries[0]).toHaveProperty('eventId');
      expect(summaries[0]).toHaveProperty('eventType');
      expect(summaries[0]).toHaveProperty('correlationId');
    });
  });

  describe('getChain', () => {
    it('should return events in order', async () => {
      const event1 = createEvent();
      const event2 = createEvent();
      const event3 = createEvent();

      await store.append(event1);
      await store.append(event2);
      await store.append(event3);

      const chain = await store.getChain();
      expect(chain).toHaveLength(3);
      expect(chain[0].eventId).toBe(event1.eventId);
      expect(chain[2].eventId).toBe(event3.eventId);
    });

    it('should return events from a starting point', async () => {
      const event1 = createEvent();
      const event2 = createEvent();
      const event3 = createEvent();

      await store.append(event1);
      await store.append(event2);
      await store.append(event3);

      const chain = await store.getChain(event2.eventId);
      expect(chain).toHaveLength(2);
      expect(chain[0].eventId).toBe(event2.eventId);
    });

    it('should limit results', async () => {
      await store.append(createEvent());
      await store.append(createEvent());
      await store.append(createEvent());

      const chain = await store.getChain(undefined, 2);
      expect(chain).toHaveLength(2);
    });
  });

  describe('count', () => {
    it('should return total count', async () => {
      await store.append(createEvent());
      await store.append(createEvent());
      await store.append(createEvent());

      const count = await store.count();
      expect(count).toBe(3);
    });

    it('should return filtered count', async () => {
      const agentId = uuidv4();
      await store.append(createEvent({ agentId }));
      await store.append(createEvent({ agentId }));
      await store.append(createEvent({ agentId: uuidv4() }));

      const count = await store.count({ agentId });
      expect(count).toBe(2);
    });
  });

  describe('getStats', () => {
    it('should return statistics', async () => {
      const agentId = uuidv4();
      await store.append(createEvent({
        agentId,
        eventType: ProofEventType.INTENT_RECEIVED,
      }));
      await store.append(createEvent({
        agentId,
        eventType: ProofEventType.DECISION_MADE,
      }));
      await store.append(createEvent({
        agentId: uuidv4(),
        eventType: ProofEventType.INTENT_RECEIVED,
      }));

      const stats = await store.getStats();
      expect(stats.totalEvents).toBe(3);
      expect(stats.byType[ProofEventType.INTENT_RECEIVED]).toBe(2);
      expect(stats.byType[ProofEventType.DECISION_MADE]).toBe(1);
      expect(stats.byAgent[agentId]).toBe(2);
    });
  });

  describe('exists', () => {
    it('should return true for existing event', async () => {
      const event = createEvent();
      await store.append(event);

      const exists = await store.exists(event.eventId);
      expect(exists).toBe(true);
    });

    it('should return false for non-existent event', async () => {
      const exists = await store.exists(uuidv4());
      expect(exists).toBe(false);
    });
  });

  describe('clear', () => {
    it('should remove all events', async () => {
      await store.append(createEvent());
      await store.append(createEvent());

      await store.clear();

      const count = await store.count();
      expect(count).toBe(0);
    });
  });
});

// Test helper

function createEvent(overrides: Partial<ProofEvent> = {}): ProofEvent {
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
    eventHash: uuidv4() + uuidv4(), // Fake 64-char hash
    occurredAt: new Date(),
    recordedAt: new Date(),
    signedBy: 'test',
    ...overrides,
  };
}
