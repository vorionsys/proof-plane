/**
 * Store & Emission Tests
 *
 * Production-hardening tests for the in-memory event store
 * and the proof event emitter, covering edge cases in storage,
 * chain linking, batch emission, and concurrency.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType, type ProofEvent, type ProofEventPayload } from '@vorionsys/contracts';
import { InMemoryEventStore } from '../src/events/memory-store.js';
import { ProofEventEmitter } from '../src/events/event-emitter.js';
import { computeEventHash, computeEventHash3 } from '../src/events/hash-chain.js';
import { EventStoreError, EventStoreErrorCode } from '../src/events/event-store.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function makePayload(action = 'read-file'): ProofEventPayload {
  return {
    type: 'intent_received',
    intentId: uuidv4(),
    action,
    actionType: 'read',
    resourceScope: ['/data'],
  };
}

function makeEvent(overrides: Partial<ProofEvent> = {}): ProofEvent {
  return {
    eventId: uuidv4(),
    eventType: ProofEventType.INTENT_RECEIVED,
    correlationId: uuidv4(),
    agentId: 'agent-01',
    payload: makePayload(),
    previousHash: null,
    eventHash: uuidv4(), // placeholder hash
    occurredAt: new Date('2026-01-15T10:00:00Z'),
    recordedAt: new Date('2026-01-15T10:00:01Z'),
    ...overrides,
  } as ProofEvent;
}

// ─── InMemoryEventStore ─────────────────────────────────────────────────────

describe('InMemoryEventStore', () => {
  let store: InMemoryEventStore;

  beforeEach(() => {
    store = new InMemoryEventStore();
  });

  describe('append and retrieve', () => {
    it('appends an event and retrieves it by ID', async () => {
      const event = makeEvent();
      await store.append(event);
      const retrieved = await store.get(event.eventId);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.eventId).toBe(event.eventId);
    });

    it('sets recordedAt on appended event', async () => {
      const event = makeEvent({ recordedAt: undefined as unknown as Date });
      const stored = await store.append(event);
      expect(stored.recordedAt).toBeDefined();
    });

    it('preserves all event fields', async () => {
      const event = makeEvent({ agentId: 'agent-99', signedBy: 'signer-1' });
      await store.append(event);
      const retrieved = await store.get(event.eventId);
      expect(retrieved!.agentId).toBe('agent-99');
      expect(retrieved!.signedBy).toBe('signer-1');
    });

    it('getLatest returns the most recently appended event', async () => {
      const e1 = makeEvent();
      const e2 = makeEvent();
      await store.append(e1);
      await store.append(e2);
      const latest = await store.getLatest();
      expect(latest!.eventId).toBe(e2.eventId);
    });
  });

  describe('duplicate event ID rejection', () => {
    it('rejects duplicate event ID with EventStoreError', async () => {
      const event = makeEvent();
      await store.append(event);
      await expect(store.append(event)).rejects.toThrow(EventStoreError);
    });

    it('error has DUPLICATE_EVENT code', async () => {
      const event = makeEvent();
      await store.append(event);
      try {
        await store.append(event);
        expect.unreachable('should have thrown');
      } catch (err) {
        expect((err as EventStoreError).code).toBe(EventStoreErrorCode.DUPLICATE_EVENT);
      }
    });

    it('different IDs with same content are accepted', async () => {
      const e1 = makeEvent();
      const e2 = makeEvent({ eventId: uuidv4() });
      await store.append(e1);
      await store.append(e2);
      expect(await store.count()).toBe(2);
    });
  });

  describe('query with multiple filters', () => {
    it('filters by agentId', async () => {
      await store.append(makeEvent({ agentId: 'agent-A' }));
      await store.append(makeEvent({ agentId: 'agent-B' }));
      await store.append(makeEvent({ agentId: 'agent-A' }));
      const result = await store.query({ agentId: 'agent-A' });
      expect(result.events.length).toBe(2);
    });

    it('filters by eventType', async () => {
      await store.append(makeEvent({ eventType: ProofEventType.INTENT_RECEIVED }));
      await store.append(makeEvent({ eventType: ProofEventType.TRUST_DELTA }));
      await store.append(makeEvent({ eventType: ProofEventType.INTENT_RECEIVED }));
      const result = await store.query({ eventTypes: [ProofEventType.TRUST_DELTA] });
      expect(result.events.length).toBe(1);
    });

    it('filters by time range', async () => {
      const e1 = makeEvent({ occurredAt: new Date('2026-01-01') });
      const e2 = makeEvent({ occurredAt: new Date('2026-06-15') });
      const e3 = makeEvent({ occurredAt: new Date('2026-12-31') });
      await store.append(e1);
      await store.append(e2);
      await store.append(e3);
      const result = await store.query({
        from: new Date('2026-03-01'),
        to: new Date('2026-09-01'),
      });
      expect(result.events.length).toBe(1);
      expect(result.events[0].eventId).toBe(e2.eventId);
    });

    it('combines agentId + eventType filters', async () => {
      await store.append(makeEvent({ agentId: 'A', eventType: ProofEventType.INTENT_RECEIVED }));
      await store.append(makeEvent({ agentId: 'A', eventType: ProofEventType.TRUST_DELTA }));
      await store.append(makeEvent({ agentId: 'B', eventType: ProofEventType.INTENT_RECEIVED }));
      const result = await store.query({
        agentId: 'A',
        eventTypes: [ProofEventType.INTENT_RECEIVED],
      });
      expect(result.events.length).toBe(1);
    });

    it('combines agentId + eventType + timeRange', async () => {
      await store.append(makeEvent({
        agentId: 'A',
        eventType: ProofEventType.INTENT_RECEIVED,
        occurredAt: new Date('2026-06-01'),
      }));
      await store.append(makeEvent({
        agentId: 'A',
        eventType: ProofEventType.INTENT_RECEIVED,
        occurredAt: new Date('2026-01-01'),
      }));
      const result = await store.query({
        agentId: 'A',
        eventTypes: [ProofEventType.INTENT_RECEIVED],
        from: new Date('2026-05-01'),
        to: new Date('2026-07-01'),
      });
      expect(result.events.length).toBe(1);
    });
  });

  describe('pagination', () => {
    it('limit restricts result count', async () => {
      for (let i = 0; i < 10; i++) {
        await store.append(makeEvent());
      }
      const result = await store.query(undefined, { limit: 3 });
      expect(result.events.length).toBe(3);
      expect(result.hasMore).toBe(true);
      expect(result.totalCount).toBe(10);
    });

    it('offset skips events', async () => {
      const events: ProofEvent[] = [];
      for (let i = 0; i < 5; i++) {
        const e = makeEvent();
        events.push(e);
        await store.append(e);
      }
      const result = await store.query(undefined, { offset: 3, limit: 10 });
      expect(result.events.length).toBe(2);
      expect(result.events[0].eventId).toBe(events[3].eventId);
    });

    it('offset >= count returns empty', async () => {
      await store.append(makeEvent());
      await store.append(makeEvent());
      const result = await store.query(undefined, { offset: 5, limit: 10 });
      expect(result.events.length).toBe(0);
      expect(result.hasMore).toBe(false);
    });

    it('offset + limit combined', async () => {
      for (let i = 0; i < 10; i++) {
        await store.append(makeEvent());
      }
      const result = await store.query(undefined, { offset: 2, limit: 3 });
      expect(result.events.length).toBe(3);
      expect(result.hasMore).toBe(true);
    });
  });

  describe('stats', () => {
    it('empty store has zero stats', async () => {
      const stats = await store.getStats();
      expect(stats.totalEvents).toBe(0);
      expect(Object.keys(stats.byType).length).toBe(0);
      expect(Object.keys(stats.byAgent).length).toBe(0);
    });

    it('counts total events', async () => {
      await store.append(makeEvent());
      await store.append(makeEvent());
      await store.append(makeEvent());
      const stats = await store.getStats();
      expect(stats.totalEvents).toBe(3);
    });

    it('groups by type', async () => {
      await store.append(makeEvent({ eventType: ProofEventType.INTENT_RECEIVED }));
      await store.append(makeEvent({ eventType: ProofEventType.INTENT_RECEIVED }));
      await store.append(makeEvent({ eventType: ProofEventType.TRUST_DELTA }));
      const stats = await store.getStats();
      expect(stats.byType[ProofEventType.INTENT_RECEIVED]).toBe(2);
      expect(stats.byType[ProofEventType.TRUST_DELTA]).toBe(1);
    });

    it('groups by agent', async () => {
      await store.append(makeEvent({ agentId: 'agent-X' }));
      await store.append(makeEvent({ agentId: 'agent-X' }));
      await store.append(makeEvent({ agentId: 'agent-Y' }));
      const stats = await store.getStats();
      expect(stats.byAgent['agent-X']).toBe(2);
      expect(stats.byAgent['agent-Y']).toBe(1);
    });
  });

  describe('getLatestHash', () => {
    it('returns null for empty store', async () => {
      expect(await store.getLatestHash()).toBeNull();
    });

    it('returns hash of most recent event', async () => {
      const e1 = makeEvent({ eventHash: 'hash-one' });
      const e2 = makeEvent({ eventHash: 'hash-two' });
      await store.append(e1);
      await store.append(e2);
      expect(await store.getLatestHash()).toBe('hash-two');
    });
  });

  describe('empty store behavior', () => {
    it('get returns null for nonexistent ID', async () => {
      expect(await store.get('nonexistent')).toBeNull();
    });

    it('getLatest returns null', async () => {
      expect(await store.getLatest()).toBeNull();
    });

    it('query returns empty result', async () => {
      const result = await store.query();
      expect(result.events.length).toBe(0);
      expect(result.totalCount).toBe(0);
      expect(result.hasMore).toBe(false);
    });

    it('count returns 0', async () => {
      expect(await store.count()).toBe(0);
    });

    it('exists returns false', async () => {
      expect(await store.exists('anything')).toBe(false);
    });
  });

  describe('clear', () => {
    it('removes all events', async () => {
      await store.append(makeEvent());
      await store.append(makeEvent());
      expect(await store.count()).toBe(2);
      await store.clear();
      expect(await store.count()).toBe(0);
      expect(await store.getLatest()).toBeNull();
    });

    it('store is usable after clear', async () => {
      await store.append(makeEvent());
      await store.clear();
      const newEvent = makeEvent();
      await store.append(newEvent);
      expect(await store.count()).toBe(1);
      expect((await store.get(newEvent.eventId))!.eventId).toBe(newEvent.eventId);
    });
  });

  describe('getChain', () => {
    it('returns all events in order', async () => {
      const e1 = makeEvent();
      const e2 = makeEvent();
      await store.append(e1);
      await store.append(e2);
      const chain = await store.getChain();
      expect(chain.length).toBe(2);
      expect(chain[0].eventId).toBe(e1.eventId);
      expect(chain[1].eventId).toBe(e2.eventId);
    });

    it('returns events from a starting point', async () => {
      const e1 = makeEvent();
      const e2 = makeEvent();
      const e3 = makeEvent();
      await store.append(e1);
      await store.append(e2);
      await store.append(e3);
      const chain = await store.getChain(e2.eventId);
      expect(chain.length).toBe(2);
      expect(chain[0].eventId).toBe(e2.eventId);
    });

    it('returns empty for unknown starting event', async () => {
      await store.append(makeEvent());
      const chain = await store.getChain('nonexistent');
      expect(chain.length).toBe(0);
    });
  });
});

// ─── ProofEventEmitter ──────────────────────────────────────────────────────

describe('ProofEventEmitter', () => {
  let store: InMemoryEventStore;
  let emitter: ProofEventEmitter;

  beforeEach(() => {
    store = new InMemoryEventStore();
    emitter = new ProofEventEmitter({ store });
  });

  describe('event creation', () => {
    it('creates an event with correct fields', async () => {
      const result = await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'corr-1',
        agentId: 'agent-01',
        payload: makePayload(),
        occurredAt: new Date('2026-03-01'),
      });
      expect(result.event.eventId).toBeDefined();
      expect(result.event.eventType).toBe(ProofEventType.INTENT_RECEIVED);
      expect(result.event.correlationId).toBe('corr-1');
      expect(result.event.agentId).toBe('agent-01');
      expect(result.event.eventHash).toMatch(/^[0-9a-f]{64}$/);
      expect(result.event.eventHash3).toMatch(/^[0-9a-f]{64}$/);
    });

    it('first event has null previousHash', async () => {
      const result = await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'corr-1',
        payload: makePayload(),
      });
      expect(result.event.previousHash).toBeNull();
      expect(result.isGenesis).toBe(true);
    });

    it('second event chains to first event hash', async () => {
      const first = await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'corr-1',
        payload: makePayload(),
      });
      const second = await emitter.emit({
        eventType: ProofEventType.DECISION_MADE,
        correlationId: 'corr-1',
        payload: {
          type: 'decision_made',
          decisionId: uuidv4(),
          intentId: uuidv4(),
          permitted: true,
          trustBand: 'T4',
          trustScore: 700,
          reasoning: ['approved'],
        },
      });
      expect(second.event.previousHash).toBe(first.event.eventHash);
      expect(second.isGenesis).toBe(false);
    });

    it('third event chains to second event hash', async () => {
      await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'c',
        payload: makePayload(),
      });
      const second = await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'c',
        payload: makePayload(),
      });
      const third = await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'c',
        payload: makePayload(),
      });
      expect(third.event.previousHash).toBe(second.event.eventHash);
    });

    it('event hash is verifiable', async () => {
      const result = await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'corr-v',
        payload: makePayload(),
      });
      const recomputed = await computeEventHash(result.event);
      expect(recomputed).toBe(result.event.eventHash);
    });

    it('event hash3 is verifiable', async () => {
      const result = await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'corr-v3',
        payload: makePayload(),
      });
      const recomputed = computeEventHash3(result.event);
      expect(recomputed).toBe(result.event.eventHash3);
    });

    it('event is stored in the store', async () => {
      const result = await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'stored-test',
        payload: makePayload(),
      });
      const fromStore = await store.get(result.event.eventId);
      expect(fromStore).not.toBeNull();
      expect(fromStore!.eventHash).toBe(result.event.eventHash);
    });
  });

  describe('batch emission', () => {
    it('emits multiple events in a batch', async () => {
      const requests = Array.from({ length: 5 }, () => ({
        eventType: ProofEventType.INTENT_RECEIVED as ProofEventType,
        correlationId: uuidv4(),
        payload: makePayload(),
      }));
      const result = await emitter.emitBatch(requests);
      expect(result.success).toBe(true);
      expect(result.events.length).toBe(5);
      expect(result.errors.length).toBe(0);
    });

    it('batch events form a valid chain', async () => {
      const requests = Array.from({ length: 4 }, () => ({
        eventType: ProofEventType.INTENT_RECEIVED as ProofEventType,
        correlationId: uuidv4(),
        payload: makePayload(),
      }));
      const result = await emitter.emitBatch(requests);
      // Check chain linking
      expect(result.events[0].previousHash).toBeNull();
      for (let i = 1; i < result.events.length; i++) {
        expect(result.events[i].previousHash).toBe(result.events[i - 1].eventHash);
      }
    });

    it('batch with shared correlationId uses the option', async () => {
      const sharedCorr = 'batch-corr-shared';
      const requests = [
        { eventType: ProofEventType.INTENT_RECEIVED as ProofEventType, correlationId: 'ignored', payload: makePayload() },
        { eventType: ProofEventType.INTENT_RECEIVED as ProofEventType, correlationId: 'ignored', payload: makePayload() },
      ];
      const result = await emitter.emitBatch(requests, { correlationId: sharedCorr });
      for (const event of result.events) {
        expect(event.correlationId).toBe(sharedCorr);
      }
    });
  });

  describe('listener notification', () => {
    it('listener is called on emit', async () => {
      const received: ProofEvent[] = [];
      emitter.addListener((event) => { received.push(event); });
      await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'listen-test',
        payload: makePayload(),
      });
      expect(received.length).toBe(1);
      expect(received[0].correlationId).toBe('listen-test');
    });

    it('multiple listeners are all notified', async () => {
      let count1 = 0;
      let count2 = 0;
      emitter.addListener(() => { count1++; });
      emitter.addListener(() => { count2++; });
      await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'multi-listen',
        payload: makePayload(),
      });
      expect(count1).toBe(1);
      expect(count2).toBe(1);
    });

    it('removed listener is not called', async () => {
      let called = false;
      const listener = () => { called = true; };
      emitter.addListener(listener);
      emitter.removeListener(listener);
      await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'removed-listen',
        payload: makePayload(),
      });
      expect(called).toBe(false);
    });

    it('listener error does not prevent event creation', async () => {
      emitter.addListener(() => { throw new Error('listener boom'); });
      const result = await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'error-listen',
        payload: makePayload(),
      });
      expect(result.event).toBeDefined();
      const stored = await store.get(result.event.eventId);
      expect(stored).not.toBeNull();
    });
  });

  describe('shadow mode', () => {
    it('default emitter is not in shadow mode', () => {
      expect(emitter.isShadowMode()).toBe(false);
      expect(emitter.getShadowMode()).toBe('production');
    });

    it('shadow mode emitter tags events', async () => {
      const shadowEmitter = new ProofEventEmitter({
        store,
        shadowMode: 'shadow',
      });
      expect(shadowEmitter.isShadowMode()).toBe(true);
      const result = await shadowEmitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'shadow-test',
        payload: makePayload(),
      });
      expect(result.event.shadowMode).toBe('shadow');
    });

    it('testnet mode emitter tags events as testnet', async () => {
      const testnetEmitter = new ProofEventEmitter({
        store,
        shadowMode: 'testnet',
      });
      expect(testnetEmitter.getShadowMode()).toBe('testnet');
      const result = await testnetEmitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'testnet-test',
        payload: makePayload(),
      });
      expect(result.event.shadowMode).toBe('testnet');
    });

    it('production emitter does not set shadowMode on events', async () => {
      const result = await emitter.emit({
        eventType: ProofEventType.INTENT_RECEIVED,
        correlationId: 'prod-test',
        payload: makePayload(),
      });
      expect(result.event.shadowMode).toBeUndefined();
    });
  });

  describe('concurrent rapid emissions', () => {
    it('10 parallel emits produce valid chain without corruption', async () => {
      const promises = Array.from({ length: 10 }, (_, i) =>
        emitter.emit({
          eventType: ProofEventType.INTENT_RECEIVED,
          correlationId: `concurrent-${i}`,
          payload: makePayload(`action-${i}`),
        }),
      );
      const results = await Promise.all(promises);
      expect(results.length).toBe(10);
      expect(await store.count()).toBe(10);

      // Verify chain integrity: each event (after first) references the previous
      const chain = await store.getChain();
      expect(chain[0].previousHash).toBeNull();
      for (let i = 1; i < chain.length; i++) {
        expect(chain[i].previousHash).toBe(chain[i - 1].eventHash);
      }
    });

    it('20 parallel emits all succeed with unique event IDs', async () => {
      const promises = Array.from({ length: 20 }, (_, i) =>
        emitter.emit({
          eventType: ProofEventType.INTENT_RECEIVED,
          correlationId: `rapid-${i}`,
          payload: makePayload(),
        }),
      );
      const results = await Promise.all(promises);
      const ids = new Set(results.map(r => r.event.eventId));
      expect(ids.size).toBe(20);
    });
  });

  describe('emitTyped helper', () => {
    it('creates event with specified type', async () => {
      const result = await emitter.emitTyped(
        ProofEventType.TRUST_DELTA,
        'typed-corr',
        {
          type: 'trust_delta',
          deltaId: uuidv4(),
          previousScore: 100,
          newScore: 150,
          previousBand: 'T0',
          newBand: 'T0',
          reason: 'test delta',
        },
        'agent-typed',
      );
      expect(result.event.eventType).toBe(ProofEventType.TRUST_DELTA);
      expect(result.event.agentId).toBe('agent-typed');
      expect(result.event.correlationId).toBe('typed-corr');
    });
  });

  describe('getStore', () => {
    it('returns the underlying store', () => {
      expect(emitter.getStore()).toBe(store);
    });
  });
});
