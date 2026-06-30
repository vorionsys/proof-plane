/**
 * CockroachEventStore Tests
 *
 * Unit tests that mock pg.Pool to verify SQL generation, error mapping,
 * and interface compliance without requiring a live database.
 *
 * Integration tests against a real CockroachDB/PostgreSQL instance
 * should be added under tests/integration/ and gated by vitest.config.infra.ts.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType, type ProofEvent } from '@vorionsys/contracts';
import {
  CockroachEventStore,
  createCockroachEventStore,
  EventStoreError,
  EventStoreErrorCode,
} from '../src/index.js';

// ─── Mock Pool ──────────────────────────────────────────────────────────────

function createMockPool() {
  const queryFn = vi.fn();
  return {
    query: queryFn,
    // Expose for test assertions
    _query: queryFn,
  };
}

type MockPool = ReturnType<typeof createMockPool>;

// ─── Helpers ────────────────────────────────────────────────────────────────

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
    eventHash: uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, ''),
    occurredAt: new Date('2026-04-01T00:00:00Z'),
    recordedAt: new Date('2026-04-01T00:00:01Z'),
    signedBy: 'test-signer',
    ...overrides,
  };
}

/** Return a row matching the shape CockroachDB would return. */
function eventToRow(event: ProofEvent, seq = 1) {
  return {
    event_id: event.eventId,
    event_type: event.eventType,
    correlation_id: event.correlationId,
    agent_id: event.agentId ?? null,
    payload: event.payload,
    previous_hash: event.previousHash,
    event_hash: event.eventHash,
    event_hash3: event.eventHash3 ?? null,
    occurred_at: event.occurredAt.toISOString(),
    recorded_at: (event.recordedAt ?? new Date()).toISOString(),
    signed_by: event.signedBy ?? null,
    signature: event.signature ?? null,
    shadow_mode: event.shadowMode ?? 'production',
    verification_id: event.verificationId ?? null,
    verified_at: event.verifiedAt?.toISOString() ?? null,
    seq,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('CockroachEventStore', () => {
  let pool: MockPool;
  let store: CockroachEventStore;

  beforeEach(() => {
    pool = createMockPool();
    // autoMigrate: false to skip CREATE TABLE in every test
    store = createCockroachEventStore(pool as unknown as import('pg').Pool, {
      autoMigrate: false,
    });
  });

  // ── Factory ────────────────────────────────────────────────────────────

  it('createCockroachEventStore returns a CockroachEventStore', () => {
    expect(store).toBeInstanceOf(CockroachEventStore);
  });

  // ── Append ─────────────────────────────────────────────────────────────

  describe('append', () => {
    it('inserts event and returns mapped result', async () => {
      const event = createEvent();
      const row = eventToRow(event);
      pool._query.mockResolvedValueOnce({ rows: [row] });

      const stored = await store.append(event);

      expect(stored.eventId).toBe(event.eventId);
      expect(stored.eventType).toBe(event.eventType);
      expect(stored.correlationId).toBe(event.correlationId);
      expect(stored.agentId).toBe(event.agentId);
      expect(stored.eventHash).toBe(event.eventHash);

      // Verify INSERT was called with correct params
      const [sql, params] = pool._query.mock.calls[0];
      expect(sql).toContain('INSERT INTO proof_events');
      expect(params[0]).toBe(event.eventId);
    });

    it('maps pg unique violation to DUPLICATE_EVENT', async () => {
      const event = createEvent();
      pool._query.mockRejectedValueOnce(
        Object.assign(new Error('duplicate key'), { code: '23505' }),
      );

      try {
        await store.append(event);
        expect.unreachable('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(EventStoreError);
        expect((err as EventStoreError).code).toBe(EventStoreErrorCode.DUPLICATE_EVENT);
        expect((err as EventStoreError).eventId).toBe(event.eventId);
      }
    });

    it('maps generic pg errors to STORAGE_ERROR', async () => {
      const event = createEvent();
      pool._query.mockRejectedValueOnce(new Error('connection lost'));

      try {
        await store.append(event);
        expect.unreachable('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(EventStoreError);
        expect((err as EventStoreError).code).toBe(EventStoreErrorCode.STORAGE_ERROR);
      }
    });
  });

  // ── Get ────────────────────────────────────────────────────────────────

  describe('get', () => {
    it('returns event when found', async () => {
      const event = createEvent();
      pool._query.mockResolvedValueOnce({ rows: [eventToRow(event)] });

      const result = await store.get(event.eventId);
      expect(result).not.toBeNull();
      expect(result!.eventId).toBe(event.eventId);
    });

    it('returns null when not found', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });
      const result = await store.get('nonexistent');
      expect(result).toBeNull();
    });
  });

  // ── GetLatest ──────────────────────────────────────────────────────────

  describe('getLatest', () => {
    it('returns the last inserted event (by seq)', async () => {
      const event = createEvent();
      pool._query.mockResolvedValueOnce({ rows: [eventToRow(event, 42)] });

      const latest = await store.getLatest();
      expect(latest!.eventId).toBe(event.eventId);

      const [sql] = pool._query.mock.calls[0];
      expect(sql).toContain('ORDER BY seq DESC LIMIT 1');
    });

    it('returns null on empty store', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });
      expect(await store.getLatest()).toBeNull();
    });
  });

  // ── GetLatestHash ──────────────────────────────────────────────────────

  describe('getLatestHash', () => {
    it('returns event_hash of the latest event', async () => {
      pool._query.mockResolvedValueOnce({
        rows: [{ event_hash: 'abc123' }],
      });
      expect(await store.getLatestHash()).toBe('abc123');
    });

    it('returns null on empty store', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });
      expect(await store.getLatestHash()).toBeNull();
    });
  });

  // ── Query ──────────────────────────────────────────────────────────────

  describe('query', () => {
    it('applies filters and pagination', async () => {
      const event = createEvent();
      const row = { ...eventToRow(event), total_count: '1' };
      pool._query.mockResolvedValueOnce({ rows: [row] });

      const result = await store.query(
        { agentId: 'agent-1', eventTypes: [ProofEventType.INTENT_RECEIVED] },
        { limit: 50, offset: 10, order: 'desc' },
      );

      expect(result.events).toHaveLength(1);
      expect(result.totalCount).toBe(1);
      expect(result.hasMore).toBe(false);

      const [sql, params] = pool._query.mock.calls[0];
      expect(sql).toContain('agent_id = $1');
      expect(sql).toContain('event_type = ANY($2)');
      expect(sql).toContain('ORDER BY seq DESC');
      expect(params).toContain('agent-1');
    });

    it('returns empty result for no matches', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });

      const result = await store.query();
      expect(result.events).toHaveLength(0);
      expect(result.totalCount).toBe(0);
      expect(result.hasMore).toBe(false);
    });

    it('strips payload when includePayload is false', async () => {
      const event = createEvent();
      const row = { ...eventToRow(event), total_count: '1' };
      pool._query.mockResolvedValueOnce({ rows: [row] });

      await store.query({}, { includePayload: false });

      const [sql] = pool._query.mock.calls[0];
      expect(sql).toContain('stripped');
    });

    it('filters by shadow mode', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });

      await store.query({}, { shadowModeOnly: ['shadow', 'testnet'] });

      const [sql, params] = pool._query.mock.calls[0];
      expect(sql).toContain('shadow_mode = ANY');
      expect(params[0]).toEqual(['shadow', 'testnet']);
    });

    it('excludes shadow events when excludeShadow is true', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });

      await store.query({}, { excludeShadow: true });

      const [sql] = pool._query.mock.calls[0];
      expect(sql).toContain("shadow_mode IS NULL OR shadow_mode = 'production'");
    });
  });

  // ── Convenience accessors ──────────────────────────────────────────────

  describe('getByCorrelationId', () => {
    it('delegates to query with correlationId filter', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });
      const result = await store.getByCorrelationId('corr-1');
      expect(result).toEqual([]);
      const [sql, params] = pool._query.mock.calls[0];
      expect(sql).toContain('correlation_id = $1');
      expect(params[0]).toBe('corr-1');
    });
  });

  describe('getByAgentId', () => {
    it('delegates to query with agentId filter', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });
      await store.getByAgentId('agent-1');
      const [, params] = pool._query.mock.calls[0];
      expect(params[0]).toBe('agent-1');
    });
  });

  describe('getByTimeRange', () => {
    it('delegates to query with from/to filter', async () => {
      const from = new Date('2026-01-01');
      const to = new Date('2026-12-31');
      pool._query.mockResolvedValueOnce({ rows: [] });
      await store.getByTimeRange(from, to);
      const [sql] = pool._query.mock.calls[0];
      expect(sql).toContain('occurred_at >= $1');
      expect(sql).toContain('occurred_at <= $2');
    });
  });

  describe('getByType', () => {
    it('delegates to query with eventTypes filter', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });
      await store.getByType(ProofEventType.DECISION_MADE);
      const [, params] = pool._query.mock.calls[0];
      expect(params[0]).toEqual([ProofEventType.DECISION_MADE]);
    });
  });

  // ── Summaries ──────────────────────────────────────────────────────────

  describe('getSummaries', () => {
    it('returns lightweight summaries without payload', async () => {
      const event = createEvent();
      pool._query.mockResolvedValueOnce({
        rows: [{
          event_id: event.eventId,
          event_type: event.eventType,
          correlation_id: event.correlationId,
          agent_id: event.agentId,
          occurred_at: event.occurredAt.toISOString(),
          recorded_at: event.recordedAt.toISOString(),
        }],
      });

      const summaries = await store.getSummaries();
      expect(summaries).toHaveLength(1);
      expect(summaries[0].eventId).toBe(event.eventId);
      expect((summaries[0] as unknown as Record<string, unknown>).payload).toBeUndefined();
    });
  });

  // ── GetChain ───────────────────────────────────────────────────────────

  describe('getChain', () => {
    it('returns events from starting point', async () => {
      const event = createEvent();
      // First query: lookup seq of starting event
      pool._query.mockResolvedValueOnce({ rows: [{ seq: 5 }] });
      // Second query: fetch chain from that seq
      pool._query.mockResolvedValueOnce({ rows: [eventToRow(event, 5)] });

      const chain = await store.getChain(event.eventId, 10);
      expect(chain).toHaveLength(1);
      expect(chain[0].eventId).toBe(event.eventId);
    });

    it('returns empty array when start event not found', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });
      const chain = await store.getChain('nonexistent');
      expect(chain).toEqual([]);
    });

    it('returns all events when no start specified', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });
      const chain = await store.getChain();
      expect(chain).toEqual([]);
      const [sql] = pool._query.mock.calls[0];
      expect(sql).toContain('ORDER BY seq ASC');
    });
  });

  // ── Count ──────────────────────────────────────────────────────────────

  describe('count', () => {
    it('returns total count without filter', async () => {
      pool._query.mockResolvedValueOnce({ rows: [{ cnt: '42' }] });
      expect(await store.count()).toBe(42);
    });

    it('returns filtered count', async () => {
      pool._query.mockResolvedValueOnce({ rows: [{ cnt: '5' }] });
      const count = await store.count({ agentId: 'agent-1' });
      expect(count).toBe(5);
      const [sql] = pool._query.mock.calls[0];
      expect(sql).toContain('agent_id = $1');
    });
  });

  // ── Stats ──────────────────────────────────────────────────────────────

  describe('getStats', () => {
    it('returns aggregated statistics', async () => {
      pool._query.mockResolvedValueOnce({
        rows: [{
          total_events: '100',
          by_type: { intent_received: 60, decision_made: 40 },
          by_agent: { 'agent-1': 80, 'agent-2': 20 },
          oldest_event: '2026-01-01T00:00:00Z',
          newest_event: '2026-04-01T00:00:00Z',
          by_shadow: { production: 90, shadow: 10 },
        }],
      });

      const stats = await store.getStats();
      expect(stats.totalEvents).toBe(100);
      expect(stats.byType.intent_received).toBe(60);
      expect(stats.byAgent['agent-1']).toBe(80);
      expect(stats.oldestEvent).toBeInstanceOf(Date);
      expect(stats.byShadowMode?.production).toBe(90);
    });

    it('handles empty store', async () => {
      pool._query.mockResolvedValueOnce({
        rows: [{
          total_events: '0',
          by_type: null,
          by_agent: null,
          oldest_event: null,
          newest_event: null,
          by_shadow: null,
        }],
      });

      const stats = await store.getStats();
      expect(stats.totalEvents).toBe(0);
      expect(stats.byType).toEqual({});
      expect(stats.oldestEvent).toBeUndefined();
    });
  });

  // ── Exists ─────────────────────────────────────────────────────────────

  describe('exists', () => {
    it('returns true when event exists', async () => {
      pool._query.mockResolvedValueOnce({ rows: [{ '?column?': 1 }] });
      expect(await store.exists('ev-1')).toBe(true);
    });

    it('returns false when event does not exist', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });
      expect(await store.exists('ev-1')).toBe(false);
    });
  });

  // ── Clear ──────────────────────────────────────────────────────────────

  describe('clear', () => {
    it('executes DELETE FROM', async () => {
      pool._query.mockResolvedValueOnce({ rows: [] });
      await store.clear();
      const [sql] = pool._query.mock.calls[0];
      expect(sql).toContain('DELETE FROM proof_events');
    });
  });

  // ── Migration ──────────────────────────────────────────────────────────

  describe('migrate', () => {
    it('creates table and indexes (idempotent)', async () => {
      const autoStore = createCockroachEventStore(pool as unknown as import('pg').Pool);
      pool._query
        .mockResolvedValueOnce({ rows: [] })  // CREATE TABLE
        .mockResolvedValueOnce({ rows: [] }); // first operation

      await autoStore.migrate();
      const [sql] = pool._query.mock.calls[0];
      expect(sql).toContain('CREATE TABLE IF NOT EXISTS');
      expect(sql).toContain('idx_proof_events_correlation');
    });

    it('only runs migration once', async () => {
      const autoStore = createCockroachEventStore(pool as unknown as import('pg').Pool, {
        autoMigrate: false,
      });
      pool._query.mockResolvedValue({ rows: [] });

      await autoStore.migrate();
      await autoStore.migrate();
      // Only one CREATE TABLE call
      const createCalls = pool._query.mock.calls.filter(
        ([sql]: [string]) => typeof sql === 'string' && sql.includes('CREATE TABLE'),
      );
      expect(createCalls).toHaveLength(1);
    });
  });
});
