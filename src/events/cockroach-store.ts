/**
 * CockroachDB Event Store - Production implementation of ProofEventStore
 *
 * Uses CockroachDB (PostgreSQL wire-compatible) for durable, serializable
 * storage of proof events. Designed for the immutable audit trail where
 * events are append-only and form a hash chain.
 *
 * Features:
 * - Serializable isolation for chain integrity
 * - Parameterized queries (SQL injection safe)
 * - Shadow mode filtering for sandbox/testnet events
 * - Efficient pagination with COUNT(*) OVER()
 * - Connection pooling via pg.Pool
 */

import type { Pool } from 'pg';
import type {
  ProofEvent,
  ProofEventFilter,
  ProofEventSummary,
  ProofEventType,
  ProofEventPayload,
  ShadowModeStatus,
} from '@vorionsys/contracts';
import {
  type ProofEventStore,
  type EventQueryOptions,
  type EventQueryResult,
  type EventStats,
  EventStoreError,
  EventStoreErrorCode,
} from './event-store.js';

// =============================================================================
// SQL CONSTANTS
// =============================================================================

const TABLE = 'proof_events';

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS ${TABLE} (
  event_id         TEXT PRIMARY KEY,
  event_type       TEXT NOT NULL,
  correlation_id   TEXT NOT NULL,
  agent_id         TEXT,
  payload          JSONB NOT NULL,
  previous_hash    TEXT,
  event_hash       TEXT NOT NULL,
  event_hash3      TEXT,
  occurred_at      TIMESTAMPTZ NOT NULL,
  recorded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  signed_by        TEXT,
  signature        TEXT,
  shadow_mode      TEXT DEFAULT 'production',
  verification_id  TEXT,
  verified_at      TIMESTAMPTZ,
  seq              BIGSERIAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_proof_events_correlation ON ${TABLE} (correlation_id);
CREATE INDEX IF NOT EXISTS idx_proof_events_agent ON ${TABLE} (agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_proof_events_type ON ${TABLE} (event_type);
CREATE INDEX IF NOT EXISTS idx_proof_events_occurred ON ${TABLE} (occurred_at);
CREATE INDEX IF NOT EXISTS idx_proof_events_shadow ON ${TABLE} (shadow_mode) WHERE shadow_mode != 'production';
CREATE INDEX IF NOT EXISTS idx_proof_events_seq ON ${TABLE} (seq);
`;

const INSERT_SQL = `
INSERT INTO ${TABLE} (
  event_id, event_type, correlation_id, agent_id, payload,
  previous_hash, event_hash, event_hash3,
  occurred_at, recorded_at, signed_by, signature,
  shadow_mode, verification_id, verified_at
) VALUES (
  $1, $2, $3, $4, $5,
  $6, $7, $8,
  $9, $10, $11, $12,
  $13, $14, $15
)
RETURNING *
`;

// =============================================================================
// HELPERS
// =============================================================================

/** Map a database row to a ProofEvent domain object. */
function rowToEvent(row: Record<string, unknown>): ProofEvent {
  return {
    eventId: row.event_id as string,
    eventType: row.event_type as ProofEventType,
    correlationId: row.correlation_id as string,
    agentId: (row.agent_id as string) ?? undefined,
    payload: row.payload as ProofEventPayload,
    previousHash: (row.previous_hash as string) ?? null,
    eventHash: row.event_hash as string,
    eventHash3: (row.event_hash3 as string) ?? undefined,
    occurredAt: new Date(row.occurred_at as string),
    recordedAt: new Date(row.recorded_at as string),
    signedBy: (row.signed_by as string) ?? undefined,
    signature: (row.signature as string) ?? undefined,
    shadowMode: (row.shadow_mode as ShadowModeStatus) ?? undefined,
    verificationId: (row.verification_id as string) ?? undefined,
    verifiedAt: row.verified_at ? new Date(row.verified_at as string) : undefined,
  };
}

/** Build WHERE clauses and params from a ProofEventFilter + EventQueryOptions. */
function buildWhereClause(
  filter?: ProofEventFilter,
  options?: EventQueryOptions,
): { where: string; params: unknown[] } {
  const conditions: string[] = [];
  const params: unknown[] = [];
  let idx = 1;

  if (filter?.correlationId) {
    conditions.push(`correlation_id = $${idx++}`);
    params.push(filter.correlationId);
  }
  if (filter?.agentId) {
    conditions.push(`agent_id = $${idx++}`);
    params.push(filter.agentId);
  }
  if (filter?.eventTypes && filter.eventTypes.length > 0) {
    conditions.push(`event_type = ANY($${idx++})`);
    params.push(filter.eventTypes);
  }
  if (filter?.from) {
    conditions.push(`occurred_at >= $${idx++}`);
    params.push(filter.from);
  }
  if (filter?.to) {
    conditions.push(`occurred_at <= $${idx++}`);
    params.push(filter.to);
  }

  // Shadow mode filtering from EventQueryOptions
  if (options?.shadowModeOnly && options.shadowModeOnly.length > 0) {
    conditions.push(`shadow_mode = ANY($${idx++})`);
    params.push(options.shadowModeOnly);
  }
  if (options?.excludeShadow) {
    conditions.push(`(shadow_mode IS NULL OR shadow_mode = 'production')`);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  return { where, params };
}

// =============================================================================
// COCKROACH EVENT STORE
// =============================================================================

export interface CockroachEventStoreOptions {
  /** pg.Pool instance — caller owns lifecycle */
  pool: Pool;
  /** Auto-create table on first use (default: true) */
  autoMigrate?: boolean;
}

export class CockroachEventStore implements ProofEventStore {
  readonly persistent = true as const;
  readonly storeType = 'cockroachdb' as const;

  private readonly pool: Pool;
  private readonly autoMigrate: boolean;
  private migrated = false;

  constructor(options: CockroachEventStoreOptions) {
    this.pool = options.pool;
    this.autoMigrate = options.autoMigrate ?? true;
  }

  // ── Schema bootstrap ──────────────────────────────────────────────────

  /** Ensure the table and indexes exist. Idempotent. */
  async migrate(): Promise<void> {
    if (this.migrated) return;
    await this.pool.query(CREATE_TABLE_SQL);
    this.migrated = true;
  }

  private async ensureMigrated(): Promise<void> {
    if (this.autoMigrate) {
      await this.migrate();
    }
  }

  // ── ProofEventStore interface ─────────────────────────────────────────

  async append(event: ProofEvent): Promise<ProofEvent> {
    await this.ensureMigrated();
    const recordedAt = event.recordedAt ?? new Date();

    try {
      const result = await this.pool.query(INSERT_SQL, [
        event.eventId,
        event.eventType,
        event.correlationId,
        event.agentId ?? null,
        JSON.stringify(event.payload),
        event.previousHash ?? null,
        event.eventHash,
        event.eventHash3 ?? null,
        event.occurredAt,
        recordedAt,
        event.signedBy ?? null,
        event.signature ?? null,
        event.shadowMode ?? 'production',
        event.verificationId ?? null,
        event.verifiedAt ?? null,
      ]);
      return rowToEvent(result.rows[0]);
    } catch (err: unknown) {
      const pgErr = err as { code?: string };
      if (pgErr.code === '23505') {
        // Unique violation — duplicate event_id
        throw new EventStoreError(
          `Event ${event.eventId} already exists`,
          EventStoreErrorCode.DUPLICATE_EVENT,
          event.eventId,
        );
      }
      throw new EventStoreError(
        `Failed to append event: ${(err as Error).message}`,
        EventStoreErrorCode.STORAGE_ERROR,
        event.eventId,
      );
    }
  }

  async get(eventId: string): Promise<ProofEvent | null> {
    await this.ensureMigrated();
    const result = await this.pool.query(
      `SELECT * FROM ${TABLE} WHERE event_id = $1`,
      [eventId],
    );
    return result.rows.length > 0 ? rowToEvent(result.rows[0]) : null;
  }

  async getLatest(): Promise<ProofEvent | null> {
    await this.ensureMigrated();
    const result = await this.pool.query(
      `SELECT * FROM ${TABLE} ORDER BY seq DESC LIMIT 1`,
    );
    return result.rows.length > 0 ? rowToEvent(result.rows[0]) : null;
  }

  async getLatestHash(): Promise<string | null> {
    await this.ensureMigrated();
    const result = await this.pool.query(
      `SELECT event_hash FROM ${TABLE} ORDER BY seq DESC LIMIT 1`,
    );
    return result.rows.length > 0 ? (result.rows[0].event_hash as string) : null;
  }

  async query(
    filter?: ProofEventFilter,
    options?: EventQueryOptions,
  ): Promise<EventQueryResult> {
    await this.ensureMigrated();
    const { where, params } = buildWhereClause(filter, options);
    const order = options?.order === 'desc' ? 'DESC' : 'ASC';
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;

    // Single query: COUNT(*) OVER() gives total without a second round-trip
    const selectCols = options?.includePayload === false
      ? `event_id, event_type, correlation_id, agent_id,
         '{"type":"stripped"}'::jsonb AS payload,
         previous_hash, event_hash, event_hash3,
         occurred_at, recorded_at, signed_by, signature,
         shadow_mode, verification_id, verified_at, seq`
      : '*';

    const sql = `
      SELECT ${selectCols}, COUNT(*) OVER() AS total_count
      FROM ${TABLE}
      ${where}
      ORDER BY seq ${order}
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;
    params.push(limit, offset);

    const result = await this.pool.query(sql, params);
    const totalCount = result.rows.length > 0
      ? Number(result.rows[0].total_count)
      : 0;

    return {
      events: result.rows.map(rowToEvent),
      totalCount,
      hasMore: offset + limit < totalCount,
    };
  }

  async getByCorrelationId(
    correlationId: string,
    options?: EventQueryOptions,
  ): Promise<ProofEvent[]> {
    const result = await this.query({ correlationId }, options);
    return result.events;
  }

  async getByAgentId(
    agentId: string,
    options?: EventQueryOptions,
  ): Promise<ProofEvent[]> {
    const result = await this.query({ agentId }, options);
    return result.events;
  }

  async getByTimeRange(
    from: Date,
    to: Date,
    options?: EventQueryOptions,
  ): Promise<ProofEvent[]> {
    const result = await this.query({ from, to }, options);
    return result.events;
  }

  async getByType(
    eventType: ProofEventType,
    options?: EventQueryOptions,
  ): Promise<ProofEvent[]> {
    const result = await this.query({ eventTypes: [eventType] }, options);
    return result.events;
  }

  async getSummaries(
    filter?: ProofEventFilter,
    options?: EventQueryOptions,
  ): Promise<ProofEventSummary[]> {
    await this.ensureMigrated();
    const { where, params } = buildWhereClause(filter, options);
    const order = options?.order === 'desc' ? 'DESC' : 'ASC';
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;

    const sql = `
      SELECT event_id, event_type, correlation_id, agent_id, occurred_at, recorded_at
      FROM ${TABLE}
      ${where}
      ORDER BY seq ${order}
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;
    params.push(limit, offset);

    const result = await this.pool.query(sql, params);
    return result.rows.map((row) => ({
      eventId: row.event_id as string,
      eventType: row.event_type as ProofEventType,
      correlationId: row.correlation_id as string,
      agentId: (row.agent_id as string) ?? undefined,
      occurredAt: new Date(row.occurred_at as string),
      recordedAt: new Date(row.recorded_at as string),
    }));
  }

  async getChain(fromEventId?: string, limit?: number): Promise<ProofEvent[]> {
    await this.ensureMigrated();

    if (fromEventId) {
      // Get the seq of the starting event, then fetch from there
      const startResult = await this.pool.query(
        `SELECT seq FROM ${TABLE} WHERE event_id = $1`,
        [fromEventId],
      );
      if (startResult.rows.length === 0) return [];

      const startSeq = startResult.rows[0].seq;
      const sql = limit
        ? `SELECT * FROM ${TABLE} WHERE seq >= $1 ORDER BY seq ASC LIMIT $2`
        : `SELECT * FROM ${TABLE} WHERE seq >= $1 ORDER BY seq ASC`;
      const params = limit ? [startSeq, limit] : [startSeq];

      const result = await this.pool.query(sql, params);
      return result.rows.map(rowToEvent);
    }

    const sql = limit
      ? `SELECT * FROM ${TABLE} ORDER BY seq ASC LIMIT $1`
      : `SELECT * FROM ${TABLE} ORDER BY seq ASC`;
    const params = limit ? [limit] : [];

    const result = await this.pool.query(sql, params);
    return result.rows.map(rowToEvent);
  }

  async count(filter?: ProofEventFilter): Promise<number> {
    await this.ensureMigrated();
    const { where, params } = buildWhereClause(filter);
    const result = await this.pool.query(
      `SELECT COUNT(*) AS cnt FROM ${TABLE} ${where}`,
      params,
    );
    return Number(result.rows[0].cnt);
  }

  async getStats(): Promise<EventStats> {
    await this.ensureMigrated();

    // Single query with aggregation CTEs to avoid multiple round-trips
    const sql = `
      WITH
        totals AS (
          SELECT COUNT(*) AS total FROM ${TABLE}
        ),
        by_type AS (
          SELECT event_type, COUNT(*) AS cnt FROM ${TABLE} GROUP BY event_type
        ),
        by_agent AS (
          SELECT agent_id, COUNT(*) AS cnt FROM ${TABLE}
          WHERE agent_id IS NOT NULL GROUP BY agent_id
        ),
        time_range AS (
          SELECT MIN(occurred_at) AS oldest, MAX(occurred_at) AS newest FROM ${TABLE}
        ),
        by_shadow AS (
          SELECT COALESCE(shadow_mode, 'production') AS mode, COUNT(*) AS cnt
          FROM ${TABLE} GROUP BY COALESCE(shadow_mode, 'production')
        )
      SELECT
        (SELECT total FROM totals) AS total_events,
        (SELECT json_object_agg(event_type, cnt) FROM by_type) AS by_type,
        (SELECT json_object_agg(agent_id, cnt) FROM by_agent) AS by_agent,
        (SELECT oldest FROM time_range) AS oldest_event,
        (SELECT newest FROM time_range) AS newest_event,
        (SELECT json_object_agg(mode, cnt) FROM by_shadow) AS by_shadow
    `;

    const result = await this.pool.query(sql);
    const row = result.rows[0];

    return {
      totalEvents: Number(row.total_events),
      byType: (row.by_type as Record<string, number>) ?? {},
      byAgent: (row.by_agent as Record<string, number>) ?? {},
      oldestEvent: row.oldest_event ? new Date(row.oldest_event as string) : undefined,
      newestEvent: row.newest_event ? new Date(row.newest_event as string) : undefined,
      byShadowMode: (row.by_shadow as Record<ShadowModeStatus | 'production', number>) ?? undefined,
    };
  }

  async exists(eventId: string): Promise<boolean> {
    await this.ensureMigrated();
    const result = await this.pool.query(
      `SELECT 1 FROM ${TABLE} WHERE event_id = $1 LIMIT 1`,
      [eventId],
    );
    return result.rows.length > 0;
  }

  async clear(): Promise<void> {
    await this.ensureMigrated();
    await this.pool.query(`DELETE FROM ${TABLE}`);
  }
}

/**
 * Create a CockroachDB-backed event store.
 *
 * The caller owns the Pool lifecycle (connect before, end after).
 */
export function createCockroachEventStore(
  pool: Pool,
  options?: { autoMigrate?: boolean },
): CockroachEventStore {
  return new CockroachEventStore({ pool, ...options });
}
