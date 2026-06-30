/**
 * ClickHouse Event Store — analytical read layer for CQRS.
 *
 * Optimized for high-volume reads: trust history dashboards, compliance
 * queries, proof chain analytics. NOT for chain integrity (use Postgres).
 *
 * Used as the readStore for KafkaEventStore:
 *   Kafka → KafkaEventStore consumer → ClickHouseEventStore.append() → ClickHouse
 *   Dashboard reads → ClickHouseEventStore.query() → ClickHouse
 *
 * Table: vorion.proof_events (MergeTree, partitioned by month, ordered by occurredAt)
 *
 * @packageDocumentation
 */

import type {
  ProofEvent,
  ProofEventFilter,
  ProofEventSummary,
  ProofEventType,
} from '@vorionsys/contracts';
import type { ProofEventStore, EventQueryOptions, EventQueryResult, EventStats } from './event-store.js';
import { EventStoreError, EventStoreErrorCode } from './event-store.js';

// =============================================================================
// Configuration
// =============================================================================

export interface ClickHouseEventStoreConfig {
  /** ClickHouse HTTP URL (default: http://localhost:8123) */
  url: string;
  /** Database name (default: vorion) */
  database?: string;
  /** Table name (default: proof_events) */
  table?: string;
  /** Username (default: vorion) */
  user?: string;
  /** Password (default: vorion) */
  password?: string;
}

const DEFAULTS = {
  database: 'vorion',
  table: 'proof_events',
  user: 'vorion',
  password: 'vorion',
};

// =============================================================================
// ClickHouse Event Store
// =============================================================================

export class ClickHouseEventStore implements ProofEventStore {
  readonly persistent = true as const;
  readonly storeType = 'clickhouse' as const;
  private config: Required<ClickHouseEventStoreConfig>;

  constructor(config: ClickHouseEventStoreConfig) {
    this.config = { ...DEFAULTS, ...config } as Required<ClickHouseEventStoreConfig>;
  }

  /**
   * Create the proof_events table if it doesn't exist.
   * Call once at startup.
   */
  async ensureTable(): Promise<void> {
    await this.query_raw(`
      CREATE TABLE IF NOT EXISTS ${this.config.database}.${this.config.table} (
        eventId String,
        eventType LowCardinality(String),
        agentId String,
        tenantId String,
        occurredAt DateTime64(3),
        previousHash String,
        eventHash String,
        chainPosition UInt64,
        correlationId Nullable(String),
        payload String,
        shadowMode Nullable(String),
        createdAt DateTime64(3) DEFAULT now64()
      )
      ENGINE = MergeTree()
      PARTITION BY toYYYYMM(occurredAt)
      ORDER BY (tenantId, agentId, occurredAt)
      TTL toDateTime(occurredAt) + INTERVAL 1 YEAR
      SETTINGS index_granularity = 8192
    `);
  }

  // =========================================================================
  // Write (called by Kafka consumer materializer)
  // =========================================================================

  async append(event: ProofEvent): Promise<ProofEvent> {
    const e = event as unknown as Record<string, unknown>;
    const payload = JSON.stringify(e.payload ?? {});

    await this.query_raw(`
      INSERT INTO ${this.config.database}.${this.config.table}
      (eventId, eventType, agentId, tenantId, occurredAt, previousHash, eventHash, chainPosition, correlationId, payload, shadowMode)
      VALUES (
        '${this.esc(event.eventId)}',
        '${this.esc(event.eventType)}',
        '${this.esc(event.agentId ?? '')}',
        '${this.esc(String(e.tenantId ?? 'default'))}',
        '${this.escDate(event.occurredAt)}',
        '${this.esc(event.previousHash ?? '')}',
        '${this.esc(event.eventHash ?? '')}',
        ${Number(e.chainPosition ?? 0)},
        ${e.correlationId ? `'${this.esc(String(e.correlationId))}'` : 'NULL'},
        '${this.esc(payload)}',
        ${e.shadowMode ? `'${this.esc(String(e.shadowMode))}'` : 'NULL'}
      )
    `);

    return event;
  }

  // =========================================================================
  // Read
  // =========================================================================

  async get(eventId: string): Promise<ProofEvent | null> {
    const rows = await this.query_json<ProofEvent>(
      `SELECT * FROM ${this.fqn()} WHERE eventId = '${this.esc(eventId)}' LIMIT 1`
    );
    return rows[0] ?? null;
  }

  async getLatest(): Promise<ProofEvent | null> {
    const rows = await this.query_json<ProofEvent>(
      `SELECT * FROM ${this.fqn()} ORDER BY occurredAt DESC LIMIT 1`
    );
    return rows[0] ?? null;
  }

  async getLatestHash(): Promise<string | null> {
    const rows = await this.query_json<{ eventHash: string }>(
      `SELECT eventHash FROM ${this.fqn()} ORDER BY occurredAt DESC LIMIT 1`
    );
    return rows[0]?.eventHash ?? null;
  }

  async query(filter?: ProofEventFilter, options?: EventQueryOptions): Promise<EventQueryResult> {
    const where = this.buildWhere(filter, options);
    const order = options?.order === 'asc' ? 'ASC' : 'DESC';
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;

    const [events, countResult] = await Promise.all([
      this.query_json<ProofEvent>(
        `SELECT * FROM ${this.fqn()} ${where} ORDER BY occurredAt ${order} LIMIT ${limit} OFFSET ${offset}`
      ),
      this.query_json<{ cnt: number }>(
        `SELECT count() as cnt FROM ${this.fqn()} ${where}`
      ),
    ]);

    const totalCount = countResult[0]?.cnt ?? 0;
    return {
      events,
      totalCount,
      hasMore: offset + events.length < totalCount,
    };
  }

  async getByCorrelationId(correlationId: string, options?: EventQueryOptions): Promise<ProofEvent[]> {
    const limit = options?.limit ?? 100;
    return this.query_json<ProofEvent>(
      `SELECT * FROM ${this.fqn()} WHERE correlationId = '${this.esc(correlationId)}' ORDER BY occurredAt LIMIT ${limit}`
    );
  }

  async getByAgentId(agentId: string, options?: EventQueryOptions): Promise<ProofEvent[]> {
    const limit = options?.limit ?? 100;
    return this.query_json<ProofEvent>(
      `SELECT * FROM ${this.fqn()} WHERE agentId = '${this.esc(agentId)}' ORDER BY occurredAt DESC LIMIT ${limit}`
    );
  }

  async getByTimeRange(from: Date, to: Date, options?: EventQueryOptions): Promise<ProofEvent[]> {
    const limit = options?.limit ?? 1000;
    return this.query_json<ProofEvent>(
      `SELECT * FROM ${this.fqn()} WHERE occurredAt >= '${this.escDate(from)}' AND occurredAt <= '${this.escDate(to)}' ORDER BY occurredAt LIMIT ${limit}`
    );
  }

  async getByType(eventType: ProofEventType, options?: EventQueryOptions): Promise<ProofEvent[]> {
    const limit = options?.limit ?? 100;
    return this.query_json<ProofEvent>(
      `SELECT * FROM ${this.fqn()} WHERE eventType = '${this.esc(eventType)}' ORDER BY occurredAt DESC LIMIT ${limit}`
    );
  }

  async getSummaries(filter?: ProofEventFilter, options?: EventQueryOptions): Promise<ProofEventSummary[]> {
    const where = this.buildWhere(filter, options);
    const limit = options?.limit ?? 100;
    return this.query_json<ProofEventSummary>(
      `SELECT eventId, eventType, agentId, occurredAt, eventHash FROM ${this.fqn()} ${where} ORDER BY occurredAt DESC LIMIT ${limit}`
    );
  }

  async getChain(fromEventId?: string, limit = 1000): Promise<ProofEvent[]> {
    if (fromEventId) {
      return this.query_json<ProofEvent>(
        `SELECT * FROM ${this.fqn()} WHERE chainPosition >= (SELECT chainPosition FROM ${this.fqn()} WHERE eventId = '${this.esc(fromEventId)}' LIMIT 1) ORDER BY chainPosition ASC LIMIT ${limit}`
      );
    }
    return this.query_json<ProofEvent>(
      `SELECT * FROM ${this.fqn()} ORDER BY chainPosition ASC LIMIT ${limit}`
    );
  }

  async count(filter?: ProofEventFilter): Promise<number> {
    const where = this.buildWhere(filter);
    const rows = await this.query_json<{ cnt: number }>(
      `SELECT count() as cnt FROM ${this.fqn()} ${where}`
    );
    return rows[0]?.cnt ?? 0;
  }

  async getStats(): Promise<EventStats> {
    const [total, byType, byAgent, range] = await Promise.all([
      this.query_json<{ cnt: number }>(`SELECT count() as cnt FROM ${this.fqn()}`),
      this.query_json<{ eventType: string; cnt: number }>(`SELECT eventType, count() as cnt FROM ${this.fqn()} GROUP BY eventType`),
      this.query_json<{ agentId: string; cnt: number }>(`SELECT agentId, count() as cnt FROM ${this.fqn()} GROUP BY agentId ORDER BY cnt DESC LIMIT 100`),
      this.query_json<{ oldest: string; newest: string }>(`SELECT min(occurredAt) as oldest, max(occurredAt) as newest FROM ${this.fqn()}`),
    ]);

    return {
      totalEvents: total[0]?.cnt ?? 0,
      byType: Object.fromEntries(byType.map(r => [r.eventType, r.cnt])),
      byAgent: Object.fromEntries(byAgent.map(r => [r.agentId, r.cnt])),
      oldestEvent: range[0]?.oldest ? new Date(range[0].oldest) : undefined,
      newestEvent: range[0]?.newest ? new Date(range[0].newest) : undefined,
    };
  }

  async exists(eventId: string): Promise<boolean> {
    const rows = await this.query_json<{ cnt: number }>(
      `SELECT count() as cnt FROM ${this.fqn()} WHERE eventId = '${this.esc(eventId)}'`
    );
    return (rows[0]?.cnt ?? 0) > 0;
  }

  async clear(): Promise<void> {
    await this.query_raw(`TRUNCATE TABLE ${this.fqn()}`);
  }

  // =========================================================================
  // Internal: HTTP query interface
  // =========================================================================

  private async query_raw(sql: string): Promise<string> {
    const url = `${this.config.url}/?database=${this.config.database}`;
    const response = await fetch(url, {
      method: 'POST',
      body: sql,
      headers: {
        'X-ClickHouse-User': this.config.user,
        'X-ClickHouse-Key': this.config.password,
      },
    });

    if (!response.ok) {
      const body = await response.text();
      throw new EventStoreError(
        `ClickHouse query failed: ${response.status} ${body.slice(0, 200)}`,
        EventStoreErrorCode.STORAGE_ERROR,
      );
    }

    return response.text();
  }

  private async query_json<T>(sql: string): Promise<T[]> {
    const raw = await this.query_raw(`${sql} FORMAT JSONEachRow`);
    if (!raw.trim()) return [];
    return raw.trim().split('\n').map(line => JSON.parse(line) as T);
  }

  private fqn(): string {
    return `${this.config.database}.${this.config.table}`;
  }

  private buildWhere(filter?: ProofEventFilter, options?: EventQueryOptions): string {
    const conditions: string[] = [];
    if (filter) {
      const f = filter as Record<string, unknown>;
      if (f.agentId) conditions.push(`agentId = '${this.esc(String(f.agentId))}'`);
      if (f.eventType) conditions.push(`eventType = '${this.esc(String(f.eventType))}'`);
      if (f.from) conditions.push(`occurredAt >= '${this.escDate(f.from as Date)}'`);
      if (f.to) conditions.push(`occurredAt <= '${this.escDate(f.to as Date)}'`);
    }
    if (options?.excludeShadow) {
      conditions.push(`(shadowMode IS NULL OR shadowMode = 'production')`);
    }
    if (options?.shadowModeOnly?.length) {
      const modes = options.shadowModeOnly.map(m => `'${this.esc(m)}'`).join(',');
      conditions.push(`shadowMode IN (${modes})`);
    }
    return conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  }

  private esc(s: string): string {
    return s.replace(/'/g, "\\'").replace(/\\/g, '\\\\');
  }

  private escDate(d: Date | string): string {
    const date = typeof d === 'string' ? new Date(d) : d;
    return date.toISOString().replace('T', ' ').replace('Z', '');
  }
}

// =============================================================================
// Factory
// =============================================================================

export function createClickHouseEventStore(config: ClickHouseEventStoreConfig): ClickHouseEventStore {
  return new ClickHouseEventStore(config);
}
