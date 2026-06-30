/**
 * Event Store - Abstract storage interface for proof events
 *
 * Implementations can use in-memory storage (for testing),
 * or persistent stores (PostgreSQL, Supabase, etc.).
 */

import type {
  ProofEvent,
  ProofEventFilter,
  ProofEventSummary,
  ProofEventType,
  ShadowModeStatus,
} from '@vorionsys/contracts';

/**
 * Query options for event retrieval
 */
export interface EventQueryOptions {
  /** Maximum number of events to return */
  limit?: number;
  /** Number of events to skip */
  offset?: number;
  /** Sort order (default: ascending by occurredAt) */
  order?: 'asc' | 'desc';
  /** Include event payload in results */
  includePayload?: boolean;
  /**
   * Filter by shadow mode status
   *
   * If provided, only events matching these statuses are returned.
   * Useful for querying unverified sandbox events:
   *   shadowModeOnly: ['shadow', 'testnet']
   */
  shadowModeOnly?: ShadowModeStatus[];
  /**
   * Exclude shadow mode events (production only)
   *
   * If true, only production events (no shadowMode or shadowMode='production')
   * are returned. Used when calculating official trust scores.
   *
   * @default false
   */
  excludeShadow?: boolean;
}

/**
 * Result of an event query
 */
export interface EventQueryResult {
  /** Retrieved events */
  events: ProofEvent[];
  /** Total count matching filter (before pagination) */
  totalCount: number;
  /** Whether there are more results */
  hasMore: boolean;
}

/**
 * Event statistics
 */
export interface EventStats {
  /** Total number of events */
  totalEvents: number;
  /** Events by type */
  byType: Record<string, number>;
  /** Events by agent */
  byAgent: Record<string, number>;
  /** Oldest event timestamp */
  oldestEvent?: Date;
  /** Newest event timestamp */
  newestEvent?: Date;
  /**
   * Events by shadow mode status
   * Tracks how many events are pending HITL verification
   */
  byShadowMode?: Record<ShadowModeStatus | 'production', number>;
}

/**
 * Abstract interface for proof event storage
 */
export interface ProofEventStore {
  /**
   * Whether this store persists data across restarts.
   * In-memory stores return false; persistent backends return true.
   */
  readonly persistent: boolean;

  /**
   * Human-readable store type identifier (e.g. "in-memory", "postgresql", "cockroachdb")
   */
  readonly storeType: string;

  /**
   * Append an event to the store
   * Returns the stored event with recorded timestamp
   */
  append(event: ProofEvent): Promise<ProofEvent>;

  /**
   * Get an event by its ID
   */
  get(eventId: string): Promise<ProofEvent | null>;

  /**
   * Get the latest event in the chain
   */
  getLatest(): Promise<ProofEvent | null>;

  /**
   * Get the latest hash (for chaining new events)
   */
  getLatestHash(): Promise<string | null>;

  /**
   * Query events with filters
   */
  query(filter?: ProofEventFilter, options?: EventQueryOptions): Promise<EventQueryResult>;

  /**
   * Get events by correlation ID (for tracing a request)
   */
  getByCorrelationId(correlationId: string, options?: EventQueryOptions): Promise<ProofEvent[]>;

  /**
   * Get events by agent ID
   */
  getByAgentId(agentId: string, options?: EventQueryOptions): Promise<ProofEvent[]>;

  /**
   * Get events in a time range
   */
  getByTimeRange(from: Date, to: Date, options?: EventQueryOptions): Promise<ProofEvent[]>;

  /**
   * Get events by type
   */
  getByType(eventType: ProofEventType, options?: EventQueryOptions): Promise<ProofEvent[]>;

  /**
   * Get event summaries (lightweight list without payloads)
   */
  getSummaries(filter?: ProofEventFilter, options?: EventQueryOptions): Promise<ProofEventSummary[]>;

  /**
   * Get the chain of events from a starting point
   * Returns events in order for chain verification
   */
  getChain(fromEventId?: string, limit?: number): Promise<ProofEvent[]>;

  /**
   * Get event count
   */
  count(filter?: ProofEventFilter): Promise<number>;

  /**
   * Get event statistics
   */
  getStats(): Promise<EventStats>;

  /**
   * Check if an event exists
   */
  exists(eventId: string): Promise<boolean>;

  /**
   * Clear all events (for testing only)
   */
  clear(): Promise<void>;
}

/**
 * Error thrown when event storage fails
 */
export class EventStoreError extends Error {
  constructor(
    message: string,
    public readonly code: EventStoreErrorCode,
    public readonly eventId?: string
  ) {
    super(message);
    this.name = 'EventStoreError';
  }
}

/**
 * Event store error codes
 */
export enum EventStoreErrorCode {
  /** Event already exists (duplicate ID) */
  DUPLICATE_EVENT = 'DUPLICATE_EVENT',
  /** Event not found */
  NOT_FOUND = 'NOT_FOUND',
  /** Invalid event data */
  INVALID_EVENT = 'INVALID_EVENT',
  /** Chain integrity error */
  CHAIN_INTEGRITY = 'CHAIN_INTEGRITY',
  /** Storage error */
  STORAGE_ERROR = 'STORAGE_ERROR',
}
