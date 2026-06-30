/**
 * In-Memory Event Store - Reference implementation for testing
 *
 * This implementation stores events in memory. For production,
 * use a persistent store (PostgreSQL, Supabase, etc.).
 */

import type {
  ProofEvent,
  ProofEventFilter,
  ProofEventSummary,
  ProofEventType,
} from '@vorionsys/contracts';
import {
  type ProofEventStore,
  type EventQueryOptions,
  type EventQueryResult,
  type EventStats,
  EventStoreError,
  EventStoreErrorCode,
} from './event-store.js';

/**
 * In-memory implementation of ProofEventStore
 */
export class InMemoryEventStore implements ProofEventStore {
  readonly persistent = false as const;
  readonly storeType = 'in-memory' as const;

  private events: Map<string, ProofEvent> = new Map();
  private eventOrder: string[] = []; // Maintains insertion order

  /**
   * Append an event to the store
   */
  async append(event: ProofEvent): Promise<ProofEvent> {
    if (this.events.has(event.eventId)) {
      throw new EventStoreError(
        `Event ${event.eventId} already exists`,
        EventStoreErrorCode.DUPLICATE_EVENT,
        event.eventId
      );
    }

    // Set recorded timestamp if not already set
    const storedEvent: ProofEvent = {
      ...event,
      recordedAt: event.recordedAt ?? new Date(),
    };

    this.events.set(event.eventId, storedEvent);
    this.eventOrder.push(event.eventId);

    return storedEvent;
  }

  /**
   * Get an event by ID
   */
  async get(eventId: string): Promise<ProofEvent | null> {
    return this.events.get(eventId) ?? null;
  }

  /**
   * Get the latest event
   */
  async getLatest(): Promise<ProofEvent | null> {
    if (this.eventOrder.length === 0) {
      return null;
    }
    const lastId = this.eventOrder[this.eventOrder.length - 1];
    return this.events.get(lastId) ?? null;
  }

  /**
   * Get the latest hash for chaining
   */
  async getLatestHash(): Promise<string | null> {
    const latest = await this.getLatest();
    return latest?.eventHash ?? null;
  }

  /**
   * Query events with filters
   */
  async query(
    filter?: ProofEventFilter,
    options?: EventQueryOptions
  ): Promise<EventQueryResult> {
    let events = this.getOrderedEvents(options?.order);

    // Apply filters
    if (filter) {
      events = this.applyFilter(events, filter);
    }

    const totalCount = events.length;

    // Apply pagination
    const offset = options?.offset ?? 0;
    const limit = options?.limit ?? 100;
    const paginatedEvents = events.slice(offset, offset + limit);

    // Optionally strip payloads
    const resultEvents = options?.includePayload === false
      ? paginatedEvents.map(e => ({ ...e, payload: { type: e.payload.type } as ProofEvent['payload'] }))
      : paginatedEvents;

    return {
      events: resultEvents,
      totalCount,
      hasMore: offset + limit < totalCount,
    };
  }

  /**
   * Get events by correlation ID
   */
  async getByCorrelationId(
    correlationId: string,
    options?: EventQueryOptions
  ): Promise<ProofEvent[]> {
    const result = await this.query({ correlationId }, options);
    return result.events;
  }

  /**
   * Get events by agent ID
   */
  async getByAgentId(
    agentId: string,
    options?: EventQueryOptions
  ): Promise<ProofEvent[]> {
    const result = await this.query({ agentId }, options);
    return result.events;
  }

  /**
   * Get events in a time range
   */
  async getByTimeRange(
    from: Date,
    to: Date,
    options?: EventQueryOptions
  ): Promise<ProofEvent[]> {
    const result = await this.query({ from, to }, options);
    return result.events;
  }

  /**
   * Get events by type
   */
  async getByType(
    eventType: ProofEventType,
    options?: EventQueryOptions
  ): Promise<ProofEvent[]> {
    const result = await this.query({ eventTypes: [eventType] }, options);
    return result.events;
  }

  /**
   * Get event summaries
   */
  async getSummaries(
    filter?: ProofEventFilter,
    options?: EventQueryOptions
  ): Promise<ProofEventSummary[]> {
    const result = await this.query(filter, options);
    return result.events.map(e => ({
      eventId: e.eventId,
      eventType: e.eventType,
      correlationId: e.correlationId,
      agentId: e.agentId,
      occurredAt: e.occurredAt,
      recordedAt: e.recordedAt,
    }));
  }

  /**
   * Get the chain from a starting point
   */
  async getChain(fromEventId?: string, limit?: number): Promise<ProofEvent[]> {
    const events = this.getOrderedEvents('asc');

    if (fromEventId) {
      const startIndex = events.findIndex(e => e.eventId === fromEventId);
      if (startIndex === -1) {
        return [];
      }
      const chainEvents = events.slice(startIndex);
      return limit ? chainEvents.slice(0, limit) : chainEvents;
    }

    return limit ? events.slice(0, limit) : events;
  }

  /**
   * Get event count
   */
  async count(filter?: ProofEventFilter): Promise<number> {
    if (!filter) {
      return this.events.size;
    }
    const events = this.applyFilter(this.getOrderedEvents(), filter);
    return events.length;
  }

  /**
   * Get event statistics
   */
  async getStats(): Promise<EventStats> {
    const events = this.getOrderedEvents('asc');

    const byType: Record<string, number> = {};
    const byAgent: Record<string, number> = {};

    for (const event of events) {
      byType[event.eventType] = (byType[event.eventType] ?? 0) + 1;
      if (event.agentId) {
        byAgent[event.agentId] = (byAgent[event.agentId] ?? 0) + 1;
      }
    }

    return {
      totalEvents: events.length,
      byType,
      byAgent,
      oldestEvent: events[0]?.occurredAt,
      newestEvent: events[events.length - 1]?.occurredAt,
    };
  }

  /**
   * Check if an event exists
   */
  async exists(eventId: string): Promise<boolean> {
    return this.events.has(eventId);
  }

  /**
   * Clear all events
   */
  async clear(): Promise<void> {
    this.events.clear();
    this.eventOrder = [];
  }

  // Private helpers

  private getOrderedEvents(order: 'asc' | 'desc' = 'asc'): ProofEvent[] {
    const events = this.eventOrder
      .map(id => this.events.get(id))
      .filter((e): e is ProofEvent => e !== undefined);

    if (order === 'desc') {
      return events.reverse();
    }
    return events;
  }

  private applyFilter(events: ProofEvent[], filter: ProofEventFilter): ProofEvent[] {
    return events.filter(event => {
      if (filter.correlationId && event.correlationId !== filter.correlationId) {
        return false;
      }
      if (filter.agentId && event.agentId !== filter.agentId) {
        return false;
      }
      if (filter.eventTypes && !filter.eventTypes.includes(event.eventType)) {
        return false;
      }
      if (filter.from && event.occurredAt < filter.from) {
        return false;
      }
      if (filter.to && event.occurredAt > filter.to) {
        return false;
      }
      return true;
    });
  }
}

/**
 * Create an in-memory event store
 */
export function createInMemoryEventStore(): InMemoryEventStore {
  return new InMemoryEventStore();
}
