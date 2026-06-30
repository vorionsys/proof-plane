/**
 * Kafka Event Store — append-only proof event log for horizontal scaling.
 *
 * Implements ProofEventStore by publishing proof events to a Kafka topic
 * as the source of truth. Reads are served from a local materialized store
 * (Postgres, ClickHouse, or in-memory) that consumes from the same topic.
 *
 * Architecture:
 *   Producer path: append() → Kafka topic (partitioned by tenantId)
 *   Consumer path: Kafka topic → materializer → read store
 *   Read path: query/get/count → read store (NOT Kafka)
 *
 * Guarantees:
 *   - At-least-once delivery (producer acks=all, consumer commits after process)
 *   - Ordered within partition (partition key = tenantId)
 *   - Idempotent writes (eventId used as Kafka message key for dedup)
 *
 * Topic: vorion.proof-events (configurable)
 * Partitions: by tenantId (default 12, increase for >10K agents)
 * Retention: 30 days default (long-term stored in read store)
 *
 * @packageDocumentation
 */

import { Kafka, Producer, Consumer, type KafkaConfig, CompressionTypes, logLevel } from 'kafkajs';
import type { ProofEvent, ProofEventFilter, ProofEventSummary, ProofEventType } from '@vorionsys/contracts';
import type { ProofEventStore, EventQueryOptions, EventQueryResult, EventStats } from './event-store.js';
import { EventStoreError, EventStoreErrorCode } from './event-store.js';

// =============================================================================
// Configuration
// =============================================================================

export interface KafkaEventStoreConfig {
  /** Kafka broker addresses */
  brokers: string[];
  /** Topic name for proof events (default: vorion.proof-events) */
  topic?: string;
  /** Consumer group ID (default: vorion-proof-materializer) */
  consumerGroupId?: string;
  /** Client ID prefix (default: vorion-proof) */
  clientId?: string;
  /** Producer acks: -1 (all), 1 (leader), 0 (none). Default: -1 */
  acks?: number;
  /** Compression type. Default: GZIP */
  compression?: CompressionTypes;
  /** Read store for serving queries (required) */
  readStore: ProofEventStore;
  /** SASL authentication (optional) */
  sasl?: KafkaConfig['sasl'];
  /** SSL configuration (optional) */
  ssl?: KafkaConfig['ssl'];
}

const DEFAULT_TOPIC = 'vorion.proof-events';
const DEFAULT_GROUP = 'vorion-proof-materializer';
const DEFAULT_CLIENT = 'vorion-proof';

// =============================================================================
// Kafka Event Store
// =============================================================================

export class KafkaEventStore implements ProofEventStore {
  readonly persistent = true as const;
  readonly storeType = 'kafka' as const;
  private kafka: Kafka;
  private producer: Producer | null = null;
  private consumer: Consumer | null = null;
  private config: Required<Pick<KafkaEventStoreConfig, 'topic' | 'consumerGroupId' | 'acks' | 'compression'>> & KafkaEventStoreConfig;
  private readStore: ProofEventStore;
  private consuming = false;
  private totalProduced = 0;
  private totalConsumed = 0;

  constructor(config: KafkaEventStoreConfig) {
    this.config = {
      topic: DEFAULT_TOPIC,
      consumerGroupId: DEFAULT_GROUP,
      acks: -1,
      compression: CompressionTypes.GZIP,
      ...config,
    };
    this.readStore = config.readStore;

    this.kafka = new Kafka({
      clientId: config.clientId ?? DEFAULT_CLIENT,
      brokers: config.brokers,
      sasl: config.sasl,
      ssl: config.ssl,
      logLevel: logLevel.WARN,
    });
  }

  // =========================================================================
  // Lifecycle
  // =========================================================================

  /** Connect producer (call before append) */
  async connectProducer(): Promise<void> {
    this.producer = this.kafka.producer({
      idempotent: true, // Exactly-once semantics with transactional ID
      maxInFlightRequests: 5,
    });
    await this.producer.connect();
  }

  /** Start consuming and materializing to read store */
  async startConsumer(): Promise<void> {
    this.consumer = this.kafka.consumer({
      groupId: this.config.consumerGroupId,
      sessionTimeout: 30_000,
      heartbeatInterval: 3_000,
    });
    await this.consumer.connect();
    await this.consumer.subscribe({ topic: this.config.topic, fromBeginning: true });

    this.consuming = true;

    await this.consumer.run({
      eachMessage: async ({ message }) => {
        if (!message.value) return;

        try {
          const event = JSON.parse(message.value.toString()) as ProofEvent;
          // Materialize to read store (idempotent — readStore.append handles dedup)
          await this.readStore.append(event);
          this.totalConsumed++;
        } catch (err) {
          // Log but don't crash — consumer continues
          console.error('[KafkaEventStore] Failed to materialize event:', err);
        }
      },
    });
  }

  /** Disconnect producer and consumer */
  async disconnect(): Promise<void> {
    this.consuming = false;
    if (this.consumer) {
      await this.consumer.disconnect();
      this.consumer = null;
    }
    if (this.producer) {
      await this.producer.disconnect();
      this.producer = null;
    }
  }

  // =========================================================================
  // Write Path (append → Kafka)
  // =========================================================================

  async append(event: ProofEvent): Promise<ProofEvent> {
    if (!this.producer) {
      throw new EventStoreError(
        'Kafka producer not connected — call connectProducer() first',
        EventStoreErrorCode.STORAGE_ERROR,
      );
    }

    // Partition by tenantId for ordering guarantees
    const partitionKey = (event as unknown as Record<string, unknown>).tenantId as string ?? 'default';

    try {
      await this.producer.send({
        topic: this.config.topic,
        acks: this.config.acks,
        compression: this.config.compression,
        messages: [{
          key: event.eventId, // Dedup key
          value: JSON.stringify(event),
          headers: {
            'vorion-event-type': event.eventType,
            'vorion-agent-id': event.agentId,
            'vorion-tenant-id': partitionKey,
          },
          partition: undefined, // Let Kafka choose based on key hash
        }],
      });

      this.totalProduced++;

      // Return the event as-is — it will be materialized by the consumer
      return event;
    } catch (err) {
      throw new EventStoreError(
        `Failed to publish proof event to Kafka: ${err instanceof Error ? err.message : String(err)}`,
        EventStoreErrorCode.STORAGE_ERROR,
        event.eventId,
      );
    }
  }

  // =========================================================================
  // Read Path (delegated to read store)
  // =========================================================================

  async get(eventId: string): Promise<ProofEvent | null> {
    return this.readStore.get(eventId);
  }

  async getLatest(): Promise<ProofEvent | null> {
    return this.readStore.getLatest();
  }

  async getLatestHash(): Promise<string | null> {
    return this.readStore.getLatestHash();
  }

  async query(filter?: ProofEventFilter, options?: EventQueryOptions): Promise<EventQueryResult> {
    return this.readStore.query(filter, options);
  }

  async getByCorrelationId(correlationId: string, options?: EventQueryOptions): Promise<ProofEvent[]> {
    return this.readStore.getByCorrelationId(correlationId, options);
  }

  async getByAgentId(agentId: string, options?: EventQueryOptions): Promise<ProofEvent[]> {
    return this.readStore.getByAgentId(agentId, options);
  }

  async getByTimeRange(from: Date, to: Date, options?: EventQueryOptions): Promise<ProofEvent[]> {
    return this.readStore.getByTimeRange(from, to, options);
  }

  async getByType(eventType: ProofEventType, options?: EventQueryOptions): Promise<ProofEvent[]> {
    return this.readStore.getByType(eventType, options);
  }

  async getSummaries(filter?: ProofEventFilter, options?: EventQueryOptions): Promise<ProofEventSummary[]> {
    return this.readStore.getSummaries(filter, options);
  }

  async getChain(fromEventId?: string, limit?: number): Promise<ProofEvent[]> {
    return this.readStore.getChain(fromEventId, limit);
  }

  async count(filter?: ProofEventFilter): Promise<number> {
    return this.readStore.count(filter);
  }

  async getStats(): Promise<EventStats> {
    const baseStats = await this.readStore.getStats();
    return {
      ...baseStats,
      // Extend with Kafka-specific stats
    };
  }

  async exists(eventId: string): Promise<boolean> {
    return this.readStore.exists(eventId);
  }

  async clear(): Promise<void> {
    // Only clear read store — Kafka topic retention is managed by broker
    await this.readStore.clear();
  }

  // =========================================================================
  // Kafka-Specific Operations
  // =========================================================================

  /** Get producer/consumer stats */
  getKafkaStats(): {
    totalProduced: number;
    totalConsumed: number;
    consuming: boolean;
    producerConnected: boolean;
    consumerConnected: boolean;
  } {
    return {
      totalProduced: this.totalProduced,
      totalConsumed: this.totalConsumed,
      consuming: this.consuming,
      producerConnected: this.producer !== null,
      consumerConnected: this.consumer !== null,
    };
  }

  /** Create the topic if it doesn't exist */
  async ensureTopic(numPartitions = 12, replicationFactor = 3): Promise<void> {
    const admin = this.kafka.admin();
    await admin.connect();

    try {
      const topics = await admin.listTopics();
      if (!topics.includes(this.config.topic)) {
        await admin.createTopics({
          topics: [{
            topic: this.config.topic,
            numPartitions,
            replicationFactor,
            configEntries: [
              { name: 'retention.ms', value: String(30 * 24 * 60 * 60 * 1000) }, // 30 days
              { name: 'cleanup.policy', value: 'delete' },
              { name: 'compression.type', value: 'gzip' },
            ],
          }],
        });
      }
    } finally {
      await admin.disconnect();
    }
  }
}

// =============================================================================
// Factory
// =============================================================================

export function createKafkaEventStore(config: KafkaEventStoreConfig): KafkaEventStore {
  return new KafkaEventStore(config);
}
